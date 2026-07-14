// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/aimd54/palan/internal/refname"
	palanruntime "github.com/aimd54/palan/internal/runtime"
	"github.com/aimd54/palan/internal/store"
	"github.com/aimd54/palan/pkg/modelspec"
)

// keyRuntimeRef configures the default runtime artifact used by run/serve.
const keyRuntimeRef = "runtime.ref"

func newRunCmd(v *viper.Viper) *cobra.Command {
	var (
		prompt     string
		runtimeRef string
		ctxSize    int
		ngl        int
		web        bool
	)

	cmd := &cobra.Command{
		Use:   "run REF",
		Short: "Run a model interactively (pulling it if needed)",
		Long: `Run ensures the model and a llama-server runtime are available, spawns
llama-server on the raw weight blob straight from the store (no copy), and
opens an interactive chat. With --prompt it answers once and exits; with
--web it serves llama-server's UI until interrupted.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			ref, err := refname.Parse(args[0], v.GetString(keyRegistryDefault))
			if err != nil {
				return err
			}
			st, err := openStore(ctx)
			if err != nil {
				return err
			}

			model, err := ensureModel(ctx, cmd, v, st, ref.String())
			if err != nil {
				return err
			}

			// Serve parameters: pack-time defaults, overridden by flags.
			spec := palanruntime.Spec{
				ModelPath: model.blobPath,
				Alias:     ref.String(),
				CtxSize:   model.defaults.Ctx,
				NGL:       model.defaults.NGL,
				ExtraArgs: model.defaults.Flags,
				LogDir:    filepath.Join(st.Root(), "state", "logs"),
			}
			if ctxSize > 0 {
				spec.CtxSize = ctxSize
			}
			if ngl > 0 {
				spec.NGL = ngl
			}
			if runtimeRef == "" {
				runtimeRef = v.GetString(keyRuntimeRef)
			}
			if spec.Bin, err = palanruntime.Resolve(ctx, st, runtimeRef); err != nil {
				return err
			}

			fmt.Fprintf(cmd.ErrOrStderr(), "Starting %s on %s…\n", filepath.Base(spec.Bin), ref)
			srv, err := palanruntime.Start(ctx, spec)
			if err != nil {
				return err
			}
			defer func() { _ = srv.Stop(context.Background()) }()

			switch {
			case prompt != "":
				_, err = streamChat(ctx, srv.BaseURL(), ref.String(), []chatMessage{{Role: "user", Content: prompt}}, cmd.OutOrStdout())
				fmt.Fprintln(cmd.OutOrStdout())
				return err
			case web:
				fmt.Fprintf(cmd.OutOrStdout(), "llama-server UI: %s (Ctrl-C to stop)\n", srv.BaseURL())
				select {
				case <-ctx.Done():
					return nil
				case <-srv.Done():
					return fmt.Errorf("llama-server exited: %w", srv.ExitErr())
				}
			default:
				return chatREPL(ctx, cmd, srv.BaseURL(), ref.String())
			}
		},
	}
	cmd.Flags().StringVarP(&prompt, "prompt", "p", "", "answer this prompt once and exit")
	cmd.Flags().StringVar(&runtimeRef, "runtime", "", "runtime artifact reference (default: runtime.ref config, then PATH)")
	cmd.Flags().IntVar(&ctxSize, "ctx", 0, "context size override")
	cmd.Flags().IntVar(&ngl, "ngl", 0, "GPU layer count override")
	cmd.Flags().BoolVar(&web, "web", false, "expose llama-server's web UI instead of the terminal chat")
	return cmd
}

// modelInfo is what run/serve need from a stored model.
type modelInfo struct {
	blobPath string
	defaults modelspec.ServeDefaults
}

// ensureModel resolves ref locally, pulling it first when absent, and
// returns the weight blob path plus pack-time serve defaults.
func ensureModel(ctx context.Context, cmd *cobra.Command, v *viper.Viper, st *store.Store, ref string) (*modelInfo, error) {
	desc, err := st.Resolve(ctx, ref)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "%s not in local store; pulling…\n", ref)
		parsed, perr := refname.Parse(ref, v.GetString(keyRegistryDefault))
		if perr != nil {
			return nil, perr
		}
		client, cerr := newTransferClient(v)
		if cerr != nil {
			return nil, cerr
		}
		unlock, lerr := st.Lock(ctx)
		if lerr != nil {
			return nil, lerr
		}
		pr := newProgress(v.GetBool("quiet"))
		desc, err = client.Pull(ctx, st, parsed, pr.events())
		pr.close(err)
		unlock()
		if err != nil {
			return nil, err
		}
	}
	return loadModelInfo(ctx, st, ref, desc)
}

// loadModelInfo extracts the weight blob path and serve defaults.
func loadModelInfo(ctx context.Context, st *store.Store, ref string, desc ocispec.Descriptor) (*modelInfo, error) {
	manifest, err := store.FetchManifest(ctx, st.OCI(), desc)
	if err != nil {
		return nil, err
	}
	var weight *ocispec.Descriptor
	for i := range manifest.Layers {
		if modelspec.KindOf(manifest.Layers[i].MediaType) == modelspec.LayerKindWeight {
			weight = &manifest.Layers[i]
			break
		}
	}
	if weight == nil {
		return nil, fmt.Errorf("%s has no weight layer (is it a car-profile image? serve the artifact-profile tag instead)", ref)
	}
	if !modelspec.IsRaw(weight.MediaType) {
		return nil, fmt.Errorf("%s stores weights as %s; only raw weight layers are directly servable", ref, weight.MediaType)
	}
	blobPath, err := st.BlobPath(weight.Digest)
	if err != nil {
		return nil, err
	}
	info := &modelInfo{blobPath: blobPath}
	if raw, ok := manifest.Annotations[modelspec.AnnotationServeDefaults]; ok {
		if d, err := modelspec.ParseServeDefaults(raw); err == nil {
			info.defaults = d
		}
	}
	return info, nil
}

// chatREPL is the interactive loop: newline-terminated prompts on stdin,
// streamed answers on stdout, conversation history preserved.
func chatREPL(ctx context.Context, cmd *cobra.Command, baseURL, model string) error {
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "Chatting with %s — Ctrl-D or /bye to exit.\n", model)
	reader := bufio.NewReader(cmd.InOrStdin())
	var history []chatMessage
	for {
		fmt.Fprint(out, "\n> ")
		line, err := reader.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				fmt.Fprintln(out)
				return nil
			}
			return err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if line == "/bye" {
			return nil
		}
		history = append(history, chatMessage{Role: "user", Content: line})
		reply, err := streamChat(ctx, baseURL, model, history, out)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "\nerror: %v\n", err)
			history = history[:len(history)-1]
			continue
		}
		fmt.Fprintln(out)
		history = append(history, chatMessage{Role: "assistant", Content: reply})
	}
}
