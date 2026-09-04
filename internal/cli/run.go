// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	tea "charm.land/bubbletea/v2"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"

	"github.com/aimd54/palan/internal/gguf"
	"github.com/aimd54/palan/internal/modelmeta"
	"github.com/aimd54/palan/internal/refname"
	palanruntime "github.com/aimd54/palan/internal/runtime"
	"github.com/aimd54/palan/internal/store"
	"github.com/aimd54/palan/internal/ui"
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
		doVerify   bool
		verifyKey  string
		doRehash   bool
	)

	cmd := &cobra.Command{
		Use:   "run REF",
		Short: "Run a model interactively (pulling it if needed)",
		Example: `  # Interactive chat; /bye or Ctrl-D to leave
  palan run llm/qwen3:8b-q4

  # Answer one prompt and exit, for scripts
  palan run llm/qwen3:8b-q4 -p "One-line haiku about registries"`,
		Long: `Run ensures the model and a llama-server runtime are available, spawns
llama-server on the raw weight blob straight from the store (no copy), and
opens an interactive chat. With --prompt it answers once and exits; with
--web it serves llama-server's UI until interrupted.`,
		// At a terminal, a missing reference opens the store to choose from.
		// Without one it stays an error, so a script that omits the argument
		// fails instead of waiting for a keystroke that will never come.
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			target, err := refOrPick(ctx, cmd, args, "Run which model?")
			if err != nil {
				return err
			}
			ref, err := refname.Parse(target, v.GetString(keyRegistryDefault))
			if err != nil {
				return err
			}
			st, err := openStore(ctx)
			if err != nil {
				return err
			}

			// Check the policy before anything is fetched or spawned: when
			// the model is absent, resolveVerifySource answers from the
			// registry, so an unsigned model is refused without downloading
			// it first.
			var verified ocispec.Descriptor
			gate := verifyGate(v, st, doVerify, verifyKey)
			if gate != nil {
				if verified, err = gate(ctx, ref.String()); err != nil {
					return err
				}
			}

			// Once the copy to be loaded is on disk, hold it to the
			// artifact that verified, before anything reads it. The gate
			// may have answered from the registry, and a fetch reuses
			// whatever blobs are already here.
			//
			// Asked for on its own, re-reading the blobs runs with no
			// signature check beside it. Tying it to the gate would make
			// --rehash exit 0 having read nothing on a host that had not
			// also configured verification.
			rehash := rehashRequested(v, doRehash)
			var check func(context.Context, ocispec.Descriptor) error
			if gate != nil || rehash {
				check = func(ctx context.Context, local ocispec.Descriptor) error {
					return checkLoadedContent(ctx, st, ref.String(), local, verified, rehash)
				}
			}
			model, err := ensureModel(ctx, cmd, v, st, ref.String(), check)
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
			// The engine is held to the same policy as the weights it is
			// about to read.
			runtimeRef, err = checkRuntime(ctx, cmd.ErrOrStderr(), v, st, gate, runtimeRef, rehash)
			if err != nil {
				return err
			}
			if spec.Bin, err = palanruntime.Resolve(ctx, st, runtimeRef); err != nil {
				return err
			}

			fmt.Fprintf(cmd.ErrOrStderr(), "Starting %s on %s...\n", filepath.Base(spec.Bin), ref)
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
				return chat(ctx, cmd, srv.BaseURL(), ref.String())
			}
		},
	}
	cmd.Flags().StringVarP(&prompt, "prompt", "p", "", "answer this prompt once and exit")
	cmd.Flags().StringVar(&runtimeRef, "runtime", "", "runtime artifact reference (default: runtime.ref config, then PATH)")
	cmd.Flags().IntVar(&ctxSize, "ctx", 0, "context size override")
	cmd.Flags().IntVar(&ngl, "ngl", 0, "GPU layer count override")
	cmd.Flags().BoolVar(&web, "web", false, "expose llama-server's web UI instead of the terminal chat")
	cmd.Flags().BoolVar(&doVerify, "verify", false, "require a valid signature before fetching or running the model")
	cmd.Flags().StringVar(&verifyKey, "verify-key", "", "public key for --verify (default: verify.key from the config)")
	cmd.Flags().BoolVar(&doRehash, "rehash", false, "read the model's blobs back at load and hold each to the digest the manifest records")
	return cmd
}

// modelInfo is what run/serve need from a stored model.
type modelInfo struct {
	blobPath string
	defaults modelspec.ServeDefaults
}

// ensureModel resolves ref locally, pulling it first when absent, and
// returns the weight blob path plus pack-time serve defaults.
// check, when set, is run once the artifact is resident and before
// anything reads it. That ordering is the point rather than a detail:
// loadModelInfo parses the artifact's own bytes to decide whether it can be
// served, so a check placed after it would report a parse failure over
// content that should never have been opened.
func ensureModel(
	ctx context.Context, cmd *cobra.Command, v *viper.Viper, st *store.Store, ref string,
	check func(context.Context, ocispec.Descriptor) error,
) (*modelInfo, error) {
	desc, err := st.Resolve(ctx, ref)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "%s not in local store; pulling...\n", ref)
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
	if check != nil {
		if err := check(ctx, desc); err != nil {
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
	if err := requireGGUF(ctx, st, ref, manifest, weight); err != nil {
		return nil, err
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

// requireGGUF refuses an artifact whose weights llama.cpp cannot load
// (ADR-0012). The declared format decides when the config states one. The
// bytes decide otherwise, because an artifact packed by another tool may leave
// the field empty, and a label is not evidence.
func requireGGUF(ctx context.Context, st *store.Store, ref string, manifest ocispec.Manifest, weight *ocispec.Descriptor) error {
	declared := ""
	if manifest.Config.MediaType == modelspec.MediaTypeModelConfig {
		model, err := store.FetchJSON[modelspec.Model](ctx, st.OCI(), manifest.Config)
		if err != nil {
			return err
		}
		declared = model.Config.Format
	}
	if declared != "" && declared != modelmeta.FormatGGUF {
		return fmt.Errorf("%s holds %s weights, which llama.cpp cannot load; "+
			"pull and verify it here, and serve it from a runtime that reads %s",
			ref, declared, declared)
	}

	path, err := st.BlobPath(weight.Digest)
	if err != nil {
		return err
	}
	f, err := os.Open(path) // #nosec G304 -- a blob path from the local store
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	var magic [4]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return fmt.Errorf("%s: reading the weight header: %w", ref, err)
	}
	if string(magic[:]) != gguf.Magic {
		return fmt.Errorf("%s: the primary weight layer begins with %q rather than the %s magic, "+
			"so llama.cpp cannot load it; pull and verify it here, and serve it from a "+
			"runtime that reads the format those bytes belong to",
			ref, magic[:], gguf.Magic)
	}
	return nil
}

// chat opens the interactive session, choosing the interface the destination
// can actually support.
//
// The full interface needs a terminal on both ends: it reads keys and repaints
// a live region. Anything else, a pipe, a here-doc, a CI job, gets the plain
// loop, which reads lines and writes the reply as it arrives. Both hold the
// same conversation; only the presentation differs.
func chat(ctx context.Context, cmd *cobra.Command, baseURL, model string) error {
	in, inOK := cmd.InOrStdin().(*os.File)
	out, outOK := cmd.OutOrStdout().(*os.File)
	interactive := inOK && outOK &&
		term.IsTerminal(int(in.Fd())) && term.IsTerminal(int(out.Fd()))
	if !interactive {
		return chatPlain(ctx, cmd, baseURL, model)
	}

	width, _, err := term.GetSize(int(out.Fd()))
	if err != nil || width <= 0 {
		width = 80
	}
	m, err := newChatModel(ctx, baseURL, model, ui.New(out), width)
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "Chatting with %s. Ctrl-D or /bye to exit.\n", model)
	_, err = tea.NewProgram(m, tea.WithContext(ctx), tea.WithInput(in), tea.WithOutput(out)).Run()
	return err
}

// chatPlain is the interactive loop: newline-terminated prompts on stdin,
// streamed answers on stdout, conversation history preserved.
func chatPlain(ctx context.Context, cmd *cobra.Command, baseURL, model string) error {
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "Chatting with %s. Ctrl-D or /bye to exit.\n", model)
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
