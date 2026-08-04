// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"os"
	"slices"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/aimd54/palan/internal/hf"
	"github.com/aimd54/palan/internal/pack"
	"github.com/aimd54/palan/internal/refname"
	"github.com/aimd54/palan/pkg/modelspec"
)

func newPackCmd(v *viper.Viper) *cobra.Command {
	var (
		tag       string
		profile   string
		sourceURL string
		license   string
		ctxSize   int
		ngl       int
		originSHA string
		doPush    bool
	)

	cmd := &cobra.Command{
		Use:   "pack PATH... -t REF",
		Short: "Build a ModelPack artifact from GGUF and companion files",
		Example: `  # Pack a local GGUF with its licence and serving defaults
  palan pack qwen3-8b-q4.gguf LICENSE -t llm/qwen3:8b-q4 --ctx 8192 --ngl 99

  # Pack straight from Hugging Face, then push
  palan pack hf://Qwen/Qwen3-8B-GGUF/Qwen3-8B-Q4_K_M.gguf -t llm/qwen3:8b-q4 --push`,
		Long: `Pack reads the GGUF header to fill the model config (architecture,
quantization, size, context length) and stores a ModelPack artifact in the
local store under REF. Packing is reproducible: identical inputs yield an
identical digest.

A PATH may be a local file or a Hugging Face source,
hf://<org>/<repo>/<file>, which is downloaded first:

  palan pack hf://Qwen/Qwen3-8B-GGUF/Qwen3-8B-Q4_K_M.gguf -t llm/qwen3:8b-q4

The bytes are checked against the SHA-256 the repository publishes and
refused if they differ, that digest becomes io.palan.origin.sha256, and the
repository page becomes the source annotation. A split GGUF brings every
sibling part, and a licence file in the repository travels with the weights.
Naming a repository without a file lists what it publishes. Gated
repositories read HF_TOKEN.

Profiles: "artifact" (raw GGUF layers; the default), "car" (an OCI image
with one tar layer under models/, for Kubernetes image volumes and KServe
modelcars; tagged REF-car), or "both".`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			ref, err := refname.Parse(tag, v.GetString(keyRegistryDefault))
			if err != nil {
				return err
			}
			if err := ref.ValidateReferenceAsTag(); err != nil {
				return fmt.Errorf("pack requires a tag reference, not a digest: %w", err)
			}
			if profile != "artifact" && profile != "car" && profile != "both" {
				return fmt.Errorf("invalid --profile %q (artifact|car|both)", profile)
			}

			paths, fetched, err := resolveSources(ctx, cmd, args)
			if err != nil {
				return err
			}
			if fetched.tempDir != "" {
				defer func() { _ = os.RemoveAll(fetched.tempDir) }()
			}

			files := make([]pack.File, 0, len(paths))
			for _, p := range paths {
				files = append(files, pack.File{Path: p})
			}
			// What the source published beats what palan can infer: the
			// upstream digest is the point of the annotation, and the
			// repository page is a better provenance link than nothing.
			if sourceURL == "" {
				sourceURL = fetched.sourceURL
			}
			if originSHA == "" {
				originSHA = fetched.originSHA256
			}
			opts := pack.Options{
				SourceURL:    sourceURL,
				License:      license,
				OriginSHA256: originSHA,
			}
			if ctxSize > 0 || ngl > 0 {
				opts.ServeDefaults = &modelspec.ServeDefaults{Ctx: ctxSize, NGL: ngl}
			}

			st, err := openStore(ctx)
			if err != nil {
				return err
			}
			unlock, err := st.Lock(ctx)
			if err != nil {
				return err
			}
			defer unlock()

			type packed struct {
				ref  string
				desc ocispec.Descriptor
			}
			var results []packed

			if profile == "artifact" || profile == "both" {
				desc, err := pack.Model(ctx, st, files, ref.String(), opts)
				if err != nil {
					return err
				}
				results = append(results, packed{ref.String(), desc})
			}
			if profile == "car" || profile == "both" {
				carRef := ref
				carRef.Reference = ref.Reference + "-car"
				desc, err := pack.Car(ctx, st, files, carRef.String(), opts)
				if err != nil {
					return err
				}
				results = append(results, packed{carRef.String(), desc})
			}

			for _, r := range results {
				fmt.Fprintf(cmd.OutOrStdout(), "Packed %s\nDigest: %s\n", r.ref, r.desc.Digest)
			}

			if doPush {
				client, err := newTransferClient(v)
				if err != nil {
					return err
				}
				for _, r := range results {
					pushRef, err := refname.Parse(r.ref, "")
					if err != nil {
						return err
					}
					pr := newProgress(v.GetBool("quiet"))
					_, err = client.Push(ctx, st, pushRef, pr.events())
					pr.close(err)
					if err != nil {
						return err
					}
					fmt.Fprintf(cmd.OutOrStdout(), "Pushed %s\n", r.ref)
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&tag, "tag", "t", "", "reference to tag the packed model with (required)")
	cmd.Flags().StringVar(&profile, "profile", "artifact", "output profile: artifact|car|both")
	cmd.Flags().StringVar(&sourceURL, "source", "", "upstream source URL (org.opencontainers.image.source)")
	cmd.Flags().StringVar(&license, "license", "", "SPDX license expression (default: the GGUF header's general.license)")
	cmd.Flags().IntVar(&ctxSize, "ctx", 0, "default context size for serving (io.palan.serve.defaults)")
	cmd.Flags().IntVar(&ngl, "ngl", 0, "default GPU layer count for serving; unset means serve passes no --n-gpu-layers (io.palan.serve.defaults)")
	cmd.Flags().StringVar(&originSHA, "origin-sha256", "", "SHA-256 of the original upstream file (default: the weight digest)")
	cmd.Flags().BoolVar(&doPush, "push", false, "push to the registry after packing")
	must(cmd.MarkFlagRequired("tag"))
	return cmd
}

// fetchedSources records what a remote source contributed beyond its files:
// provenance that palan could not otherwise know.
type fetchedSources struct {
	tempDir      string
	sourceURL    string
	originSHA256 string
}

// resolveSources turns pack arguments into local paths, downloading any
// hf:// references first. Local paths pass through untouched, so a command can
// mix a fetched model with a licence or template already on disk.
//
// The weight file's upstream digest and the repository URL are carried back,
// because a model fetched from a known source should say so rather than
// annotating itself with its own digest.
func resolveSources(ctx context.Context, cmd *cobra.Command, args []string) ([]string, fetchedSources, error) {
	var info fetchedSources
	if !slices.ContainsFunc(args, hf.IsRef) {
		return args, info, nil
	}

	tmp, err := os.MkdirTemp("", "palan-fetch-*")
	if err != nil {
		return nil, info, err
	}
	info.tempDir = tmp
	client := hf.NewClient()
	out := make([]string, 0, len(args))

	for _, arg := range args {
		if !hf.IsRef(arg) {
			out = append(out, arg)
			continue
		}
		ref, err := hf.ParseRef(arg)
		if err != nil {
			return nil, info, err
		}
		files, err := client.Resolve(ctx, ref)
		if err != nil {
			return nil, info, err
		}
		if info.sourceURL == "" {
			info.sourceURL = ref.URL()
		}
		for _, f := range files {
			fmt.Fprintf(cmd.ErrOrStderr(), "Fetching %s (%s)\n", f.Path, humanBytes(f.Size))
			path, err := client.Download(ctx, ref, f, tmp, hf.Events{})
			if err != nil {
				return nil, info, err
			}
			// The named weight file is the one whose provenance matters; a
			// licence fetched alongside it is not what the artifact is.
			if f.Path == ref.Path && f.SHA256 != "" {
				info.originSHA256 = "sha256:" + f.SHA256
			}
			out = append(out, path)
		}
	}
	return out, info, nil
}
