// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

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
		Long: `Pack reads the GGUF header to fill the model config (architecture,
quantization, size, context length) and stores a ModelPack artifact in the
local store under REF. Packing is reproducible: identical inputs yield an
identical digest.

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

			files := make([]pack.File, 0, len(args))
			for _, p := range args {
				files = append(files, pack.File{Path: p})
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
	cmd.Flags().IntVar(&ngl, "ngl", 0, "default GPU layer count for serving (io.palan.serve.defaults)")
	cmd.Flags().StringVar(&originSHA, "origin-sha256", "", "SHA-256 of the original upstream file (default: the weight digest)")
	cmd.Flags().BoolVar(&doPush, "push", false, "push to the registry after packing")
	must(cmd.MarkFlagRequired("tag"))
	return cmd
}
