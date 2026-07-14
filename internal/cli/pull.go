// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/aimd54/palan/internal/refname"
	"github.com/aimd54/palan/internal/store"
	"github.com/aimd54/palan/pkg/modelspec"
)

func newPullCmd(v *viper.Viper) *cobra.Command {
	var (
		outputDir string
		doVerify  bool
		verifyKey string
	)
	cmd := &cobra.Command{
		Use:   "pull REF",
		Short: "Pull a model from a registry into the local store",
		Long: `Pull resolves REF on its registry and fetches missing blobs concurrently,
verifying digests. Interrupted downloads resume from where they stopped,
including across process restarts.

With --output, the model's files are additionally materialized into a
directory (named per their org.cncf.model.filepath annotations) — the
Kubernetes init-container pattern: pull into an emptyDir, serve with any
llama-server image.`,
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
			unlock, err := st.Lock(ctx)
			if err != nil {
				return err
			}
			defer unlock()

			client, err := newTransferClient(v)
			if err != nil {
				return err
			}

			// Signature gate (design §11): verify the manifest signature
			// BEFORE any weight bytes move, when asked or when the config
			// enforces verify.required.
			if doVerify || v.GetBool(keyVerifyRequired) {
				repo, err := client.Repository(ref)
				if err != nil {
					return err
				}
				desc, err := repo.Resolve(ctx, ref.Reference)
				if err != nil {
					return err
				}
				if err := verifyDigest(ctx, v, verifyKey, client, ref, desc.Digest); err != nil {
					return err
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "Signature verified for %s@%s\n", ref, desc.Digest)
			}

			pr := newProgress(v.GetBool("quiet"))
			desc, err := client.Pull(ctx, st, ref, pr.events())
			pr.close(err)
			if err != nil {
				return err
			}
			pr.report()
			fmt.Fprintf(cmd.OutOrStdout(), "Pulled %s\nDigest: %s\n", ref, desc.Digest)

			if outputDir != "" {
				files, err := materialize(ctx, st, desc, outputDir)
				if err != nil {
					return err
				}
				for _, f := range files {
					fmt.Fprintf(cmd.OutOrStdout(), "Wrote %s\n", f)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&outputDir, "output", "o", "", "also materialize the model files into this directory")
	cmd.Flags().BoolVar(&doVerify, "verify", false, "verify the artifact's signature before downloading (always on when verify.required is set)")
	cmd.Flags().StringVar(&verifyKey, "verify-key", "", "public key for --verify (default: verify.key from the config)")
	return cmd
}

// materialize copies raw layers into dir under their filepath annotations,
// refusing names that would escape the directory.
func materialize(ctx context.Context, st *store.Store, desc ocispec.Descriptor, dir string) ([]string, error) {
	manifest, err := store.FetchManifest(ctx, st.OCI(), desc)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	var written []string
	for _, l := range manifest.Layers {
		name := l.Annotations[modelspec.AnnotationFilepath]
		if name == "" {
			continue
		}
		if !modelspec.IsRaw(l.MediaType) {
			return nil, fmt.Errorf("layer %s is %s; only raw layers can be materialized (tar-based ModelPack variants are not supported yet)", name, l.MediaType)
		}
		clean := filepath.Clean(name)
		if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("layer file name %q escapes the output directory", name)
		}
		dest := filepath.Join(dir, clean)
		if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
			return nil, err
		}
		src, err := st.BlobPath(l.Digest)
		if err != nil {
			return nil, err
		}
		if err := copyFile(src, dest, 0o644); err != nil {
			return nil, err
		}
		written = append(written, dest)
	}
	if len(written) == 0 {
		return nil, fmt.Errorf("nothing to materialize: no raw layers with filepath annotations (car-profile images are mounted, not materialized)")
	}
	return written, nil
}

func copyFile(src, dest string, mode os.FileMode) error {
	in, err := os.Open(src) // #nosec G304 -- digest-derived path inside the store
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode) // #nosec G304 -- traversal-checked destination
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
