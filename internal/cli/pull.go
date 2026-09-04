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
		Example: `  # Pull into the local store
  palan pull registry.internal/llm/qwen3:8b-q4

  # Refuse the model unless it carries a valid signature
  palan pull registry.internal/llm/qwen3:8b-q4 --verify --verify-key cosign.pub`,
		Long: `Pull resolves REF on its registry and fetches missing blobs concurrently,
verifying digests. Interrupted downloads resume from where they stopped,
including across process restarts.

With --output, the model's files are additionally materialized into a
directory (named per their org.cncf.model.filepath annotations). This is
the Kubernetes init-container pattern: pull into an emptyDir, serve with
any llama-server image.`,
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

			// Signature gate (see docs/architecture.md, "Security model"):
			// verify the manifest signature BEFORE any weight bytes move,
			// when asked or when the config
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
				// The registry is the only source that makes sense here: the
				// gate runs before anything is downloaded, so a local copy
				// would be the previous version rather than what is arriving.
				src := remoteSource(repo, desc, "registry")
				if _, err := verifyDigest(ctx, v, verifyKey, src, ref); err != nil {
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
//
// Every layer is held to the digest its manifest records as it is written.
// The file that lands here is a copy leaving the content-addressed store,
// and it is the copy something else goes on to read: an init container
// writes it into a volume a serving container mounts. A store blob is
// addressed by its file name and by nothing else, and a transfer skips a
// blob that is already present, so bytes altered in the store on an earlier
// day would otherwise be written out under a signature checked today.
func materialize(ctx context.Context, st *store.Store, desc ocispec.Descriptor, dir string) ([]string, error) {
	manifest, err := store.FetchManifest(ctx, st.OCI(), desc)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	var written []string
	// A model can be many files, and a failure on the fourth leaves three
	// already on disk. The directory is what something else reads, so a
	// refusal has to take back what it wrote rather than leave a partial
	// model that looks like a whole one.
	complete := false
	defer func() {
		if complete {
			return
		}
		for _, p := range written {
			_ = os.Remove(p)
		}
	}()
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
		// Recorded before the write, so the cleanup below covers the file
		// that failed as well as the ones that succeeded. A failure can
		// leave a partial or wrong-length file, and it is the same problem
		// as a completed one holding the wrong bytes.
		written = append(written, dest)
		if err := copyFile(src, dest, l, 0o644); err != nil {
			return nil, err
		}
	}
	if len(written) == 0 {
		return nil, fmt.Errorf("nothing to materialize: no raw layers with filepath annotations (car-profile images are mounted, not materialized)")
	}
	complete = true
	return written, nil
}

// copyFile writes one blob out of the store to dest, holding the bytes to
// the digest desc records as they go past.
//
// The destination is opened without following a symlink. A name already in
// the output directory that points somewhere else would otherwise be
// written through, so a pull into a directory somebody else can prepare
// would write the model wherever that link aimed.
func copyFile(src, dest string, desc ocispec.Descriptor, mode os.FileMode) error {
	in, err := os.Open(src) // #nosec G304 -- digest-derived path inside the store
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	// Checked before the open as well as refused by it: the flag has no
	// Windows equivalent, and an existing name that is not a regular file
	// deserves a message naming what it is.
	if fi, lerr := os.Lstat(dest); lerr == nil && !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is a %s, not a regular file", dest, fi.Mode().Type())
	}
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|openNoFollow, mode) // #nosec G304 -- traversal-checked destination
	if err != nil {
		return err
	}
	verifier := desc.Digest.Verifier()
	n, err := io.Copy(io.MultiWriter(out, verifier), io.LimitReader(in, desc.Size+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n != desc.Size {
		return fmt.Errorf("blob %s holds %d bytes in the store, the manifest records %d", desc.Digest, n, desc.Size)
	}
	if !verifier.Verified() {
		return fmt.Errorf(
			"blob %s does not hash to the digest the manifest records, so %s was not written",
			desc.Digest, filepath.Base(dest))
	}
	return nil
}
