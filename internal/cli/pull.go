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

	"github.com/opencontainers/go-digest"
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
			// The artifact a signature was checked against, empty when no
			// check was asked for.
			var verified digest.Digest
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
				// Carried into the fetch. Without it the tag is resolved
				// again below, and a registry that answers differently the
				// second time has one artifact checked and another
				// downloaded, materialized and served.
				verified = desc.Digest
				fmt.Fprintf(cmd.ErrOrStderr(), "Signature verified for %s@%s\n", ref, desc.Digest)
			}

			pr := newProgress(v.GetBool("quiet"))
			desc, err := client.Pull(ctx, st, ref, verified, pr.events())
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
	// Every write goes through this handle, which the kernel holds to the
	// directory it was opened on. A layer file name may be nested, and
	// checking the components in advance is a check followed by a use: the
	// path is resolved again at open time, so a component swapped for a
	// link in between escapes anyway. Resolving beneath a root closes that
	// interval rather than narrowing it.
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()

	var written []string
	var madeDirs []string
	seen := make(map[string]bool, len(manifest.Layers))
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
			_ = root.Remove(p)
		}
		// Deepest first, so a nested chain comes apart. Directories the
		// refusal did not create are not in this list and stay.
		for i := len(madeDirs) - 1; i >= 0; i-- {
			_ = root.Remove(madeDirs[i])
		}
	}()
	for _, l := range manifest.Layers {
		name := l.Annotations[modelspec.AnnotationFilepath]
		if name == "" {
			// A layer with no file name has nowhere to go. Skipping a
			// small one is right, since not every layer is a file the
			// serving process reads; skipping the weights is not, because
			// the command would report success over a directory holding
			// everything except the model.
			if modelspec.KindOf(l.MediaType) == modelspec.LayerKindWeight {
				return nil, fmt.Errorf(
					"weight layer %s records no file name, so it cannot be written out and the model would be incomplete", l.Digest)
			}
			continue
		}
		if !modelspec.IsRaw(l.MediaType) {
			return nil, fmt.Errorf("layer %s is %s; only raw layers can be materialized (tar-based ModelPack variants are not supported yet)", name, l.MediaType)
		}
		clean := filepath.Clean(name)
		if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("layer file name %q escapes the output directory", name)
		}
		// Compared case-insensitively as well as exactly. macOS is a
		// release target and its default filesystem folds case, so two
		// layers named "Model.gguf" and "model.gguf" are one file there:
		// the second write opens the first one's inode and the earlier
		// layer's bytes are gone with nothing reported.
		fold := strings.ToLower(clean)
		if seen[fold] {
			return nil, fmt.Errorf("two layers claim the file name %q, so one would overwrite the other", clean)
		}
		seen[fold] = true
		if parent := filepath.Dir(clean); parent != "." {
			// Recorded before creation, and only the components that were
			// missing, so a refusal leaves the directory as it found it.
			// The gate pattern is sold on a refusal writing nothing, and a
			// directory left behind is something.
			madeDirs = append(madeDirs, missingDirs(root, parent)...)
			if err := root.MkdirAll(parent, 0o750); err != nil {
				return nil, err
			}
		}
		src, err := st.BlobPath(l.Digest)
		if err != nil {
			return nil, err
		}
		// Recorded before the write, so the cleanup below covers the file
		// that failed as well as the ones that succeeded. A failure can
		// leave a partial or wrong-length file, and it is the same problem
		// as a completed one holding the wrong bytes.
		written = append(written, clean)
		if err := copyFile(src, root, clean, l, 0o644); err != nil {
			return nil, err
		}
	}
	if len(written) == 0 {
		return nil, fmt.Errorf("nothing to materialize: no raw layers with filepath annotations (car-profile images are mounted, not materialized)")
	}
	complete = true
	// Reported as paths a reader can go and look at, having been written
	// through the root as names relative to it.
	full := make([]string, 0, len(written))
	for _, w := range written {
		full = append(full, filepath.Join(dir, w))
	}
	return full, nil
}

// missingDirs reports the components of rel that do not yet exist beneath
// root, outermost first, so a caller can take back exactly what it created.
func missingDirs(root *os.Root, rel string) []string {
	var missing []string
	cur := ""
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		cur = filepath.Join(cur, part)
		if _, err := root.Lstat(cur); err != nil {
			missing = append(missing, cur)
		}
	}
	return missing
}

// copyFile writes one blob out of the store to name beneath root, holding
// the bytes to the digest desc records as they go past.
func copyFile(src string, root *os.Root, name string, desc ocispec.Descriptor, mode os.FileMode) error {
	in, err := os.Open(src) // #nosec G304 -- digest-derived path inside the store
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	// The root refuses a name resolving outside the output directory,
	// including through a link at any component, and it resolves the path
	// itself, so a caller's O_NOFOLLOW is subsumed and does nothing. A link
	// that stays inside the directory is therefore followed, and the write
	// lands on whatever it names. Refused here instead: the file this
	// writes has to be the file the layer named.
	if fi, lerr := root.Lstat(name); lerr == nil && !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is a %s in the output directory, not a regular file", name, fi.Mode().Type())
	}
	out, err := root.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
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
			desc.Digest, filepath.Base(name))
	}
	return nil
}
