// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package transfer

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	oras "oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry"

	"github.com/aimd54/palan/internal/signing"
	"github.com/aimd54/palan/internal/store"
)

// Copy transfers an artifact between two registries without touching the
// local store: the air-gap and mirroring workhorse.
func (c *Client) Copy(ctx context.Context, src, dst registry.Reference, ev Events) (ocispec.Descriptor, error) {
	srcRepo, err := c.Repository(src)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	dstRepo, err := c.Repository(dst)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	opts := oras.CopyOptions{CopyGraphOptions: oras.CopyGraphOptions{
		Concurrency: c.concurrency(),
		OnCopySkipped: func(_ context.Context, desc ocispec.Descriptor) error {
			ev.blobSkip(desc)
			return nil
		},
	}}
	desc, err := oras.Copy(ctx, &fetchCounter{ReadOnlyTarget: srcRepo, ev: ev}, src.Reference, dstRepo, dst.Reference, opts)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("copying %s to %s: %w", src, dst, err)
	}

	// Mirroring into an offline registry is one of the two ways a model
	// crosses a gap, and a model that arrives without its signature cannot be
	// verified on the far side. The copy is still supplementary: the model is
	// already mirrored, and registries disagree on what they answer for a tag
	// that is absent or invisible, so a lookup failure is reported rather than
	// undoing a transfer that succeeded.
	sigTag := signing.SigTag(desc.Digest)
	switch _, err := srcRepo.Resolve(ctx, sigTag); {
	case err == nil:
		if _, err := oras.Copy(ctx, srcRepo, sigTag, dstRepo, sigTag, opts); err != nil {
			ev.signature(false, fmt.Errorf("copying the signature for %s: %w", src, err))
		} else {
			ev.signature(true, nil)
		}
	case errors.Is(err, errdef.ErrNotFound):
		ev.signature(false, nil) // unsigned, nothing more to carry
	default:
		ev.signature(false, fmt.Errorf("looking for a signature on %s: %w", src, err))
	}

	// An attestation travels the same way, independently of whether a
	// signature exists: most artifacts carry neither, and carrying one must
	// not depend on the other being present. A lookup or copy that fails is
	// reported rather than swallowed, for the same reason it is on the
	// signature above: a mirror that silently lost the attestation is
	// indistinguishable from one whose source never had it.
	attTag := signing.AttTag(desc.Digest)
	switch _, err := srcRepo.Resolve(ctx, attTag); {
	case err == nil:
		if _, err := oras.Copy(ctx, srcRepo, attTag, dstRepo, attTag, opts); err != nil {
			ev.attestation(false, fmt.Errorf("copying the attestation for %s: %w", src, err))
		} else {
			ev.attestation(true, nil)
		}
	case errors.Is(err, errdef.ErrNotFound):
		ev.attestation(false, nil) // no attestation, nothing more to carry
	default:
		ev.attestation(false, fmt.Errorf("looking for an attestation on %s: %w", src, err))
	}

	// A keyless signature is found by asking what refers to the model
	// rather than by tag, because that is the only place one is written.
	// It is otherwise carried on the same terms as the two above: a mirror
	// that silently lost it leaves the far side unable to check a model it
	// could have checked.
	switch bundles, err := signing.BundleReferrers(ctx, srcRepo, desc); {
	case err != nil:
		ev.bundle(false, fmt.Errorf("looking for a keyless signature on %s: %w", src, err))
	case len(bundles) == 0:
		ev.bundle(false, nil) // no keyless signature, nothing more to carry
	default:
		var problem error
		for _, b := range bundles {
			from := b.Digest.String()
			if _, err := oras.Copy(ctx, srcRepo, from, dstRepo, from, opts); err != nil {
				problem = fmt.Errorf("copying a keyless signature for %s: %w", src, err)
				break
			}
		}
		ev.bundle(problem == nil, problem)
	}

	return desc, nil
}

// Save exports refs from the local store into a tar stream containing a
// standard OCI image layout, readable by any OCI tool
// (see docs/architecture.md, "Client and local store": offline transfer bundles).
//
// A model's signature and its source attestation travel with it when the
// store holds them, so the bundle can be verified on a machine that never
// reaches a registry. Save reports how many of each it included, since that
// is not something the caller's list of references reveals.
func Save(ctx context.Context, st *store.Store, refs []string, w io.Writer) (SaveReport, error) {
	tmp, err := os.MkdirTemp("", "palan-save-*")
	if err != nil {
		return SaveReport{}, err
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	dst, err := oci.NewWithContext(ctx, tmp)
	if err != nil {
		return SaveReport{}, err
	}
	var report SaveReport
	for _, ref := range refs {
		desc, err := oras.Copy(ctx, st.OCI(), ref, dst, ref, oras.DefaultCopyOptions)
		if err != nil {
			return SaveReport{}, fmt.Errorf("exporting %s: %w", ref, err)
		}
		signed, err := saveSignature(ctx, st, dst, ref, desc.Digest)
		if err != nil {
			return SaveReport{}, err
		}
		if signed {
			report.Signatures++
		}
		attested, err := saveAttestation(ctx, st, dst, ref, desc.Digest)
		if err != nil {
			return SaveReport{}, err
		}
		if attested {
			report.Attestations++
		}
		bundled, err := saveBundles(ctx, st, dst, ref, desc)
		if err != nil {
			return SaveReport{}, err
		}
		report.Bundles += bundled
	}
	if err := tarDir(tmp, w); err != nil {
		return SaveReport{}, err
	}
	return report, nil
}

// SaveReport counts the supplementary objects a bundle carries beside the
// models themselves. Neither count is derivable from the references the
// caller asked for, and both decide what the far side can check.
type SaveReport struct {
	// Signatures is how many of the exported models carried one.
	Signatures int
	// Attestations is how many carried a source attestation.
	Attestations int
	// Bundles is how many carried a keyless signature. It is counted apart
	// from Signatures because the far side needs different material to
	// check one: a pinned trusted root rather than a public key.
	Bundles int
}

// saveSignature copies a reference's signature into the bundle when the store
// has one. An unsigned model is ordinary, so a missing signature is reported
// rather than treated as a failure.
func saveSignature(ctx context.Context, st *store.Store, dst *oci.Store, ref string, d digest.Digest) (bool, error) {
	parsed, err := registry.ParseReference(ref)
	if err != nil {
		// Not a registry-shaped reference, so no signature can be addressed.
		return false, nil //nolint:nilerr // exporting the artifact alone is correct here
	}
	sigRef := signing.SigRef(parsed, d)
	if _, err := st.Resolve(ctx, sigRef); err != nil {
		if errors.Is(err, errdef.ErrNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("looking for a signature on %s: %w", ref, err)
	}
	if _, err := oras.Copy(ctx, st.OCI(), sigRef, dst, sigRef, oras.DefaultCopyOptions); err != nil {
		return false, fmt.Errorf("exporting the signature for %s: %w", ref, err)
	}
	return true, nil
}

// saveAttestation copies a reference's source attestation into the bundle
// when the store has one, the same way saveSignature copies its signature.
// Most artifacts carry no attestation, so a missing one is reported rather
// than treated as a failure.
func saveAttestation(ctx context.Context, st *store.Store, dst *oci.Store, ref string, d digest.Digest) (bool, error) {
	parsed, err := registry.ParseReference(ref)
	if err != nil {
		// Not a registry-shaped reference, so no attestation can be addressed.
		return false, nil //nolint:nilerr // exporting the artifact alone is correct here
	}
	attRef := signing.AttRef(parsed, d)
	if _, err := st.Resolve(ctx, attRef); err != nil {
		if errors.Is(err, errdef.ErrNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("looking for an attestation on %s: %w", ref, err)
	}
	if _, err := oras.Copy(ctx, st.OCI(), attRef, dst, attRef, oras.DefaultCopyOptions); err != nil {
		return false, fmt.Errorf("exporting the attestation for %s: %w", ref, err)
	}
	return true, nil
}

// saveBundles copies every keyless signature attached to a reference into
// the bundle and reports how many travelled. They are found by asking what
// refers to the model rather than by name, because a bundle is named after
// itself and an artifact may carry several. Most artifacts carry none, so
// none is reported rather than treated as a failure.
//
// Each is copied by digest and named at the destination. A bundle in the
// store need not carry palan's name for it: the store is a plain OCI
// layout, so another tool can attach one knowing only the subject
// relationship. Resolving the name first would fail on exactly that
// bundle and take the whole export down with it.
func saveBundles(ctx context.Context, st *store.Store, dst *oci.Store, ref string, target ocispec.Descriptor) (int, error) {
	parsed, err := registry.ParseReference(ref)
	if err != nil {
		// Not a registry-shaped reference, so no signature can be addressed.
		return 0, nil //nolint:nilerr // exporting the artifact alone is correct here
	}
	bundles, err := signing.BundleReferrers(ctx, st.OCI(), target)
	if err != nil {
		return 0, fmt.Errorf("looking for a keyless signature on %s: %w", ref, err)
	}
	for _, b := range bundles {
		if _, err := oras.Copy(ctx, st.OCI(), b.Digest.String(), dst,
			signing.BundleRef(parsed, b.Digest), oras.DefaultCopyOptions); err != nil {
			return 0, fmt.Errorf("exporting a keyless signature for %s: %w", ref, err)
		}
	}
	return len(bundles), nil
}

// LoadOption configures Load.
type LoadOption func(*loadConfig)

type loadConfig struct {
	beforeImport func(ctx context.Context, bundle oras.ReadOnlyTarget, refs []string) error
}

// WithBeforeImport runs fn against the bundle's own layout before any content
// reaches the store, so a policy check can reject a bundle without the store
// ever holding what it rejected. A non-nil error aborts the whole import.
//
// The callback takes a plain read-only target rather than anything from the
// signing package, which keeps verification policy out of the transfer layer.
func WithBeforeImport(fn func(ctx context.Context, bundle oras.ReadOnlyTarget, refs []string) error) LoadOption {
	return func(c *loadConfig) { c.beforeImport = fn }
}

// Load imports every tagged reference from a tar'd OCI image layout into
// the local store and returns the imported refs.
func Load(ctx context.Context, st *store.Store, r io.Reader, opts ...LoadOption) ([]string, error) {
	tmp, err := os.MkdirTemp("", "palan-load-*")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	if err := untarDir(r, tmp); err != nil {
		return nil, fmt.Errorf("unpacking bundle: %w", err)
	}
	src, err := oci.NewWithContext(ctx, tmp)
	if err != nil {
		return nil, fmt.Errorf("bundle is not an OCI image layout: %w", err)
	}
	var refs []string
	if err := src.Tags(ctx, "", func(tags []string) error {
		refs = append(refs, tags...)
		return nil
	}); err != nil {
		return nil, err
	}
	if len(refs) == 0 {
		return nil, errors.New("bundle contains no tagged references")
	}

	var cfg loadConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.beforeImport != nil {
		if err := cfg.beforeImport(ctx, src, refs); err != nil {
			return nil, err
		}
	}

	for _, ref := range refs {
		if _, err := oras.Copy(ctx, src, ref, st.OCI(), ref, oras.DefaultCopyOptions); err != nil {
			return nil, fmt.Errorf("importing %s: %w", ref, err)
		}
	}
	return refs, nil
}

// tarDir archives dir with deterministic entries (sorted paths, zeroed
// times, fixed ownership).
func tarDir(dir string, w io.Writer) error {
	var paths []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p != dir {
			paths = append(paths, p)
		}
		return nil
	})
	if err != nil {
		return err
	}
	sort.Strings(paths)

	tw := tar.NewWriter(w)
	for _, p := range paths {
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		switch {
		case fi.IsDir():
			if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: rel + "/", Mode: 0o755, Format: tar.FormatUSTAR}); err != nil {
				return err
			}
		case fi.Mode().IsRegular():
			if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: rel, Size: fi.Size(), Mode: 0o644, Format: tar.FormatUSTAR}); err != nil {
				return err
			}
			f, err := os.Open(p) // #nosec G304 -- walking our own temp export dir
			if err != nil {
				return err
			}
			_, err = io.Copy(tw, f)
			_ = f.Close()
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported file type in layout: %s", rel)
		}
	}
	return tw.Close()
}

// untarDir extracts a tar stream under dir, rejecting path traversal,
// absolute paths, and links (an OCI layout needs none of them).
func untarDir(r io.Reader, dir string) error {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		name := filepath.Clean(hdr.Name)
		if filepath.IsAbs(name) || strings.HasPrefix(name, "..") {
			return fmt.Errorf("bundle entry escapes extraction dir: %q", hdr.Name)
		}
		dest := filepath.Join(dir, name)
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dest, 0o750); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
				return err
			}
			f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) // #nosec G304 -- traversal-checked above
			if err != nil {
				return err
			}
			// The layout's own digest verification happens on import; the
			// size bound here only guards the temp dir against tar bombs
			// beyond the header-declared size.
			if _, err := io.CopyN(f, tr, hdr.Size); err != nil && !errors.Is(err, io.EOF) {
				_ = f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
		default:
			return fmt.Errorf("bundle entry %q has unsupported type %d", hdr.Name, hdr.Typeflag)
		}
	}
}
