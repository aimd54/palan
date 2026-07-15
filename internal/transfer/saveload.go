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

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	oras "oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/registry"

	"github.com/aimd54/palan/internal/store"
)

// Copy transfers an artifact between two registries without touching the
// local store — the air-gap and mirroring workhorse.
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
	return desc, nil
}

// Save exports refs from the local store into a tar stream containing a
// standard OCI image layout — readable by any OCI tool, not just palan
// (see docs/architecture.md, "Client and local store": offline transfer bundles).
func Save(ctx context.Context, st *store.Store, refs []string, w io.Writer) error {
	tmp, err := os.MkdirTemp("", "palan-save-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	dst, err := oci.NewWithContext(ctx, tmp)
	if err != nil {
		return err
	}
	for _, ref := range refs {
		if _, err := oras.Copy(ctx, st.OCI(), ref, dst, ref, oras.DefaultCopyOptions); err != nil {
			return fmt.Errorf("exporting %s: %w", ref, err)
		}
	}
	return tarDir(tmp, w)
}

// Load imports every tagged reference from a tar'd OCI image layout into
// the local store and returns the imported refs.
func Load(ctx context.Context, st *store.Store, r io.Reader) ([]string, error) {
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
