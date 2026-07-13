// Copyright The moci Authors
// SPDX-License-Identifier: Apache-2.0

package pack

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"

	"github.com/aimd54/moci/internal/store"
)

// carPrefix is the in-image directory holding the model files, following
// the KServe modelcar convention of mounting under /models.
const carPrefix = "models/"

// Car packs the same inputs as an OCI *image* with a single uncompressed
// tar layer (design §7.3): containerd-based image volumes and KServe
// modelcars mount images, not raw artifacts. The tar is deterministic —
// sorted entries, zeroed timestamps, fixed ownership — and uncompressed so
// identical inputs give identical digests.
//
// The image config pins linux/amd64: the payload is architecture-neutral
// data, but image tooling requires a platform.
func Car(ctx context.Context, st *store.Store, files []File, ref string, opts Options) (ocispec.Descriptor, error) {
	ordered, _, err := prepare(files)
	if err != nil {
		return ocispec.Descriptor{}, err
	}

	// Pass 1: stream the tar through a hasher to learn digest and size.
	h := sha256.New()
	counter := &countWriter{w: h}
	if err := writeCarTar(counter, ordered); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("building tar layer: %w", err)
	}
	layerDesc := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageLayer, // uncompressed tar
		Digest:    digest.NewDigest(digest.SHA256, h),
		Size:      counter.n,
	}

	// Pass 2: stream the identical tar into the store.
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(writeCarTar(pw, ordered)) }()
	if err := pushStream(ctx, st, layerDesc, pr); err != nil {
		return ocispec.Descriptor{}, err
	}

	img := ocispec.Image{
		Platform: ocispec.Platform{Architecture: "amd64", OS: "linux"},
		RootFS: ocispec.RootFS{
			Type:    "layers",
			DiffIDs: []digest.Digest{layerDesc.Digest}, // uncompressed: diffID == digest
		},
	}
	cfgBytes, err := json.Marshal(img)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("encoding image config: %w", err)
	}
	cfgDesc := content.NewDescriptorFromBytes(ocispec.MediaTypeImageConfig, cfgBytes)
	if err := pushBytes(ctx, st, cfgDesc, cfgBytes); err != nil {
		return ocispec.Descriptor{}, err
	}

	annotations := map[string]string{}
	if opts.SourceURL != "" {
		annotations[ocispec.AnnotationSource] = opts.SourceURL
	}
	if opts.License != "" {
		annotations[ocispec.AnnotationLicenses] = opts.License
	}

	manifest := ocispec.Manifest{
		MediaType:   ocispec.MediaTypeImageManifest,
		Config:      cfgDesc,
		Layers:      []ocispec.Descriptor{layerDesc},
		Annotations: annotations,
	}
	manifest.SchemaVersion = 2
	return pushManifest(ctx, st, manifest, ref)
}

// writeCarTar writes the deterministic tar stream: a models/ directory
// followed by the files in canonical order.
func writeCarTar(w io.Writer, ordered []File) error {
	tw := tar.NewWriter(w)
	if err := tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeDir,
		Name:     carPrefix,
		Mode:     0o755,
		Format:   tar.FormatUSTAR,
	}); err != nil {
		return err
	}
	for _, f := range ordered {
		fi, err := os.Stat(f.Path)
		if err != nil {
			return err
		}
		if err := tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg,
			Name:     carPrefix + f.Name,
			Mode:     0o644,
			Size:     fi.Size(),
			Format:   tar.FormatUSTAR,
		}); err != nil {
			return err
		}
		fh, err := os.Open(f.Path) // #nosec G304 -- user-supplied input path is the point of pack
		if err != nil {
			return err
		}
		_, err = io.Copy(tw, fh)
		_ = fh.Close()
		if err != nil {
			return fmt.Errorf("archiving %s: %w", f.Path, err)
		}
	}
	return tw.Close()
}

// pushStream installs streaming content under a precomputed descriptor.
func pushStream(ctx context.Context, st *store.Store, desc ocispec.Descriptor, r io.Reader) error {
	if err := st.OCI().Push(ctx, desc, r); err != nil && !isAlreadyExists(err) {
		return fmt.Errorf("storing %s: %w", desc.Digest, err)
	}
	return nil
}

// countWriter counts bytes flowing through to a delegate writer.
type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
