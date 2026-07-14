// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package transfer

import (
	"context"
	"fmt"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sync/errgroup"
	oras "oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry"

	"github.com/aimd54/palan/internal/store"
)

// Events carries optional progress callbacks. All fields may be nil.
// Callbacks must be safe for concurrent use: blobs transfer in parallel.
type Events struct {
	// OnBlobStart announces a starting blob transfer. resumeOffset > 0 means
	// a partial download is being continued from that byte offset. The
	// returned function (may be nil) receives byte-count deltas as the blob
	// streams.
	OnBlobStart func(desc ocispec.Descriptor, resumeOffset int64) func(delta int64)
	// OnBlobSkip reports content skipped because the destination has it.
	OnBlobSkip func(desc ocispec.Descriptor)
}

func (e Events) blobStart(desc ocispec.Descriptor, resumeOffset int64) func(int64) {
	if e.OnBlobStart == nil {
		return nil
	}
	return e.OnBlobStart(desc, resumeOffset)
}

func (e Events) blobSkip(desc ocispec.Descriptor) {
	if e.OnBlobSkip != nil {
		e.OnBlobSkip(desc)
	}
}

// Pull fetches ref from its registry into the local store and tags it with
// the fully-qualified reference. Large leaf blobs download concurrently with
// cross-restart resume; manifests, config, and tagging go through oras.Copy,
// which skips everything already present.
func (c *Client) Pull(ctx context.Context, st *store.Store, ref registry.Reference, ev Events) (ocispec.Descriptor, error) {
	repo, err := c.Repository(ref)
	if err != nil {
		return ocispec.Descriptor{}, err
	}

	root, err := repo.Resolve(ctx, ref.Reference)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("resolving %s: %w", ref, err)
	}

	leaves, err := collectLeafBlobs(ctx, repo, root)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("walking manifest graph for %s: %w", ref, err)
	}

	ingest, err := st.IngestDir()
	if err != nil {
		return ocispec.Descriptor{}, err
	}

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(c.concurrency())
	for _, desc := range leaves {
		g.Go(func() error {
			exists, err := st.OCI().Exists(gctx, desc)
			if err != nil {
				return err
			}
			if exists {
				ev.blobSkip(desc)
				return nil
			}
			return c.downloadBlob(gctx, repo, ref, desc, st, ingest, ev)
		})
	}
	if err := g.Wait(); err != nil {
		return ocispec.Descriptor{}, err
	}

	copyOpts := oras.CopyOptions{
		CopyGraphOptions: oras.CopyGraphOptions{Concurrency: c.concurrency()},
	}
	desc, err := oras.Copy(ctx, repo, ref.Reference, st.OCI(), ref.String(), copyOpts)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("copying %s into local store: %w", ref, err)
	}
	return desc, nil
}

// manifestMediaTypes are the media types treated as graph-interior nodes.
func isManifestMediaType(mt string) bool {
	switch mt {
	case ocispec.MediaTypeImageManifest,
		ocispec.MediaTypeImageIndex,
		"application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.docker.distribution.manifest.list.v2+json":
		return true
	}
	return false
}

// collectLeafBlobs walks the manifest graph breadth-first and returns the
// non-manifest descriptors (config plus layers).
func collectLeafBlobs(ctx context.Context, fetcher content.Fetcher, root ocispec.Descriptor) ([]ocispec.Descriptor, error) {
	var leaves []ocispec.Descriptor
	seen := map[string]bool{}
	queue := []ocispec.Descriptor{root}
	for len(queue) > 0 {
		d := queue[0]
		queue = queue[1:]
		if seen[d.Digest.String()] {
			continue
		}
		seen[d.Digest.String()] = true
		if !isManifestMediaType(d.MediaType) {
			leaves = append(leaves, d)
			continue
		}
		succ, err := content.Successors(ctx, fetcher, d)
		if err != nil {
			return nil, err
		}
		queue = append(queue, succ...)
	}
	return leaves, nil
}
