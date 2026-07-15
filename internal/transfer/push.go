// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package transfer

import (
	"context"
	"fmt"
	"io"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	oras "oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry"

	"github.com/aimd54/palan/internal/store"
)

// Push uploads the locally-stored ref to its registry. Blobs the registry
// already has are skipped; where the registry supports cross-repository
// blob mounting, blobs known from sibling repositories mount server-side
// instead of re-uploading.
func (c *Client) Push(ctx context.Context, st *store.Store, ref registry.Reference, ev Events) (ocispec.Descriptor, error) {
	repo, err := c.Repository(ref)
	if err != nil {
		return ocispec.Descriptor{}, err
	}

	local := ref.String()
	if _, err := st.Resolve(ctx, local); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("%q is not in the local store (see `palan ls`): %w", local, err)
	}

	copyOpts := oras.CopyOptions{
		CopyGraphOptions: oras.CopyGraphOptions{
			Concurrency: c.concurrency(),
			MountFrom: func(_ context.Context, _ ocispec.Descriptor) ([]string, error) {
				return mountCandidates(ctx, st, ref)
			},
			OnCopySkipped: func(_ context.Context, desc ocispec.Descriptor) error {
				ev.blobSkip(desc)
				return nil
			},
		},
	}

	src := &fetchCounter{ReadOnlyTarget: st.OCI(), ev: ev}
	desc, err := oras.Copy(ctx, src, local, repo, ref.Reference, copyOpts)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("pushing %s: %w", ref, err)
	}
	return desc, nil
}

// mountCandidates lists other repositories on the same registry present in
// the local store — likely blob sources for cross-repo mounting (e.g. two
// quantizations sharing a license layer).
func mountCandidates(ctx context.Context, st *store.Store, ref registry.Reference) ([]string, error) {
	entries, err := st.List(ctx)
	if err != nil {
		return nil, err
	}
	const maxCandidates = 3
	var out []string
	seen := map[string]bool{ref.Repository: true}
	for _, e := range entries {
		r, err := registry.ParseReference(e.Ref)
		if err != nil || r.Registry != ref.Registry || seen[r.Repository] {
			continue
		}
		seen[r.Repository] = true
		out = append(out, r.Repository)
		if len(out) == maxCandidates {
			break
		}
	}
	return out, nil
}

// fetchCounter wraps a copy source so blob reads report byte progress.
type fetchCounter struct {
	oras.ReadOnlyTarget
	ev Events
}

func (p *fetchCounter) Fetch(ctx context.Context, desc ocispec.Descriptor) (io.ReadCloser, error) {
	rc, err := p.ReadOnlyTarget.Fetch(ctx, desc)
	if err != nil || isManifestMediaType(desc.MediaType) {
		return rc, err
	}
	report := p.ev.blobStart(desc, 0)
	if report == nil {
		return rc, nil
	}
	return &countingReadCloser{rc: rc, fn: report}, nil
}

// countingReadCloser reports read byte counts to a progress callback.
type countingReadCloser struct {
	rc io.ReadCloser
	fn func(int64)
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.rc.Read(p)
	if n > 0 {
		c.fn(int64(n))
	}
	return n, err
}

func (c *countingReadCloser) Close() error { return c.rc.Close() }
