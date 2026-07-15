// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package transfer

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/aimd54/palan/internal/store"
)

// downloadAttempts bounds retries per blob; partials persist between
// attempts, so each retry resumes rather than restarts.
const downloadAttempts = 3

// downloadBlob fetches one blob into the store with resume support. The
// partial file is keyed by digest under the store's ingest directory, so a
// killed process resumes where it stopped (HTTP Range).
func (c *Client) downloadBlob(ctx context.Context, repo *remote.Repository, ref registry.Reference, desc ocispec.Descriptor, st *store.Store, ingestDir string, ev Events) error {
	if desc.Digest.Algorithm() != digest.SHA256 {
		// Rare algorithm: fall back to a plain verified fetch (no resume).
		return c.fetchWholeBlob(ctx, repo, desc, st, ev)
	}
	partial := filepath.Join(ingestDir, desc.Digest.Algorithm().String()+"-"+desc.Digest.Encoded())

	var lastErr error
	for attempt := range downloadAttempts {
		err := c.tryDownload(ctx, repo, ref, desc, partial, st, ev)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return err
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(attempt+1) * 500 * time.Millisecond):
		}
	}
	return fmt.Errorf("downloading blob %s after %d attempts: %w", desc.Digest, downloadAttempts, lastErr)
}

// tryDownload performs one download attempt, resuming from an existing
// partial when the registry honors Range requests.
func (c *Client) tryDownload(ctx context.Context, repo *remote.Repository, ref registry.Reference, desc ocispec.Descriptor, partial string, st *store.Store, ev Events) (retErr error) {
	offset, hasher, err := rehashPartial(partial, desc.Size)
	if err != nil {
		return err
	}
	if offset == desc.Size {
		// A previous attempt fetched everything but died before install.
		return c.installPartial(ctx, st, desc, partial, hasher)
	}

	url := fmt.Sprintf("%s://%s/v2/%s/blobs/%s", c.scheme(), ref.Registry, ref.Repository, desc.Digest)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if offset > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	}

	resp, err := repo.Client.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil && retErr == nil {
			retErr = err
		}
	}()

	appendMode := false
	switch resp.StatusCode {
	case http.StatusOK:
		// Registry ignored the Range request: start over.
		offset = 0
		hasher = sha256.New()
	case http.StatusPartialContent:
		appendMode = true
	case http.StatusRequestedRangeNotSatisfiable:
		_ = os.Remove(partial)
		return fmt.Errorf("registry rejected resume of %s at offset %d; partial discarded", desc.Digest, offset)
	default:
		return fmt.Errorf("GET %s: unexpected status %q", url, resp.Status)
	}

	flags := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	if appendMode {
		flags = os.O_CREATE | os.O_WRONLY | os.O_APPEND
	}
	f, err := os.OpenFile(partial, flags, 0o600) // #nosec G304 -- path is digest-derived inside the store's ingest dir
	if err != nil {
		return err
	}

	report := ev.blobStart(desc, offset)
	_, copyErr := io.Copy(io.MultiWriter(f, hasher, countingWriter{report}), resp.Body)
	if err := f.Close(); err != nil && copyErr == nil {
		copyErr = err
	}
	if copyErr != nil {
		// Keep the partial: the next attempt resumes from here.
		return fmt.Errorf("streaming %s: %w", desc.Digest, copyErr)
	}

	fi, err := os.Stat(partial)
	if err != nil {
		return err
	}
	if fi.Size() != desc.Size {
		if fi.Size() > desc.Size {
			_ = os.Remove(partial)
		}
		return fmt.Errorf("blob %s: got %d bytes, want %d", desc.Digest, fi.Size(), desc.Size)
	}
	return c.installPartial(ctx, st, desc, partial, hasher)
}

// rehashPartial replays an existing partial file through SHA-256 so the
// digest check covers resumed bytes too. A corrupt or oversized partial is
// discarded.
func rehashPartial(partial string, expectedSize int64) (int64, hash.Hash, error) {
	hasher := sha256.New()
	f, err := os.Open(partial) // #nosec G304 -- digest-derived path in the ingest dir
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, hasher, nil
		}
		return 0, nil, err
	}
	n, err := io.Copy(hasher, f)
	_ = f.Close()
	if err != nil || n > expectedSize {
		_ = os.Remove(partial)
		return 0, sha256.New(), nil
	}
	return n, hasher, nil
}

// installPartial verifies the completed partial against the expected digest
// and moves it into the content store.
func (c *Client) installPartial(ctx context.Context, st *store.Store, desc ocispec.Descriptor, partial string, hasher hash.Hash) error {
	got := digest.NewDigest(digest.SHA256, hasher)
	if got != desc.Digest {
		_ = os.Remove(partial)
		return fmt.Errorf("digest mismatch for %s: downloaded content hashes to %s (partial discarded)", desc.Digest, got)
	}
	f, err := os.Open(partial) // #nosec G304 -- digest-derived path in the ingest dir
	if err != nil {
		return err
	}
	err = st.OCI().Push(ctx, desc, f)
	_ = f.Close()
	if err != nil && !errors.Is(err, errdef.ErrAlreadyExists) {
		return fmt.Errorf("installing blob %s: %w", desc.Digest, err)
	}
	return os.Remove(partial)
}

// fetchWholeBlob is the no-resume path for non-SHA-256 digests: oras-go
// verifies the digest during Push.
func (c *Client) fetchWholeBlob(ctx context.Context, repo *remote.Repository, desc ocispec.Descriptor, st *store.Store, ev Events) error {
	rc, err := repo.Blobs().Fetch(ctx, desc)
	if err != nil {
		return err
	}
	defer func() { _ = rc.Close() }()
	report := ev.blobStart(desc, 0)
	err = st.OCI().Push(ctx, desc, io.TeeReader(rc, countingWriter{report}))
	if err != nil && !errors.Is(err, errdef.ErrAlreadyExists) {
		return err
	}
	return nil
}

// countingWriter forwards byte counts to a progress callback; the zero
// value (nil fn) discards.
type countingWriter struct{ fn func(int64) }

func (w countingWriter) Write(p []byte) (int, error) {
	if w.fn != nil {
		w.fn(int64(len(p)))
	}
	return len(p), nil
}
