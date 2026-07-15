// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

// Package store implements palan's local model store.
//
// The store is a standard OCI image layout (oci-layout, index.json,
// blobs/<alg>/<hex>) managed through oras-go's oci.Store, so any OCI tool
// can read it directly — `oras cp --from-oci-layout` included. Weight layers
// are raw GGUF bytes, which means the blob path returned by BlobPath is the
// exact file llama-server mmaps: zero copies between "pulled" and
// "servable" (see docs/architecture.md, "Client and local store").
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/errdef"
)

// EnvHome overrides the store location when set.
const EnvHome = "PALAN_HOME"

// maxJSONBlobSize bounds manifests/config blobs we are willing to parse.
// Real ModelPack manifests and configs are a few KiB; anything approaching
// this limit is malformed or hostile.
const maxJSONBlobSize = 4 * 1024 * 1024

// lockRetryInterval is how often lock acquisition retries under contention.
const lockRetryInterval = 100 * time.Millisecond

// Store is the content-addressed local model store.
type Store struct {
	root string
	oci  *oci.Store
	lk   *flock.Flock
}

// DefaultRoot resolves the store directory: $PALAN_HOME, else
// $XDG_DATA_HOME/palan, else ~/.local/share/palan.
func DefaultRoot() (string, error) {
	if v := os.Getenv(EnvHome); v != "" {
		return v, nil
	}
	if v := os.Getenv("XDG_DATA_HOME"); v != "" {
		return filepath.Join(v, "palan"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolving home directory: %w", err)
	}
	return filepath.Join(home, ".local", "share", "palan"), nil
}

// Open opens (creating if necessary) the store at root; an empty root means
// DefaultRoot.
func Open(ctx context.Context, root string) (*Store, error) {
	if root == "" {
		var err error
		if root, err = DefaultRoot(); err != nil {
			return nil, err
		}
	}
	if err := os.MkdirAll(root, 0o750); err != nil {
		return nil, fmt.Errorf("creating store root: %w", err)
	}
	ociStore, err := oci.NewWithContext(ctx, root)
	if err != nil {
		return nil, fmt.Errorf("opening OCI layout at %s: %w", root, err)
	}
	return &Store{
		root: root,
		oci:  ociStore,
		lk:   flock.New(filepath.Join(root, ".palan.lock")),
	}, nil
}

// Root returns the store directory.
func (s *Store) Root() string { return s.root }

// OCI exposes the underlying oras-go store for transfer operations
// (oras.Copy sources/destinations).
func (s *Store) OCI() *oci.Store { return s.oci }

// Lock acquires an exclusive lock for mutating operations (pull, rm, gc,
// pack, load). It blocks until acquired or ctx is done, and returns the
// unlock function.
func (s *Store) Lock(ctx context.Context) (func(), error) {
	ok, err := s.lk.TryLockContext(ctx, lockRetryInterval)
	if err != nil || !ok {
		return nil, fmt.Errorf("acquiring exclusive store lock at %s (another palan process may be running): %w", s.lk.Path(), err)
	}
	return func() { _ = s.lk.Unlock() }, nil
}

// RLock acquires a shared lock for read operations.
func (s *Store) RLock(ctx context.Context) (func(), error) {
	ok, err := s.lk.TryRLockContext(ctx, lockRetryInterval)
	if err != nil || !ok {
		return nil, fmt.Errorf("acquiring shared store lock at %s: %w", s.lk.Path(), err)
	}
	return func() { _ = s.lk.Unlock() }, nil
}

// BlobPath returns the filesystem path of a stored blob, verifying it
// exists. This is the path handed to llama-server for raw weight layers.
func (s *Store) BlobPath(d digest.Digest) (string, error) {
	if err := d.Validate(); err != nil {
		return "", fmt.Errorf("invalid digest %q: %w", d, err)
	}
	p := filepath.Join(s.root, "blobs", d.Algorithm().String(), d.Encoded())
	if _, err := os.Stat(p); err != nil {
		return "", fmt.Errorf("blob %s not in local store: %w", d, err)
	}
	return p, nil
}

// Entry is one tagged reference in the store.
type Entry struct {
	Ref        string
	Descriptor ocispec.Descriptor
}

// List returns all tagged references, in the index's stable order.
func (s *Store) List(ctx context.Context) ([]Entry, error) {
	var entries []Entry
	err := s.oci.Tags(ctx, "", func(tags []string) error {
		for _, t := range tags {
			desc, err := s.oci.Resolve(ctx, t)
			if err != nil {
				return fmt.Errorf("resolving %q: %w", t, err)
			}
			entries = append(entries, Entry{Ref: t, Descriptor: desc})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return entries, nil
}

// Resolve resolves a reference to its descriptor.
func (s *Store) Resolve(ctx context.Context, ref string) (ocispec.Descriptor, error) {
	return s.oci.Resolve(ctx, ref)
}

// Tag associates ref with the given descriptor.
func (s *Store) Tag(ctx context.Context, desc ocispec.Descriptor, ref string) error {
	return s.oci.Tag(ctx, desc, ref)
}

// Remove unlinks a reference. Content stays until GC reclaims it
// (`palan rm` unlinks, `palan gc` reclaims).
func (s *Store) Remove(ctx context.Context, ref string) error {
	if err := s.oci.Untag(ctx, ref); err != nil {
		if errors.Is(err, errdef.ErrNotFound) {
			return fmt.Errorf("reference %q not found in local store: %w", ref, err)
		}
		return err
	}
	return nil
}

// GC removes all blobs not reachable from a tagged manifest, plus any
// leftover partial downloads in the ingest directory. GC callers hold the
// exclusive lock, so no in-flight pull can lose its partials to GC.
func (s *Store) GC(ctx context.Context) error {
	if err := s.oci.GC(ctx); err != nil {
		return err
	}
	ingest := filepath.Join(s.root, "ingest")
	entries, err := os.ReadDir(ingest)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("reading ingest dir: %w", err)
	}
	for _, e := range entries {
		if err := os.Remove(filepath.Join(ingest, e.Name())); err != nil {
			return fmt.Errorf("removing stale partial %s: %w", e.Name(), err)
		}
	}
	return nil
}

// IngestDir returns (creating if needed) the directory holding partial
// blob downloads, keyed by digest so interrupted pulls resume across
// process restarts.
func (s *Store) IngestDir() (string, error) {
	p := filepath.Join(s.root, "ingest")
	if err := os.MkdirAll(p, 0o750); err != nil {
		return "", fmt.Errorf("creating ingest dir: %w", err)
	}
	return p, nil
}

// FetchJSON fetches a JSON blob from any fetcher (local store or remote
// repository) and decodes it into T, enforcing a sanity size bound.
func FetchJSON[T any](ctx context.Context, fetcher content.Fetcher, desc ocispec.Descriptor) (T, error) {
	var zero T
	if desc.Size <= 0 || desc.Size > maxJSONBlobSize {
		return zero, fmt.Errorf("refusing to parse %s blob of size %d (limit %d)", desc.MediaType, desc.Size, maxJSONBlobSize)
	}
	b, err := content.FetchAll(ctx, fetcher, desc)
	if err != nil {
		return zero, fmt.Errorf("fetching %s: %w", desc.Digest, err)
	}
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		return zero, fmt.Errorf("decoding %s blob %s: %w", desc.MediaType, desc.Digest, err)
	}
	return v, nil
}

// FetchManifest fetches and decodes an OCI image manifest.
func FetchManifest(ctx context.Context, fetcher content.Fetcher, desc ocispec.Descriptor) (ocispec.Manifest, error) {
	return FetchJSON[ocispec.Manifest](ctx, fetcher, desc)
}
