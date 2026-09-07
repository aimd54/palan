// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

// Package store implements palan's local model store.
//
// The store is a standard OCI image layout (oci-layout, index.json,
// blobs/<alg>/<hex>) managed through oras-go's oci.Store, so any OCI tool
// can read it directly, `oras cp --from-oci-layout` included. Weight layers
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

// maxWalkedManifestSize bounds a manifest read only to find its subject.
// Larger than the parse bound on purpose: a manifest past that bound still
// takes part in the subject chain collection has to walk, and refusing to
// look at one leaves it behind for the collector to hang on.
const maxWalkedManifestSize = 64 * 1024 * 1024

// mediaTypeArtifactManifest is the OCI 1.1 artifact manifest. oras-go keeps
// its own copy in an internal package, and the collector's subject reader
// accepts it alongside the two image types, so this has to as well or the
// two would disagree about which manifests carry a subject.
const mediaTypeArtifactManifest = "application/vnd.oci.artifact.manifest.v1+json"

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
	// Deleting a manifest deletes that manifest. By default the layout also
	// walks what the delete leaves dangling and removes that too, and a
	// subject is one of the things a manifest names, so removing a
	// signature would take the artifact it describes with it, and removing
	// something attached to a signature would take the signature. Both are
	// content nothing asked to lose. It is also what `palan rm` and
	// `palan gc` are documented to divide between them: unlinking is one
	// command and reclaiming is the other.
	ociStore.AutoGC = false
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
// (`palan rm` unlinks, `palan gc` reclaims). A referrer's manifest is
// deleted rather than merely untagged, for the reason given below, but its
// blobs go the same way as everything else: at the next collection.
func (s *Store) Remove(ctx context.Context, ref string) error {
	// Read before untagging: a referrer is addressed by the tag about to
	// go, and what it is can only be answered while the tag still answers.
	// A reference that cannot be read is untagged anyway, because removal
	// is not the place to insist on interpreting content.
	var referrer *ocispec.Descriptor
	if desc, err := s.oci.Resolve(ctx, ref); err == nil {
		if subject, serr := s.subjectOf(ctx, desc); serr == nil && subject != nil {
			referrer = &desc
		}
	}
	if err := s.oci.Untag(ctx, ref); err != nil {
		if errors.Is(err, errdef.ErrNotFound) {
			return fmt.Errorf("reference %q not found in local store: %w", ref, err)
		}
		return err
	}
	if referrer == nil {
		return nil
	}
	// A referrer is deleted rather than left untagged. It stays in the
	// referrers index either way, where it still names its subject and so
	// still holds that subject's blobs on disk, and nothing can reach it by
	// name to remove it later: untagging a signature is how one is meant to
	// go away, so leaving the manifest behind removes the handle and keeps
	// the object. It also strands collection outright, because oras-go
	// v2.6.2 walks the subject chain of an untagged manifest without
	// advancing and never returns.
	if err := s.oci.Delete(ctx, *referrer); err != nil && !errors.Is(err, errdef.ErrNotFound) {
		return fmt.Errorf("removing referrer %q: %w", ref, err)
	}
	return nil
}

// GC removes all blobs not reachable from a tagged manifest, plus any
// leftover partial downloads in the ingest directory. GC callers hold the
// exclusive lock, so no in-flight pull can lose its partials to GC.
//
// Orphaned referrers are unlinked first. A referrer names its subject, so it
// keeps that subject and everything under it reachable; a signature left
// behind by a removed model would hold the whole model on disk and GC would
// report success having reclaimed nothing.
func (s *Store) GC(ctx context.Context) error {
	if err := s.unlinkOrphanedReferrers(ctx); err != nil {
		return err
	}
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

// unlinkOrphanedReferrers untags every referrer whose subject is no longer a
// tagged artifact in its own right.
//
// A referrer is any tagged manifest carrying a subject, which in this store
// means a signature. Because the subject is a successor, the referrer's tag
// keeps the artifact it describes alive, so removing a model without removing
// its signature leaves the model's weights pinned. Sweeping here rather than
// in `rm` covers the cases `rm` cannot reach: a signature imported without its
// model, and a model unlinked by any path that did not know to look for one.
//
// A manifest that cannot be read is left alone. GC reclaims storage; it is not
// the place to act on content it cannot interpret.
func (s *Store) unlinkOrphanedReferrers(ctx context.Context) error {
	all, err := s.indexManifests()
	if err != nil {
		return err
	}

	named := make(map[digest.Digest][]string, len(all))
	var roots []ocispec.Descriptor
	type attached struct {
		desc    ocispec.Descriptor
		subject ocispec.Descriptor
	}
	var candidates []attached
	for _, desc := range all {
		ref := desc.Annotations[ocispec.AnnotationRefName]
		if ref != "" {
			named[desc.Digest] = append(named[desc.Digest], ref)
		}
		subject, serr := s.subjectOf(ctx, desc)
		if serr != nil {
			// Nothing was established about it either way, and a manifest
			// this cannot read is one the collector cannot read either, so
			// it fails rather than looping. Collection reclaims storage; it
			// is not the place to act on content it could not interpret.
			continue
		}
		if subject == nil {
			// An artifact in its own right, and a root of what is reachable
			// only when a tag names it.
			if ref != "" {
				roots = append(roots, desc)
			}
			continue
		}
		candidates = append(candidates, attached{desc: desc, subject: *subject})
	}

	reachable, err := s.successorClosure(ctx, roots)
	if err != nil {
		return err
	}

	for _, c := range candidates {
		if reachable[c.subject.Digest] {
			continue
		}
		for _, ref := range named[c.desc.Digest] {
			if err := s.oci.Untag(ctx, ref); err != nil && !errors.Is(err, errdef.ErrNotFound) {
				return fmt.Errorf("unlinking orphaned referrer %q: %w", ref, err)
			}
		}
		if err := s.oci.Delete(ctx, c.desc); err != nil && !errors.Is(err, errdef.ErrNotFound) {
			return fmt.Errorf("removing orphaned referrer %s: %w", c.desc.Digest, err)
		}
	}
	return nil
}

// successorClosure returns every digest reachable from roots by following
// what each manifest names: its config, its layers, an index's children, and
// the subject of anything carrying one.
//
// This is the set the collector decides against. It builds the same closure
// from every tagged descriptor and then asks, for each untagged manifest
// carrying a subject, whether that subject is in it. Answering with the list
// of tags instead would call a signature on a tagged index's child an
// orphan, because the child is reachable without being tagged, and delete a
// signature the collector would have kept.
//
// A node the store does not hold contributes itself and nothing under it: it
// is not there to expand, and being absent is exactly what makes whatever
// named it unreachable.
func (s *Store) successorClosure(
	ctx context.Context, roots []ocispec.Descriptor,
) (map[digest.Digest]bool, error) {
	reachable := make(map[digest.Digest]bool, len(roots))
	queue := append([]ocispec.Descriptor(nil), roots...)
	for len(queue) > 0 {
		node := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if reachable[node.Digest] {
			continue
		}
		reachable[node.Digest] = true
		successors, err := content.Successors(ctx, s.oci, node)
		switch {
		case errors.Is(err, errdef.ErrNotFound) || errors.Is(err, os.ErrNotExist):
			continue
		case err != nil:
			return nil, fmt.Errorf("walking what %s names: %w", node.Digest, err)
		}
		queue = append(queue, successors...)
	}
	return reachable, nil
}

// subjectOf reads the subject a manifest names, and nothing else.
//
// Deciding what is still attached to a live artifact is not the same as
// parsing a manifest in order to act on its contents, so this does not
// share the bound that protects the latter. A manifest too large for that
// bound still names a subject, and skipping it here would leave behind
// exactly the referrer the collector then spins on: the guard would once
// again exclude the broken case. It is still bounded, because the point of
// a bound is not to read something arbitrary into memory.
//
// Otherwise it answers exactly as the collector's own reader does: the same
// media types carry a subject, the bytes are verified against the digest
// before they are decoded, and trailing data after the document is an error
// rather than something to read past. Disagreeing on any of those would
// mean deciding to keep a manifest the collector will then refuse.
func (s *Store) subjectOf(ctx context.Context, desc ocispec.Descriptor) (*ocispec.Descriptor, error) {
	switch desc.MediaType {
	case ocispec.MediaTypeImageManifest, ocispec.MediaTypeImageIndex, mediaTypeArtifactManifest:
	default:
		return nil, nil
	}
	if desc.Size <= 0 || desc.Size > maxWalkedManifestSize {
		return nil, fmt.Errorf("refusing to walk a %s manifest of size %d (limit %d)",
			desc.MediaType, desc.Size, maxWalkedManifestSize)
	}
	raw, err := content.FetchAll(ctx, s.oci, desc)
	if err != nil {
		return nil, err
	}
	var manifest struct {
		Subject *ocispec.Descriptor `json:"subject,omitempty"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("reading the subject of %s: %w", desc.Digest, err)
	}
	return manifest.Subject, nil
}

// indexManifests reads the manifests the OCI layout records, tagged or not.
//
// Read from index.json rather than asked of the store, which answers with
// tags and so cannot describe a manifest that has lost its own. The file is
// what the image-layout spec defines and what this store already writes, so
// reading it is reading the store's own record rather than guessing at it.
func (s *Store) indexManifests() ([]ocispec.Descriptor, error) {
	raw, err := os.ReadFile(filepath.Join(s.root, "index.json")) // #nosec G304 -- the store's own layout file
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading the store index: %w", err)
	}
	var index ocispec.Index
	if err := json.Unmarshal(raw, &index); err != nil {
		return nil, fmt.Errorf("decoding the store index: %w", err)
	}
	return index.Manifests, nil
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
