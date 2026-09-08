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
	ociStore, err := openLayout(ctx, root)
	if err != nil {
		return nil, err
	}
	return &Store{
		root: root,
		oci:  ociStore,
		lk:   flock.New(filepath.Join(root, ".palan.lock")),
	}, nil
}

// openLayout reads the OCI layout at root into memory.
func openLayout(ctx context.Context, root string) (*oci.Store, error) {
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
	return ociStore, nil
}

// reload re-reads the layout, and is called once a lock is held.
//
// Opening a store reads what the layout holds; the lock is what makes that
// answer stay true. Everything written between the two is invisible to
// whoever opened first, and a collector that waited behind a pull walked a
// view from before it, found the arriving model's blobs unreferenced and
// removed them. Both commands reported success.
//
// Re-reading here rather than at each caller because the property wanted is
// that holding the lock and holding a stale view cannot happen together,
// and a rule kept in twelve places is a rule somebody adds a thirteenth
// place without.
func (s *Store) reload(ctx context.Context) error {
	ociStore, err := openLayout(ctx, s.root)
	if err != nil {
		return err
	}
	s.oci = ociStore
	return nil
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
	if err := s.reload(ctx); err != nil {
		// Released, or the lock outlives the command that took it and
		// every later one waits on a holder that has gone.
		_ = s.lk.Unlock()
		return nil, err
	}
	return func() { _ = s.lk.Unlock() }, nil
}

// RLock acquires a shared lock for read operations.
func (s *Store) RLock(ctx context.Context) (func(), error) {
	ok, err := s.lk.TryRLockContext(ctx, lockRetryInterval)
	if err != nil || !ok {
		return nil, fmt.Errorf("acquiring shared store lock at %s: %w", s.lk.Path(), err)
	}
	if err := s.reload(ctx); err != nil {
		_ = s.lk.Unlock()
		return nil, err
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
	if err := s.dropIndexEntriesWithoutBlobs(ctx); err != nil {
		return err
	}
	if err := s.unlinkOrphanedReferrers(ctx); err != nil {
		return err
	}
	// Collection rebuilds the layout's own view and does not write it back,
	// so index.json is left naming manifests whose blobs it just removed.
	// The next process reads that index, tries to fetch what it names, and
	// refuses to collect anything ever again. Saving it is what makes a
	// second run possible, and it is saved whether or not collection
	// finished: the view is rebuilt before the blobs are swept, so a sweep
	// that stops halfway has already made the old index wrong.
	gcErr := s.oci.GC(ctx)
	if err := s.oci.SaveIndex(); err != nil && gcErr == nil {
		gcErr = fmt.Errorf("saving the store index after collection: %w", err)
	}
	if gcErr != nil {
		return gcErr
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

// dropIndexEntriesWithoutBlobs removes index entries naming a manifest the
// layout no longer holds.
//
// This is the repair for a collection that did not finish. The view is
// rebuilt before the blobs are swept, so a sweep interrupted partway leaves
// index.json naming manifests whose blobs are gone, and every later process
// fails reloading it before it can do anything about it. Running first means
// the command that would repair the store is not the command that refuses
// to start.
func (s *Store) dropIndexEntriesWithoutBlobs(ctx context.Context) error {
	all, err := s.indexManifests()
	if err != nil {
		return err
	}
	for _, desc := range all {
		present, eerr := s.oci.Exists(ctx, desc)
		if eerr != nil || present {
			continue
		}
		switch err := s.oci.Delete(ctx, desc); {
		case err == nil,
			errors.Is(err, errdef.ErrNotFound),
			errors.Is(err, os.ErrNotExist):
		default:
			return fmt.Errorf("dropping the index entry for the missing manifest %s: %w", desc.Digest, err)
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
	// Two passes, because two different questions are being asked and only
	// one of them is the collector's.
	//
	// The first is this store's own policy: a signature whose model has
	// been removed is not worth keeping, and while its tag stands it holds
	// the model's blobs on disk, so collection would report success having
	// reclaimed nothing. The collector would keep it, because it is tagged.
	// Reachability here is therefore measured from tagged artifacts only,
	// meaning tagged manifests that describe something rather than
	// describing another manifest.
	if err := s.unlinkOrphanedTagged(ctx); err != nil {
		return err
	}
	// The second is the collector's question, asked of what is left. It
	// tests one hop, against a graph built from every tagged descriptor,
	// referrers included, and a subject it cannot place makes it read the
	// same manifest forever rather than drop it. So anything untagged whose
	// subject is outside that graph has to go, and anything inside it has
	// to stay: deleting one the collector would have kept is silent content
	// loss, and keeping one it cannot place is the hang.
	return s.deleteUnreachableUntagged(ctx)
}

// entry is one manifest the layout records, with what it is named and what
// it describes.
type entry struct {
	desc    ocispec.Descriptor
	ref     string
	subject *ocispec.Descriptor
}

// readIndex classifies every manifest the layout records. A manifest whose
// subject cannot be read is left out: nothing was established about it, and
// the collector reading it will fail rather than loop.
func (s *Store) readIndex(ctx context.Context) ([]entry, error) {
	all, err := s.indexManifests()
	if err != nil {
		return nil, err
	}
	entries := make([]entry, 0, len(all))
	for _, desc := range all {
		subject, serr := s.subjectOf(ctx, desc)
		if serr != nil {
			// Recorded with no subject rather than dropped. Both passes
			// only ever remove an entry that names one, so this is never
			// deleted, and leaving it out entirely stopped it anchoring
			// anything: a tagged artifact whose manifest would not read
			// ceased to be a root, and everything attached to it looked
			// orphaned.
			subject = nil
		}
		// A reference equal to the digest is how the layout records a
		// manifest with no tag, and it is the collector's own test for
		// one. Reading the annotation as a tag instead treated such an
		// entry as tagged, and untagging it fails with a different error
		// than the one tolerated below, so collection returned that error
		// forever on a store the collector merely hung on: the command
		// that exists to rescue the state refused to run at all.
		ref := desc.Annotations[ocispec.AnnotationRefName]
		if ref == desc.Digest.String() {
			ref = ""
		}
		entries = append(entries, entry{desc: desc, ref: ref, subject: subject})
	}
	return entries, nil
}

// unlinkOrphanedTagged removes a tagged referrer that no tagged artifact
// reaches, so the blobs it was holding can be collected.
func (s *Store) unlinkOrphanedTagged(ctx context.Context) error {
	entries, err := s.readIndex(ctx)
	if err != nil {
		return err
	}
	var roots []ocispec.Descriptor
	for _, e := range entries {
		if e.ref != "" && e.subject == nil {
			roots = append(roots, e.desc)
		}
	}
	reachable, err := s.successorClosure(ctx, roots)
	if err != nil {
		return err
	}
	// A referrer whose subject is alive is alive itself, and so is anything
	// describing it in turn. An attestation over a signature over a model
	// is the ordinary case, and taking one hop from the artifacts would
	// have called it orphaned and deleted it while nothing beneath it had
	// gone anywhere.
	//
	// Untagged referrers take part in this even though only tagged ones are
	// ever removed here. A signature that carries no tag still survives
	// collection when its subject is reachable, so it is a live link in the
	// chain, and skipping it broke the chain there: a tagged attestation
	// over an untagged signature over a tagged model was deleted while the
	// signature under it was kept.
	//
	// Repeated until nothing more is admitted, which is at most once per
	// referrer.
	admitted := make(map[digest.Digest]bool, len(entries))
	for {
		grew := false
		for _, e := range entries {
			if e.subject == nil || admitted[e.desc.Digest] {
				continue
			}
			if !s.staysFor(ctx, e, reachable) {
				continue
			}
			admitted[e.desc.Digest] = true
			grew = true
			under, cerr := s.successorClosure(ctx, []ocispec.Descriptor{e.desc})
			if cerr != nil {
				return cerr
			}
			for d := range under {
				reachable[d] = true
			}
		}
		if !grew {
			break
		}
	}
	for _, e := range entries {
		if e.ref == "" || e.subject == nil || admitted[e.desc.Digest] {
			continue
		}
		switch err := s.oci.Untag(ctx, e.ref); {
		case err == nil, errors.Is(err, errdef.ErrNotFound), errors.Is(err, errdef.ErrInvalidReference):
		default:
			return fmt.Errorf("unlinking orphaned referrer %q: %w", e.ref, err)
		}
		if err := s.oci.Delete(ctx, e.desc); err != nil && !errors.Is(err, errdef.ErrNotFound) {
			return fmt.Errorf("removing orphaned referrer %q: %w", e.ref, err)
		}
	}
	return nil
}

// staysFor reports whether a referrer keeps its place, which is what the
// admission loop grows the reachable set from.
//
// Three reasons, and a referrer admitted for any of them carries what
// describes it in turn, which is why this feeds the loop rather than
// filtering its result: a signature kept for one reason and an attestation
// over it condemned for want of that reason is the same content loss with
// an extra step.
//
// Its subject is reachable, which is the ordinary case. Or it is tagged and
// something reaches it. Or it is tagged and its subject's blob is gone,
// since this pass exists to release the blobs an orphaned signature pins
// and a missing subject pins none, so unlinking would destroy the
// description and reclaim nothing.
//
// The last two are for tagged referrers only. An untagged one over a
// subject nothing reaches is exactly what the collector reads forever.
//
// The middle reason decides more than it looks like it should, because
// being reachable does not mean having been walked. The closure marks a
// digest the moment it is reached, and asks for successors by the media
// type the descriptor claims, so a manifest named as an ordinary blob, or
// one whose digest also appears as some other manifest's layer, is marked
// without ever being read and its subject is never queued. Its subject can
// therefore be present and unreachable at once. The collector keeps such a
// referrer, because a tagged manifest never enters the pass that spins, so
// deleting it is loss with nothing bought.
func (s *Store) staysFor(ctx context.Context, e entry, reachable map[digest.Digest]bool) bool {
	if reachable[e.subject.Digest] {
		return true
	}
	if e.ref == "" {
		return false
	}
	if reachable[e.desc.Digest] {
		return true
	}
	present, err := s.oci.Exists(ctx, *e.subject)
	return err == nil && !present
}

// deleteUnreachableUntagged removes an untagged manifest whose subject is
// outside the graph the collector builds, which is the input it spins on.
// The index is read again, because the pass before this one changed it.
func (s *Store) deleteUnreachableUntagged(ctx context.Context) error {
	entries, err := s.readIndex(ctx)
	if err != nil {
		return err
	}
	var roots []ocispec.Descriptor
	for _, e := range entries {
		if e.ref != "" {
			roots = append(roots, e.desc)
		}
	}
	reachable, err := s.successorClosure(ctx, roots)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.ref != "" || e.subject == nil || reachable[e.subject.Digest] {
			continue
		}
		if err := s.oci.Delete(ctx, e.desc); err != nil && !errors.Is(err, errdef.ErrNotFound) {
			return fmt.Errorf("removing unreachable referrer %s: %w", e.desc.Digest, err)
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
	visited := make(map[digest.Digest]bool, len(roots))
	queue := append([]ocispec.Descriptor(nil), roots...)
	for len(queue) > 0 {
		node := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if visited[node.Digest] {
			continue
		}
		visited[node.Digest] = true
		// Read before recording, and record only on success. The collector
		// builds its graph the same way round: it asks for a node's
		// successors first and returns without adding the node when that
		// fails, so a manifest the layout does not hold is never in the
		// graph. Recording first and discovering the absence afterwards
		// left the digest marked, so a referrer naming it was kept, and a
		// subject the collector cannot find is the thing it reads over and
		// over instead of dropping.
		successors, err := content.Successors(ctx, s.oci, node)
		if err != nil {
			// Absent and unreadable are different answers, and only one of
			// them is a reason to drop what points here.
			//
			// The collector never makes an absent manifest a graph node, and
			// a subject missing from that graph is what it reads over and
			// over, so anything naming one has to go. A manifest that is
			// present but cannot be read makes the collector fail instead,
			// which is safe, so what is attached to it stays: treating the
			// two alike deleted signatures over a model whose blob was
			// briefly unreadable, where the collector would have deleted
			// nothing at all.
			//
			// Not fatal either way. Refusing to collect because one manifest
			// somewhere cannot be read leaves a store nothing can tidy.
			if present, eerr := s.oci.Exists(ctx, node); eerr != nil || !present {
				continue
			}
			reachable[node.Digest] = true
			continue
		}
		reachable[node.Digest] = true
		queue = append(queue, successors...)
	}
	return reachable, nil
}

// subjectOf reads the subject a manifest names, and nothing else.
//
// Deciding what is still attached to a live artifact is not the same as
// parsing a manifest in order to act on its contents, so this does not
// share the bound that protects the latter, and it carries no bound of its
// own either. The collector reads the same manifest with no limit, so any
// size this refused would be a manifest it still reads and this cannot
// see, which is the referrer it then spins on. Refusing to look is not
// caution here; it is the defect.
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
