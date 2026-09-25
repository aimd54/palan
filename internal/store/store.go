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
	"io"
	"os"
	"path/filepath"
	"strings"
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
	s, err := newStore(root)
	if err != nil {
		return nil, err
	}
	if s.oci, err = openLayout(ctx, s.root); err != nil {
		return nil, err
	}
	return s, nil
}

// OpenShared opens the store at root under a shared lock, held until release
// is called, and reads the layout only once the lock is held.
//
// Open reads the layout at once and a lock taken afterwards reads it again,
// so the first read is made with no lock, and a save in progress elsewhere
// can be caught halfway. A caller that is going to lock anyway loses nothing
// by reading once, after it has.
func OpenShared(ctx context.Context, root string) (*Store, func(), error) {
	s, err := newStore(root)
	if err != nil {
		return nil, nil, err
	}
	release, err := s.RLock(ctx)
	if err != nil {
		return nil, nil, err
	}
	return s, release, nil
}

// newStore resolves root and creates it if necessary, without reading the
// layout inside it.
func newStore(root string) (*Store, error) {
	if root == "" {
		var err error
		if root, err = DefaultRoot(); err != nil {
			return nil, err
		}
	}
	if err := os.MkdirAll(root, 0o750); err != nil {
		return nil, fmt.Errorf("creating store root: %w", err)
	}
	return &Store{root: root, lk: flock.New(filepath.Join(root, ".palan.lock"))}, nil
}

// Bounds on waiting out an index.json caught halfway through a save.
const (
	indexReadAttempts = 10
	indexReadBackoff  = 25 * time.Millisecond
)

// openLayout reads the OCI layout at root into memory.
//
// The layout library saves index.json by truncating the file and writing it
// again, so a reader holding no lock can find it empty, cut short, or
// holding the start of one save and the end of the next. That lasts as long
// as one write, so a read that fails to decode is retried briefly, and an
// index still unreadable after that is reported as broken.
func openLayout(ctx context.Context, root string) (*oci.Store, error) {
	var ociStore *oci.Store
	var err error
	for attempt := 1; ; attempt++ {
		if ociStore, err = oci.NewWithContext(ctx, root); err == nil {
			break
		}
		if !caughtMidSave(err) || attempt == indexReadAttempts {
			return nil, fmt.Errorf("opening OCI layout at %s: %w", root, err)
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("opening OCI layout at %s: %w", root, err)
		case <-time.After(indexReadBackoff):
		}
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

// caughtMidSave reports whether err is what decoding a JSON file partway
// through being rewritten produces: nothing, a document cut short, or the
// start of one save joined to the end of another.
func caughtMidSave(err error) bool {
	var syntax *json.SyntaxError
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.As(err, &syntax)
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

// Remove unlinks a reference, and content stays until GC reclaims it. The
// manifest of a signature, attestation, Sigstore bundle or bill of materials
// is deleted as well, and its blobs go at the next collection.
func (s *Store) Remove(ctx context.Context, ref string) error {
	// Read before untagging: a referrer is addressed by the tag about to
	// go, and what it is can only be answered while the tag still answers.
	// A reference that cannot be read is untagged anyway, because removal
	// is not the place to insist on interpreting content.
	var referrer *ocispec.Descriptor
	if desc, err := s.oci.Resolve(ctx, ref); err == nil {
		if h, herr := s.readHead(ctx, desc); herr == nil && h.subject != nil && describesOnly(h.artifactType) {
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
	// Left untagged, a description would stay as long as its subject, with
	// nothing to name it by. Anything else is only untagged, since deleting
	// a manifest removes every other tag on it.
	if err := s.oci.Delete(ctx, *referrer); err != nil && !errors.Is(err, errdef.ErrNotFound) {
		return fmt.Errorf("removing referrer %q: %w", ref, err)
	}
	return nil
}

// GC removes all blobs not reachable from a tagged manifest, plus any
// leftover partial downloads in the ingest directory. GC callers hold the
// exclusive lock, so no in-flight pull can lose its partials to GC.
//
// Signatures and attestations whose model is gone are unlinked first. Each
// names its model as its subject, which keeps the model reachable, so one
// left behind would hold the whole model on disk and GC would report
// success having reclaimed nothing.
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

// unlinkOrphanedReferrers removes each description no tagged artifact
// reaches, and removes or forgets each untagged entry whose subject the
// collector cannot place. A manifest that cannot be read is left alone.
func (s *Store) unlinkOrphanedReferrers(ctx context.Context) error {
	// Two passes, because two different questions are being asked and only
	// one of them is the collector's.
	//
	// The first is this store's own policy: a signature whose model has
	// been removed is not worth keeping, and while its tag stands it holds
	// the model's blobs on disk, so collection would report success having
	// reclaimed nothing. The collector would keep it, because it is tagged.
	// Reachability here is therefore measured from tagged artifacts only,
	// meaning every tagged manifest except those whose type says they only
	// describe another.
	if err := s.unlinkOrphanedTagged(ctx); err != nil {
		return err
	}
	// The second is the collector's question, asked of what is left, since a
	// subject it cannot place makes it read the same manifest forever.
	return s.deleteUnreachableUntagged(ctx)
}

// entry is one manifest the layout records, with what it is named and what
// it describes. describes is set for an entry whose subject is its only
// reason to exist, a signature or an attestation.
type entry struct {
	desc      ocispec.Descriptor
	ref       string
	subject   *ocispec.Descriptor
	describes bool
}

// readIndex classifies every manifest the layout records. A manifest whose
// subject cannot be read is recorded as naming none.
func (s *Store) readIndex(ctx context.Context) ([]entry, error) {
	all, err := s.indexManifests()
	if err != nil {
		return nil, err
	}
	entries := make([]entry, 0, len(all))
	for _, desc := range all {
		h, serr := s.readHead(ctx, desc)
		if serr != nil {
			// Recorded with no subject rather than dropped. Both passes
			// only ever remove an entry that names one, so this is never
			// deleted, and leaving it out entirely stopped it anchoring
			// anything: a tagged artifact whose manifest would not read
			// ceased to be a root, and everything attached to it looked
			// orphaned.
			h = head{}
		}
		subject := h.subject
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
		entries = append(entries, entry{
			desc:      desc,
			ref:       ref,
			subject:   subject,
			describes: subject != nil && describesOnly(h.artifactType),
		})
	}
	return entries, nil
}

// unlinkOrphanedTagged removes a tagged signature or attestation that no
// tagged artifact reaches, so the blobs it was holding can be collected.
//
// Every other tagged entry is a root, including one that records a subject,
// such as a model derived from another.
func (s *Store) unlinkOrphanedTagged(ctx context.Context) error {
	entries, err := s.readIndex(ctx)
	if err != nil {
		return err
	}
	var roots []ocispec.Descriptor
	for _, e := range entries {
		if e.ref != "" && !e.describes {
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
		if e.ref == "" || !e.describes || admitted[e.desc.Digest] {
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

// deleteUnreachableUntagged removes each untagged entry whose subject is out
// of the tagged graph, the collector's own test, unless something kept names
// it; then only its index entry goes, so the collector does not spin on it.
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
	// What the collector keeps: the tagged graph, and untagged referrers of
	// it with what they name.
	kept := make(map[digest.Digest]bool, len(reachable))
	for d := range reachable {
		kept[d] = true
	}
	for _, e := range entries {
		if e.ref != "" || e.subject == nil || !reachable[e.subject.Digest] {
			continue
		}
		under, cerr := s.successorClosure(ctx, []ocispec.Descriptor{e.desc})
		if cerr != nil {
			return cerr
		}
		for d := range under {
			kept[d] = true
		}
	}
	var forget []digest.Digest
	for _, e := range entries {
		if e.ref != "" || e.subject == nil {
			continue
		}
		switch {
		case reachable[e.subject.Digest]:
			continue
		case kept[e.desc.Digest]:
			forget = append(forget, e.desc.Digest)
			continue
		}
		if err := s.oci.Delete(ctx, e.desc); err != nil && !errors.Is(err, errdef.ErrNotFound) {
			return fmt.Errorf("removing unreachable referrer %s: %w", e.desc.Digest, err)
		}
	}
	return s.forgetUntagged(ctx, forget)
}

// forgetUntagged removes the untagged index entries naming ds and keeps their
// blobs, then reads the layout again.
func (s *Store) forgetUntagged(ctx context.Context, ds []digest.Digest) error {
	if len(ds) == 0 {
		return nil
	}
	drop := make(map[digest.Digest]bool, len(ds))
	for _, d := range ds {
		drop[d] = true
	}
	path := filepath.Join(s.root, "index.json")
	raw, err := os.ReadFile(path) // #nosec G304 -- the store's own layout file
	if err != nil {
		return fmt.Errorf("reading the store index: %w", err)
	}
	var index ocispec.Index
	if err := json.Unmarshal(raw, &index); err != nil {
		return fmt.Errorf("decoding the store index: %w", err)
	}
	kept := index.Manifests[:0]
	for _, m := range index.Manifests {
		name := m.Annotations[ocispec.AnnotationRefName]
		if drop[m.Digest] && (name == "" || name == m.Digest.String()) {
			continue
		}
		kept = append(kept, m)
	}
	index.Manifests = kept
	out, err := json.Marshal(index)
	if err != nil {
		return err
	}
	// Written beside the index and renamed over it, so a reader holding no
	// lock sees one index or the other.
	if err := replaceFile(path, out); err != nil {
		return fmt.Errorf("saving the store index: %w", err)
	}
	return s.reload(ctx)
}

// replaceFile writes data to path through a synced file renamed over it.
func replaceFile(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644) // #nosec G302 G304 -- the layout's index is world-readable, as oras-go writes it
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if serr := f.Sync(); err == nil {
		err = serr
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
	}
	return err
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
	// Keyed as the collector keys its walk, so a digest named once as a
	// blob and once as a manifest is still read as the manifest.
	type visit struct {
		mediaType string
		digest    digest.Digest
		size      int64
	}
	visited := make(map[visit]bool, len(roots))
	queue := append([]ocispec.Descriptor(nil), roots...)
	for len(queue) > 0 {
		node := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		key := visit{node.MediaType, node.Digest, node.Size}
		if visited[key] {
			continue
		}
		visited[key] = true
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

// head is what collection needs from a manifest: the subject it names, and
// the type of artifact it is.
type head struct {
	subject      *ocispec.Descriptor
	artifactType string
}

// readHead reads a manifest's subject and artifact type, the latter from the
// config's media type when the manifest states none. It reads as the
// collector does, with no size bound, the same media types and the digest
// checked first, so the two never disagree about which manifests name a
// subject.
func (s *Store) readHead(ctx context.Context, desc ocispec.Descriptor) (head, error) {
	switch desc.MediaType {
	case ocispec.MediaTypeImageManifest, ocispec.MediaTypeImageIndex, mediaTypeArtifactManifest:
	default:
		return head{}, nil
	}
	raw, err := content.FetchAll(ctx, s.oci, desc)
	if err != nil {
		return head{}, err
	}
	var manifest struct {
		ArtifactType string              `json:"artifactType,omitempty"`
		Config       *ocispec.Descriptor `json:"config,omitempty"`
		Subject      *ocispec.Descriptor `json:"subject,omitempty"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return head{}, fmt.Errorf("reading the subject of %s: %w", desc.Digest, err)
	}
	h := head{subject: manifest.Subject, artifactType: manifest.ArtifactType}
	if h.artifactType == "" && manifest.Config != nil {
		h.artifactType = manifest.Config.MediaType
	}
	return h, nil
}

// describingTypes are the artifact types of manifests that exist only to say
// something about their subject: signatures, attestations and bills of
// materials. Two families are matched by prefix below.
var describingTypes = map[string]bool{
	"application/vnd.dev.cosign.simplesigning.v1+json": true, // the signature payload's own type
	"application/vnd.cncf.notary.signature":            true, // Notation signatures
	"application/vnd.dsse.envelope.v1+json":            true, // cosign and palan attestations
	"application/vnd.in-toto+json":                     true, // in-toto statements
	"application/spdx+json":                            true,
	"application/vnd.cyclonedx+json":                   true,
}

// describingPrefixes begin families of describing types: every version of
// the Sigstore bundle, and cosign's signatures, attestations and bills of
// materials, which palan's signatures share.
var describingPrefixes = []string{
	"application/vnd.dev.sigstore.bundle",
	"application/vnd.dev.cosign.artifact.",
}

// describesOnly reports whether an artifact of this type exists only to
// describe its subject. A type not listed is taken for content, since keeping
// an unfamiliar signature costs the space it holds and deleting an
// unfamiliar model costs the model.
func describesOnly(artifactType string) bool {
	if describingTypes[artifactType] {
		return true
	}
	for _, p := range describingPrefixes {
		if strings.HasPrefix(artifactType, p) {
			return true
		}
	}
	return false
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
