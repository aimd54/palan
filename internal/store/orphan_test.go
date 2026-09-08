// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/errdef"
)

// pushUntaggedReferrer plants a manifest carrying subject and never tags it,
// which is the state an interrupted removal leaves behind and the one a
// listing of tags cannot show.
func pushUntaggedReferrer(t *testing.T, s *Store, subject ocispec.Descriptor, payload string) ocispec.Descriptor {
	t.Helper()
	ctx := context.Background()
	for _, d := range [][]byte{[]byte("{}"), []byte(payload)} {
		desc := content.NewDescriptorFromBytes("application/octet-stream", d)
		if err := s.OCI().Push(ctx, desc, bytes.NewReader(d)); err != nil && !errors.Is(err, errdef.ErrAlreadyExists) {
			t.Fatalf("push blob: %v", err)
		}
	}
	referrer := ocispec.Manifest{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: "application/vnd.dev.cosign.simplesigning.v1+json",
		Config:       content.NewDescriptorFromBytes("application/octet-stream", []byte("{}")),
		Layers:       []ocispec.Descriptor{content.NewDescriptorFromBytes("application/octet-stream", []byte(payload))},
		Subject:      &subject,
	}
	raw, err := json.Marshal(referrer)
	if err != nil {
		t.Fatal(err)
	}
	desc := content.NewDescriptorFromBytes(ocispec.MediaTypeImageManifest, raw)
	if err := s.OCI().Push(ctx, desc, bytes.NewReader(raw)); err != nil {
		t.Fatalf("push referrer: %v", err)
	}
	return desc
}

// TestGCRecoversFromAnUntaggedOrphanedReferrer: removal takes a referrer
// away with its tag, so this state needs an interruption between those two
// steps, a store written by other tooling, or a bundle carrying one. It has
// to be recoverable regardless, because the command that would repair it is
// the one that does not return: an untagged referrer whose subject is gone
// sends oras-go v2.6.2's collection walk round without advancing.
//
// Sweeping the store's references cannot reach it. That is what makes this
// different from the tagged case: the referrer is invisible to a listing of
// tags precisely because it has none.
func TestGCRecoversFromAnUntaggedOrphanedReferrer(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	const ref = "registry.internal/llm/orphan:v1"
	model := pushTestModel(t, s, ref, []byte("weights held by an orphan"))
	orphan := pushUntaggedReferrer(t, s, model, "signature payload")
	if err := s.OCI().Untag(ctx, ref); err != nil {
		t.Fatalf("untag: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- s.GC(ctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("gc: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("gc did not return with an untagged orphaned referrer in the store")
	}

	// Returning is half of it. The orphan has to be gone, and with it the
	// weights it was holding, or collection reported success having
	// reclaimed the thing it exists to reclaim.
	if _, err := s.BlobPath(orphan.Digest); err == nil {
		t.Error("the orphaned referrer survived collection")
	}
	if _, err := s.BlobPath(model.Digest); err == nil {
		t.Error("the model the orphan was holding survived collection")
	}
}

// TestGCKeepsAReferrerWhoseSubjectIsStillTagged is the other half: an
// untagged referrer is ordinary while what it describes is still here, and
// sweeping one away would take a signature off a model somebody still has.
func TestGCKeepsAReferrerWhoseSubjectIsStillTagged(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	const ref = "registry.internal/llm/kept:v1"
	model := pushTestModel(t, s, ref, []byte("weights that stay"))
	referrer := pushUntaggedReferrer(t, s, model, "signature payload")

	if err := s.GC(ctx); err != nil {
		t.Fatalf("gc: %v", err)
	}
	if _, err := s.BlobPath(referrer.Digest); err != nil {
		t.Errorf("collection removed a referrer whose subject is still tagged: %v", err)
	}
	if _, err := s.BlobPath(model.Digest); err != nil {
		t.Errorf("collection removed a tagged model: %v", err)
	}
}

// TestGCRemovesAReferrerOnAnUntaggedReferrer, and keeps the one beneath it.
//
// The collector asks one question of an untagged manifest: is the subject it
// names already in the graph built from the tagged artifacts. It does not
// follow the answer further, and a subject that is not there does not make
// it drop the manifest, it makes it read the same manifest again forever.
// So a referrer describing another referrer is not something to keep: its
// subject is untagged and is not reachable from any tagged artifact, and
// leaving it is leaving the input the collector spins on.
//
// The one beneath it is a different case and has to survive. Its subject is
// the model, the model is tagged, and the collector keeps it. Deleting the
// outer one must not take it along, which is what the layout would do on its
// own by treating a subject as something the delete leaves dangling.
func TestGCRemovesAReferrerOnAnUntaggedReferrer(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	const ref = "registry.internal/llm/chain:v1"
	model := pushTestModel(t, s, ref, []byte("weights at the end of the chain"))
	middle := pushUntaggedReferrer(t, s, model, "a signature over the model")
	outer := pushUntaggedReferrer(t, s, middle, "something describing the signature")

	done := make(chan error, 1)
	go func() { done <- s.GC(ctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("gc: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("gc did not return with a referrer on an untagged referrer")
	}

	if _, err := s.BlobPath(outer.Digest); err == nil {
		t.Error("a referrer whose subject no tagged artifact reaches survived collection")
	}
	if _, err := s.BlobPath(middle.Digest); err != nil {
		t.Errorf("collection took the signature on the model along with it: %v", err)
	}
	if _, err := s.BlobPath(model.Digest); err != nil {
		t.Errorf("collection removed a tagged model: %v", err)
	}
}

// TestGCKeepsAReferrerOnAChildOfATaggedIndex: what is reachable is not what
// is tagged. Pulling a multi-platform artifact tags the index and leaves its
// children untagged, and a signature over one child names a manifest that no
// tag reaches but that the collector has in its graph, because it indexes
// everything the tagged descriptors lead to. Deciding from the list of tags
// would delete a signature the collector would have kept, silently.
func TestGCKeepsAReferrerOnAChildOfATaggedIndex(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	child := pushTestModel(t, s, "registry.internal/llm/child:tmp", []byte("weights of one platform"))
	if err := s.OCI().Untag(ctx, "registry.internal/llm/child:tmp"); err != nil {
		t.Fatal(err)
	}
	index := ocispec.Index{
		MediaType: ocispec.MediaTypeImageIndex,
		Manifests: []ocispec.Descriptor{child},
	}
	raw, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	indexDesc := content.NewDescriptorFromBytes(ocispec.MediaTypeImageIndex, raw)
	if err := s.OCI().Push(ctx, indexDesc, bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	if err := s.OCI().Tag(ctx, indexDesc, "registry.internal/llm/multi:v1"); err != nil {
		t.Fatal(err)
	}
	signature := pushUntaggedReferrer(t, s, child, "a signature over one platform")

	if err := s.GC(ctx); err != nil {
		t.Fatalf("gc: %v", err)
	}
	if _, err := s.BlobPath(signature.Digest); err != nil {
		t.Errorf("collection removed a signature over a child of a tagged index: %v", err)
	}
	if _, err := s.BlobPath(child.Digest); err != nil {
		t.Errorf("collection removed a child of a tagged index: %v", err)
	}
}

// TestRemoveDeletesTheReferrerManifest: untagging a referrer leaves the
// manifest in the layout, where it still names its subject and so still
// holds that subject's blobs, and where the collector spins on it. Removal
// has to take the manifest, not just the name, and nothing asserted that.
func TestRemoveDeletesTheReferrerManifest(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	model := pushTestModel(t, s, "registry.internal/llm/signed:v1", []byte("weights with a signature"))
	referrer := pushUntaggedReferrer(t, s, model, "a signature to be removed by name")
	const sigRef = "registry.internal/llm/signed:sha256-deadbeef.sig"
	if err := s.Tag(ctx, referrer, sigRef); err != nil {
		t.Fatal(err)
	}

	if err := s.Remove(ctx, sigRef); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := s.BlobPath(referrer.Digest); err == nil {
		t.Fatal("removal untagged the referrer and left its manifest in the store")
	}
	// The model it described is untouched, and its blobs wait for
	// collection the way everything else does.
	if _, err := s.Resolve(ctx, "registry.internal/llm/signed:v1"); err != nil {
		t.Errorf("removing a signature took the model with it: %v", err)
	}
	if _, err := s.BlobPath(model.Digest); err != nil {
		t.Errorf("removing a signature reclaimed the model's blobs early: %v", err)
	}
}

// TestGCReturnsWithAnOrphanTooLargeToParse: the sweep reads a manifest only
// to find its subject, and refusing to look at one past the bound that
// guards parsing would leave behind exactly the referrer the collector then
// hangs on. The collector applies no such bound, so a guard that did would
// once again exclude the broken case.
func TestGCReturnsWithAnOrphanTooLargeToParse(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	const ref = "registry.internal/llm/big:v1"
	model := pushTestModel(t, s, ref, []byte("weights held by an oversized orphan"))

	padding := strings.Repeat("p", maxJSONBlobSize+1024)
	referrer := ocispec.Manifest{
		MediaType:   ocispec.MediaTypeImageManifest,
		Config:      content.NewDescriptorFromBytes("application/octet-stream", []byte("{}")),
		Subject:     &model,
		Annotations: map[string]string{"io.palan.test.padding": padding},
	}
	blob := []byte("{}")
	if err := s.OCI().Push(ctx, content.NewDescriptorFromBytes("application/octet-stream", blob), bytes.NewReader(blob)); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(referrer)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= maxJSONBlobSize {
		t.Fatalf("the fixture is only %d bytes, which the parse bound would accept", len(raw))
	}
	desc := content.NewDescriptorFromBytes(ocispec.MediaTypeImageManifest, raw)
	if err := s.OCI().Push(ctx, desc, bytes.NewReader(raw)); err != nil {
		t.Fatalf("push oversized referrer: %v", err)
	}
	if err := s.OCI().Untag(ctx, ref); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- s.GC(ctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("gc: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("gc did not return with an orphaned referrer larger than the parse bound")
	}
	if _, err := s.BlobPath(desc.Digest); err == nil {
		t.Error("the oversized orphan survived collection")
	}
}

// TestGCRemovesAReferrerWhoseSubjectIsGone: a chain that runs into something
// the store does not hold reaches nothing, so what named it is orphaned.
// Treating an absent subject as a reason to keep would leave the referrer
// there for good, and the command that would clear it is the one that hangs
// on it.
func TestGCRemovesAReferrerWhoseSubjectIsGone(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	absent := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageManifest,
		Digest:    digest.FromString("a model this store never held"),
		Size:      123,
	}
	orphan := pushUntaggedReferrer(t, s, absent, "a signature over something absent")

	done := make(chan error, 1)
	go func() { done <- s.GC(ctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("gc: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("gc did not return with a referrer whose subject is absent")
	}
	if _, err := s.BlobPath(orphan.Digest); err == nil {
		t.Error("a referrer naming a subject the store does not hold survived collection")
	}
}

// TestGCKeepsAReferrerOnATaggedReferrer: the collector builds its graph from
// every tagged descriptor, referrers included, so a signature that is itself
// tagged is in that graph and something naming it is reachable. Measuring
// reachability from tagged artifacts alone answers a different question,
// which is the right one for deciding whether a signature has outlived its
// model and the wrong one for deciding what the collector can place. Using
// the first answer for the second deleted content the collector would have
// kept, silently.
func TestGCKeepsAReferrerOnATaggedReferrer(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	model := pushTestModel(t, s, "registry.internal/llm/attested:v1", []byte("weights with a tagged signature"))
	signature := pushUntaggedReferrer(t, s, model, "a signature that carries a tag")
	const sigRef = "registry.internal/llm/attested:sha256-cafe.sig"
	if err := s.Tag(ctx, signature, sigRef); err != nil {
		t.Fatal(err)
	}
	outer := pushUntaggedReferrer(t, s, signature, "something describing the signature")

	if err := s.GC(ctx); err != nil {
		t.Fatalf("gc: %v", err)
	}
	if _, err := s.BlobPath(outer.Digest); err != nil {
		t.Errorf("collection removed a referrer on a tagged signature, which the collector reaches: %v", err)
	}
	if _, err := s.BlobPath(signature.Digest); err != nil {
		t.Errorf("collection removed a tagged signature over a tagged model: %v", err)
	}
}

// pushIndexOver tags an index naming children, so a store can hold a
// manifest that only a tagged index reaches.
func pushIndexOver(t *testing.T, s *Store, children []ocispec.Descriptor, tag string) ocispec.Descriptor {
	t.Helper()
	ctx := context.Background()
	raw, err := json.Marshal(ocispec.Index{MediaType: ocispec.MediaTypeImageIndex, Manifests: children})
	if err != nil {
		t.Fatal(err)
	}
	desc := content.NewDescriptorFromBytes(ocispec.MediaTypeImageIndex, raw)
	if err := s.OCI().Push(ctx, desc, bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	if tag != "" {
		if err := s.Tag(ctx, desc, tag); err != nil {
			t.Fatal(err)
		}
	}
	return desc
}

// returnsWithin runs collection and reports whether it came back at all.
func returnsWithin(t *testing.T, s *Store, d time.Duration) bool {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- s.GC(context.Background()) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("gc: %v", err)
		}
		return true
	case <-time.After(d):
		return false
	}
}

// TestGCReturnsWhenAnIndexNamesAManifestTheStoreDoesNotHold: a node is only
// reachable once the layout is known to hold it. Recording it first and
// discovering the absence afterwards left the digest marked, so a referrer
// naming it was kept, and a subject the collector cannot find is what it
// reads over and over instead of dropping.
func TestGCReturnsWhenAnIndexNamesAManifestTheStoreDoesNotHold(t *testing.T) {
	s := openTestStore(t)
	absent := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageManifest,
		Digest:    digest.FromString("a child this store never received"),
		Size:      321,
	}
	pushIndexOver(t, s, []ocispec.Descriptor{absent}, "registry.internal/llm/partial:v1")
	orphan := pushUntaggedReferrer(t, s, absent, "a signature over the missing child")

	if !returnsWithin(t, s, 30*time.Second) {
		t.Fatal("gc did not return with a referrer naming a manifest the store does not hold")
	}
	if _, err := s.BlobPath(orphan.Digest); err == nil {
		t.Error("a referrer whose subject the store does not hold survived collection")
	}
}

// TestGCReturnsWithAnOrphanPastTheParseBound: the sweep reads a manifest
// only to find its subject, and the collector reads the same one with no
// limit. Any size refused here is a manifest the collector still reads and
// this cannot see, which is the referrer it then spins on.
func TestGCReturnsWithAnOrphanPastTheParseBound(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	const ref = "registry.internal/llm/huge:v1"
	model := pushTestModel(t, s, ref, []byte("weights held by a very large orphan"))
	blob := []byte("{}")
	if err := s.OCI().Push(ctx, content.NewDescriptorFromBytes("application/octet-stream", blob), bytes.NewReader(blob)); err != nil && !errors.Is(err, errdef.ErrAlreadyExists) {
		t.Fatal(err)
	}
	raw, err := json.Marshal(ocispec.Manifest{
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    content.NewDescriptorFromBytes("application/octet-stream", blob),
		Subject:   &model,
		// Past 64 MiB, which is the bound this read used to carry. Padding
		// to a multiple of the parse bound tested a size the read already
		// accepted, so it stood in for the limit that actually excluded
		// rather than crossing it.
		Annotations: map[string]string{"io.palan.test.padding": strings.Repeat("p", 17*maxJSONBlobSize)},
	})
	if err != nil {
		t.Fatal(err)
	}
	desc := content.NewDescriptorFromBytes(ocispec.MediaTypeImageManifest, raw)
	if err := s.OCI().Push(ctx, desc, bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	if err := s.OCI().Untag(ctx, ref); err != nil {
		t.Fatal(err)
	}

	if !returnsWithin(t, s, 30*time.Second) {
		t.Fatalf("gc did not return with a %d-byte orphaned referrer", len(raw))
	}
	if _, err := s.BlobPath(desc.Digest); err == nil {
		t.Error("the oversized orphan survived collection")
	}
}

// TestGCKeepsATaggedReferrerOnATaggedReferrer: an attestation over a
// signature over a model is the ordinary shape. Measuring from the
// artifacts and taking one hop called it orphaned and deleted it while
// nothing beneath it had gone anywhere.
func TestGCKeepsATaggedReferrerOnATaggedReferrer(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	model := pushTestModel(t, s, "registry.internal/llm/layered:v1", []byte("weights under two tagged referrers"))
	signature := pushUntaggedReferrer(t, s, model, "a tagged signature")
	if err := s.Tag(ctx, signature, "registry.internal/llm/layered:sha256-aa.sig"); err != nil {
		t.Fatal(err)
	}
	attestation := pushUntaggedReferrer(t, s, signature, "a tagged attestation over the signature")
	if err := s.Tag(ctx, attestation, "registry.internal/llm/layered:sha256-aa.att"); err != nil {
		t.Fatal(err)
	}

	if err := s.GC(ctx); err != nil {
		t.Fatalf("gc: %v", err)
	}
	for name, d := range map[string]ocispec.Descriptor{
		"the model": model, "the signature": signature, "the attestation over the signature": attestation,
	} {
		if _, err := s.BlobPath(d.Digest); err != nil {
			t.Errorf("collection removed %s, which nothing had orphaned: %v", name, err)
		}
	}
}

// TestGCReturnsWhenAnUntaggedReferrerSitsOnAnOrphanedTaggedOne holds the
// order of the two passes. Unlinking orphaned tagged referrers has to run
// first: the other pass treats what is still tagged as reachable, so run
// the other way round it keeps the outer referrer on the strength of a
// signature the first pass is about to remove, and leaves the collector
// reading it forever.
func TestGCReturnsWhenAnUntaggedReferrerSitsOnAnOrphanedTaggedOne(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	const ref = "registry.internal/llm/ordered:v1"
	model := pushTestModel(t, s, ref, []byte("weights whose model tag goes away"))
	signature := pushUntaggedReferrer(t, s, model, "a signature left tagged behind")
	if err := s.Tag(ctx, signature, "registry.internal/llm/ordered:sha256-bb.sig"); err != nil {
		t.Fatal(err)
	}
	outer := pushUntaggedReferrer(t, s, signature, "an untagged referrer on that signature")
	if err := s.OCI().Untag(ctx, ref); err != nil {
		t.Fatal(err)
	}

	if !returnsWithin(t, s, 30*time.Second) {
		t.Fatal("gc did not return with an untagged referrer on an orphaned tagged one")
	}
	for name, d := range map[string]ocispec.Descriptor{
		"the model": model, "the orphaned signature": signature, "the referrer on it": outer,
	} {
		if _, err := s.BlobPath(d.Digest); err == nil {
			t.Errorf("%s survived collection though nothing tagged reaches it", name)
		}
	}
}

// TestGCRunsTwice: collection rebuilds the layout's own view without
// writing it back, so index.json was left naming manifests whose blobs it
// had just removed, and every later process refused to collect at all. A
// command that works once and then never again is worse than one that
// never worked.
func TestGCRunsTwice(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	first, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	const ref = "registry.internal/llm/twice:v1"
	pushTestModel(t, first, ref, []byte("weights of a model that is removed"))
	if err := first.Remove(ctx, ref); err != nil {
		t.Fatal(err)
	}
	if err := first.GC(ctx); err != nil {
		t.Fatalf("first collection: %v", err)
	}
	// A later run is a new process, so a store reading the index off disk.
	for i := 2; i <= 3; i++ {
		later, oerr := Open(ctx, dir)
		if oerr != nil {
			t.Fatalf("opening the store for run %d: %v", i, oerr)
		}
		if err := later.GC(ctx); err != nil {
			t.Fatalf("collection run %d: %v", i, err)
		}
	}
}

// TestGCKeepsATaggedReferrerOverAnUntaggedOne: a signature that carries no
// tag still survives collection when its subject is reachable, so it is a
// live link in the chain. Admitting only tagged links broke the chain
// there, and a tagged attestation over an untagged signature over a tagged
// model was deleted while the signature under it was kept. Nothing had been
// removed, and the collector on the same store keeps all three.
func TestGCKeepsATaggedReferrerOverAnUntaggedOne(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	model := pushTestModel(t, s, "registry.internal/llm/mixed:v1", []byte("weights under a mixed chain"))
	signature := pushUntaggedReferrer(t, s, model, "an untagged signature")
	attestation := pushUntaggedReferrer(t, s, signature, "a tagged attestation over it")
	if err := s.Tag(ctx, attestation, "registry.internal/llm/mixed:sha256-dd.att"); err != nil {
		t.Fatal(err)
	}

	if err := s.GC(ctx); err != nil {
		t.Fatalf("gc: %v", err)
	}
	for name, d := range map[string]ocispec.Descriptor{
		"the model": model, "the untagged signature": signature, "the tagged attestation": attestation,
	} {
		if _, err := s.BlobPath(d.Digest); err != nil {
			t.Errorf("collection removed %s, on a chain where nothing was removed: %v", name, err)
		}
	}
}

// TestGCKeepsWhatHangsOffAManifestItCannotRead: absent and unreadable are
// different answers and only one is a reason to drop what points at it. A
// manifest that is present but will not read makes the collector fail,
// which loses nothing; treating it as absent made collection delete every
// signature over a model whose blob was briefly unreadable, and then report
// an error, so the operator believes nothing happened.
func TestGCKeepsWhatHangsOffAManifestItCannotRead(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	const ref = "registry.internal/llm/unreadable:v1"
	model := pushTestModel(t, s, ref, []byte("weights whose manifest stops reading"))
	signature := pushUntaggedReferrer(t, s, model, "a signature over it")

	path, err := s.BlobPath(model.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Skipf("this filesystem does not enforce mode bits: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
	if _, rerr := os.ReadFile(path); rerr == nil { // #nosec G304 -- test fixture under a temp dir
		t.Skip("running as a user that reads regardless of mode")
	}

	// Collection may fail here, which is fine and is what the collector
	// does. What it may not do is take the signature with it.
	_ = s.GC(ctx)
	if _, err := s.BlobPath(signature.Digest); err != nil {
		t.Errorf("collection removed a signature over a model it merely could not read: %v", err)
	}
}

// TestGCRepairsAnIndexLeftNamingAMissingManifest: collection rebuilds the
// layout's view before it sweeps blobs, so a sweep that stops halfway
// leaves index.json naming manifests whose blobs are gone, and every later
// process fails reloading it. The command that would repair that state must
// not be the command that refuses to start.
func TestGCRepairsAnIndexLeftNamingAMissingManifest(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	const ref = "registry.internal/llm/halfswept:v1"
	model := pushTestModel(t, s, ref, []byte("weights whose manifest blob is removed under it"))
	if err := s.OCI().Untag(ctx, ref); err != nil {
		t.Fatal(err)
	}
	// The blob goes while index.json still names it, which is exactly what
	// an interrupted sweep leaves behind.
	path, err := s.BlobPath(model.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	later, err := Open(ctx, dir)
	if err != nil {
		t.Fatalf("opening a store left in that state: %v", err)
	}
	if err := later.GC(ctx); err != nil {
		t.Fatalf("collection could not repair a half-swept store: %v", err)
	}
	again, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := again.GC(ctx); err != nil {
		t.Fatalf("collection still fails after the repair: %v", err)
	}
}
