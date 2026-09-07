// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
