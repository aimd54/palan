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

// TestGCKeepsAReferrerWhoseChainReachesATag: a referrer may describe another
// referrer, so whether one is orphaned is a question about the chain and not
// about its first hop. Stopping at one step calls the outer one orphaned
// while the chain beneath it ends at a live model, and deleting it takes the
// middle of the chain with it, because a subject is a graph successor and
// the layout reclaims what that leaves unreferenced. Both would go without
// a word.
func TestGCKeepsAReferrerWhoseChainReachesATag(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	const ref = "registry.internal/llm/chain:v1"
	model := pushTestModel(t, s, ref, []byte("weights at the end of the chain"))
	middle := pushUntaggedReferrer(t, s, model, "a signature over the model")
	outer := pushUntaggedReferrer(t, s, middle, "something describing the signature")

	if err := s.GC(ctx); err != nil {
		t.Fatalf("gc: %v", err)
	}
	for name, d := range map[string]ocispec.Descriptor{
		"the model": model, "the signature on it": middle, "the referrer on the signature": outer,
	} {
		if _, err := s.BlobPath(d.Digest); err != nil {
			t.Errorf("collection removed %s, whose chain reaches a tag: %v", name, err)
		}
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
