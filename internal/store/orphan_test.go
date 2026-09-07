// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
)

// pushUntaggedReferrer plants a manifest carrying subject and never tags it,
// which is the state an interrupted removal leaves behind and the one a
// listing of tags cannot show.
func pushUntaggedReferrer(t *testing.T, s *Store, subject ocispec.Descriptor) ocispec.Descriptor {
	t.Helper()
	ctx := context.Background()
	for _, d := range [][]byte{[]byte("{}"), []byte("signature payload")} {
		desc := content.NewDescriptorFromBytes("application/octet-stream", d)
		if err := s.OCI().Push(ctx, desc, bytes.NewReader(d)); err != nil {
			t.Fatalf("push blob: %v", err)
		}
	}
	referrer := ocispec.Manifest{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: "application/vnd.dev.cosign.simplesigning.v1+json",
		Config:       content.NewDescriptorFromBytes("application/octet-stream", []byte("{}")),
		Layers:       []ocispec.Descriptor{content.NewDescriptorFromBytes("application/octet-stream", []byte("signature payload"))},
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
	orphan := pushUntaggedReferrer(t, s, model)
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
	referrer := pushUntaggedReferrer(t, s, model)

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
