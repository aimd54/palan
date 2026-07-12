// Copyright The moci Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/errdef"

	"github.com/aimd54/moci/pkg/modelspec"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	return s
}

// pushTestModel pushes a minimal ModelPack-shaped artifact (one weight blob,
// one config) and tags it, returning the manifest descriptor.
func pushTestModel(t *testing.T, s *Store, ref string, weights []byte) ocispec.Descriptor {
	t.Helper()
	ctx := context.Background()

	push := func(mediaType string, data []byte) ocispec.Descriptor {
		desc := content.NewDescriptorFromBytes(mediaType, data)
		err := s.OCI().Push(ctx, desc, bytes.NewReader(data))
		if err != nil && !errors.Is(err, errdef.ErrAlreadyExists) {
			t.Fatalf("push %s: %v", mediaType, err)
		}
		return desc
	}

	cfg := push(modelspec.MediaTypeModelConfig, []byte(`{"descriptor":{"name":"test"},"modelfs":{"type":"layers","diffIds":[]},"config":{}}`))
	weight := push(modelspec.MediaTypeModelWeightRaw, weights)
	weight.Annotations = map[string]string{modelspec.AnnotationFilepath: "test.gguf"}

	manifest := ocispec.Manifest{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: modelspec.ArtifactTypeModelManifest,
		Config:       cfg,
		Layers:       []ocispec.Descriptor{weight},
	}
	manifest.SchemaVersion = 2
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	mDesc := content.NewDescriptorFromBytes(ocispec.MediaTypeImageManifest, raw)
	mDesc.ArtifactType = modelspec.ArtifactTypeModelManifest
	if err := s.OCI().Push(ctx, mDesc, bytes.NewReader(raw)); err != nil && !errors.Is(err, errdef.ErrAlreadyExists) {
		t.Fatalf("push manifest: %v", err)
	}
	if err := s.Tag(ctx, mDesc, ref); err != nil {
		t.Fatalf("tag %q: %v", ref, err)
	}
	return mDesc
}

// TestLayoutShape pins the on-disk contract: a standard OCI image layout
// that any OCI tool can read (M1 acceptance).
func TestLayoutShape(t *testing.T) {
	s := openTestStore(t)
	pushTestModel(t, s, "registry.example/llm/tiny:q4", []byte("gguf-bytes"))

	layout, err := os.ReadFile(filepath.Join(s.Root(), "oci-layout"))
	if err != nil {
		t.Fatalf("oci-layout marker missing: %v", err)
	}
	var marker struct {
		Version string `json:"imageLayoutVersion"`
	}
	if err := json.Unmarshal(layout, &marker); err != nil || marker.Version == "" {
		t.Fatalf("oci-layout marker malformed: %s (%v)", layout, err)
	}
	if _, err := os.Stat(filepath.Join(s.Root(), "index.json")); err != nil {
		t.Fatalf("index.json missing: %v", err)
	}
	blobs, err := filepath.Glob(filepath.Join(s.Root(), "blobs", "sha256", "*"))
	if err != nil || len(blobs) != 3 { // config + weight + manifest
		t.Fatalf("expected 3 blobs under blobs/sha256, got %d (%v)", len(blobs), err)
	}
}

// TestFreshHandleReadsStore proves the layout is self-describing: a brand-new
// oras-go handle (as any external OCI tool would create) resolves the ref.
func TestFreshHandleReadsStore(t *testing.T) {
	s := openTestStore(t)
	want := pushTestModel(t, s, "registry.example/llm/tiny:q4", []byte("gguf-bytes"))

	fresh, err := oci.New(s.Root())
	if err != nil {
		t.Fatalf("fresh handle: %v", err)
	}
	got, err := fresh.Resolve(context.Background(), "registry.example/llm/tiny:q4")
	if err != nil {
		t.Fatalf("fresh resolve: %v", err)
	}
	if got.Digest != want.Digest {
		t.Errorf("fresh handle resolved %s, want %s", got.Digest, want.Digest)
	}
}

// TestBlobDedupAcrossTags: same weights under two tags exist once on disk
// (M1 acceptance: blobs dedup across tags).
func TestBlobDedupAcrossTags(t *testing.T) {
	s := openTestStore(t)
	weights := []byte("shared-gguf-weights")
	pushTestModel(t, s, "registry.example/llm/tiny:a", weights)
	pushTestModel(t, s, "registry.example/llm/tiny:b", weights)

	blobs, _ := filepath.Glob(filepath.Join(s.Root(), "blobs", "sha256", "*"))
	// config, weight, manifest — all identical between the two pushes except
	// nothing: both tags point at the same manifest. 3 blobs total.
	if len(blobs) != 3 {
		t.Errorf("expected 3 deduplicated blobs, got %d", len(blobs))
	}

	entries, err := s.List(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 tagged refs, got %d", len(entries))
	}
}

func TestBlobPath(t *testing.T) {
	s := openTestStore(t)
	weights := []byte("gguf-bytes-for-path")
	pushTestModel(t, s, "registry.example/llm/tiny:q4", weights)

	desc := content.NewDescriptorFromBytes(modelspec.MediaTypeModelWeightRaw, weights)
	p, err := s.BlobPath(desc.Digest)
	if err != nil {
		t.Fatalf("blob path: %v", err)
	}
	got, err := os.ReadFile(p)
	if err != nil || !bytes.Equal(got, weights) {
		t.Errorf("blob path content mismatch (%v)", err)
	}

	if _, err := s.BlobPath("sha256:0000000000000000000000000000000000000000000000000000000000000000"); err == nil {
		t.Error("missing blob must error")
	}
	if _, err := s.BlobPath("not-a-digest"); err == nil {
		t.Error("invalid digest must error")
	}
}

// TestRemoveThenGC: rm unlinks the ref (content stays), gc reclaims
// unreferenced blobs while shared content survives.
func TestRemoveThenGC(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	pushTestModel(t, s, "registry.example/llm/tiny:keep", []byte("weights-keep"))
	pushTestModel(t, s, "registry.example/llm/tiny:drop", []byte("weights-drop"))

	if err := s.Remove(ctx, "registry.example/llm/tiny:drop"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := s.Resolve(ctx, "registry.example/llm/tiny:drop"); err == nil {
		t.Fatal("removed ref must not resolve")
	}

	if err := s.GC(ctx); err != nil {
		t.Fatalf("gc: %v", err)
	}

	// The kept model must still resolve and its weight blob must exist.
	if _, err := s.Resolve(ctx, "registry.example/llm/tiny:keep"); err != nil {
		t.Fatalf("kept ref lost after gc: %v", err)
	}
	keepDesc := content.NewDescriptorFromBytes(modelspec.MediaTypeModelWeightRaw, []byte("weights-keep"))
	if _, err := s.BlobPath(keepDesc.Digest); err != nil {
		t.Errorf("kept weights reclaimed by gc: %v", err)
	}
	// The dropped weights must be gone.
	dropDesc := content.NewDescriptorFromBytes(modelspec.MediaTypeModelWeightRaw, []byte("weights-drop"))
	if _, err := s.BlobPath(dropDesc.Digest); err == nil {
		t.Error("dropped weights survived gc")
	}
}

func TestRemoveMissingRef(t *testing.T) {
	s := openTestStore(t)
	if err := s.Remove(context.Background(), "registry.example/llm/absent:tag"); err == nil {
		t.Error("removing an absent ref must error")
	}
}

func TestExclusiveLockBlocks(t *testing.T) {
	s := openTestStore(t)
	unlock, err := s.Lock(context.Background())
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}
	defer unlock()

	// A second store handle (same lock file) must fail to acquire within
	// a short deadline while the first holds the lock.
	s2, err := Open(context.Background(), s.Root())
	if err != nil {
		t.Fatalf("second open: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := s2.Lock(ctx); err == nil {
		t.Error("second exclusive lock should have timed out")
	}
}

func TestDefaultRootPrecedence(t *testing.T) {
	t.Setenv(EnvHome, "/custom/moci-home")
	if got, _ := DefaultRoot(); got != "/custom/moci-home" {
		t.Errorf("MOCI_HOME not honored: %s", got)
	}
	t.Setenv(EnvHome, "")
	t.Setenv("XDG_DATA_HOME", "/xdg/data")
	if got, _ := DefaultRoot(); got != filepath.Join("/xdg/data", "moci") {
		t.Errorf("XDG_DATA_HOME not honored: %s", got)
	}
}

func TestFetchJSONSizeGuard(t *testing.T) {
	s := openTestStore(t)
	desc := ocispec.Descriptor{MediaType: "application/json", Size: maxJSONBlobSize + 1}
	if _, err := FetchJSON[map[string]any](context.Background(), s.OCI(), desc); err == nil {
		t.Error("oversized JSON blob must be refused")
	}
}
