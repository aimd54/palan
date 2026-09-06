// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// overwriteBlob replaces a blob's bytes on disk, which is the situation
// re-hashing exists for: the manifest and its signature are untouched, and
// only the content changed.
func overwriteBlob(t *testing.T, s *Store, desc ocispec.Descriptor, content []byte) {
	t.Helper()
	path, err := s.BlobPath(desc.Digest)
	if err != nil {
		t.Fatalf("blob path: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod blob: %v", err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("overwrite blob: %v", err)
	}
}

// weightDescriptor returns the artifact's single weight layer.
func weightDescriptor(t *testing.T, s *Store, manifest ocispec.Descriptor) ocispec.Descriptor {
	t.Helper()
	man, err := FetchManifest(context.Background(), s.OCI(), manifest)
	if err != nil {
		t.Fatalf("fetch manifest: %v", err)
	}
	if len(man.Layers) != 1 {
		t.Fatalf("expected one layer, got %d", len(man.Layers))
	}
	return man.Layers[0]
}

func TestRehashReadsEveryBlobTheManifestNames(t *testing.T) {
	s := openTestStore(t)
	weights := []byte("weights that are longer than a digest")
	desc := pushTestModel(t, s, "registry.internal/llm/test:v1", weights)

	report, err := Rehash(context.Background(), s.OCI(), desc)
	if err != nil {
		t.Fatalf("rehash: %v", err)
	}
	// The manifest, its config, and the one weight layer.
	if report.Blobs != 3 {
		t.Errorf("read %d blobs, want 3 (manifest, config, weight layer)", report.Blobs)
	}
	man, err := FetchManifest(context.Background(), s.OCI(), desc)
	if err != nil {
		t.Fatalf("fetch manifest: %v", err)
	}
	want := desc.Size + man.Config.Size + man.Layers[0].Size
	if report.Bytes != want {
		t.Errorf("reported %d bytes, want %d", report.Bytes, want)
	}
	if int64(len(weights)) != man.Layers[0].Size {
		t.Errorf("the weight layer records %d bytes, the file holds %d", man.Layers[0].Size, len(weights))
	}
}

func TestRehashRefusesAWeightBlobSubstitutedBehindAnIntactManifest(t *testing.T) {
	s := openTestStore(t)
	original := []byte("the weights a publisher released")
	desc := pushTestModel(t, s, "registry.internal/llm/test:v1", original)
	weight := weightDescriptor(t, s, desc)

	// Same length, so nothing but reading the bytes back can tell. This is
	// the whole threat: a manifest that still verifies over content that
	// changed.
	substituted := []byte("the weights an attacker wrote!!!")
	if len(substituted) != len(original) {
		t.Fatalf("the substitution must be the same length, got %d against %d", len(substituted), len(original))
	}
	overwriteBlob(t, s, weight, substituted)

	_, err := Rehash(context.Background(), s.OCI(), desc)
	if err == nil {
		t.Fatal("a substituted weight blob was accepted")
	}
	if !strings.Contains(err.Error(), weight.Digest.String()) {
		t.Errorf("the refusal does not name the blob: %v", err)
	}
	if !strings.Contains(err.Error(), "signed") {
		t.Errorf("the refusal does not say the bytes are not the ones that were signed: %v", err)
	}
}

func TestRehashRefusesABlobOfTheWrongLength(t *testing.T) {
	s := openTestStore(t)
	desc := pushTestModel(t, s, "registry.internal/llm/test:v1", []byte("the weights a publisher released"))
	weight := weightDescriptor(t, s, desc)
	overwriteBlob(t, s, weight, []byte("short"))

	_, err := Rehash(context.Background(), s.OCI(), desc)
	if err == nil {
		t.Fatal("a truncated weight blob was accepted")
	}
	if !strings.Contains(err.Error(), "5 bytes") {
		t.Errorf("the refusal does not say how long the blob actually is: %v", err)
	}
}

func TestRehashRefusesAnArtifactShapeItCannotWalk(t *testing.T) {
	s := openTestStore(t)
	desc := pushTestModel(t, s, "registry.internal/llm/test:v1", []byte("weights"))
	// The same bytes, relabelled. Nothing downstream notices: the digest
	// still matches and the text still decodes, so without a guard on the
	// shape the walk reports a clean result for an artifact it was never
	// taught to read.
	asIndex := desc
	asIndex.MediaType = ocispec.MediaTypeImageIndex

	report, err := Rehash(context.Background(), s.OCI(), asIndex)
	if err == nil {
		t.Fatalf("an index was walked as a manifest, reporting %d blobs read", report.Blobs)
	}
	if !strings.Contains(err.Error(), ocispec.MediaTypeImageIndex) {
		t.Errorf("the refusal does not name the shape it was given: %v", err)
	}
}

// TestRehashNamesAManifestWithNoConfigForWhatItIs: a document carrying no
// config decodes into an image manifest without complaint and leaves a zero
// descriptor where the config belongs. Walking it refuses, which is right,
// but the refusal came from the digest check and described an unusable
// digest, which reads as a damaged or tampered artifact and sends an
// operator looking for harm that never happened. What is actually wrong is
// the shape.
func TestRehashNamesAManifestWithNoConfigForWhatItIs(t *testing.T) {
	s := openTestStore(t)
	body := []byte(`{"schemaVersion":2,"mediaType":"` + ocispec.MediaTypeImageManifest + `","layers":[]}`)
	desc := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageManifest,
		Digest:    digest.FromBytes(body),
		Size:      int64(len(body)),
	}
	if err := s.OCI().Push(context.Background(), desc, bytes.NewReader(body)); err != nil {
		t.Fatalf("push: %v", err)
	}

	report, err := Rehash(context.Background(), s.OCI(), desc)
	if err == nil {
		t.Fatalf("a document with no config was walked, reporting %d blobs read", report.Blobs)
	}
	if !strings.Contains(err.Error(), "no config blob") {
		t.Errorf("the refusal does not say what the document is missing: %v", err)
	}
}
