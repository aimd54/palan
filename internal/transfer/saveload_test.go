// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package transfer

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry"

	"github.com/aimd54/palan/internal/registrytest"
	"github.com/aimd54/palan/internal/signing"
	"github.com/aimd54/palan/internal/store"
)

// TestSaveLoadRoundTrip: two refs sharing blobs export to one bundle and
// import into a fresh store with content and dedup intact (M5 acceptance).
func TestSaveLoadRoundTrip(t *testing.T) {
	ctx := context.Background()
	src := openTestStore(t)
	weights := randomBytes(t, 1<<20)
	mA, wDesc := seedStoreModel(t, src, "registry.internal/llm/tiny:a", weights)
	seedStoreModel(t, src, "registry.internal/llm/tiny:b", weights)

	var bundle bytes.Buffer
	sigs, err := Save(ctx, src, []string{"registry.internal/llm/tiny:a", "registry.internal/llm/tiny:b"}, &bundle)
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	if sigs != 0 {
		t.Errorf("unsigned models must contribute no signatures, got %d", sigs)
	}

	dst := openTestStore(t)
	refs, err := Load(ctx, dst, bytes.NewReader(bundle.Bytes()))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(refs) != 2 {
		t.Fatalf("expected 2 refs, got %v", refs)
	}
	got, err := dst.Resolve(ctx, "registry.internal/llm/tiny:a")
	if err != nil || got.Digest != mA.Digest {
		t.Errorf("ref a after load: %v (%v)", got.Digest, err)
	}
	p, err := dst.BlobPath(wDesc.Digest)
	if err != nil {
		t.Fatalf("weights missing after load: %v", err)
	}
	onDisk, _ := os.ReadFile(p)
	if !bytes.Equal(onDisk, weights) {
		t.Error("weights corrupted through save/load")
	}
	blobs, _ := filepath.Glob(filepath.Join(dst.Root(), "blobs", "sha256", "*"))
	if len(blobs) != 3 { // config, weights, manifest: shared across both tags
		t.Errorf("dedup lost through save/load: %d blobs", len(blobs))
	}
}

func TestLoadRejectsTraversal(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: "../evil", Size: 4, Mode: 0o644})
	_, _ = tw.Write([]byte("evil"))
	_ = tw.Close()

	st := openTestStore(t)
	if _, err := Load(context.Background(), st, &buf); err == nil || !strings.Contains(err.Error(), "escapes") {
		t.Errorf("traversal entry must be rejected, got %v", err)
	}
}

func TestLoadRejectsLinks(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Typeflag: tar.TypeSymlink, Name: "oci-layout", Linkname: "/etc/passwd"})
	_ = tw.Close()

	st := openTestStore(t)
	if _, err := Load(context.Background(), st, &buf); err == nil || !strings.Contains(err.Error(), "unsupported type") {
		t.Errorf("symlink entry must be rejected, got %v", err)
	}
}

func TestLoadRejectsEmptyBundle(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.Close()
	st := openTestStore(t)
	if _, err := Load(context.Background(), st, &buf); err == nil {
		t.Error("empty bundle must be rejected")
	}
}

// TestCpRegistryToRegistry: direct registry→registry streaming.
func TestCpRegistryToRegistry(t *testing.T) {
	regA := registrytest.New(t)
	regB := registrytest.New(t)
	weights := randomBytes(t, 512<<10)
	mDesc, wDesc := seedRegistryModel(t, regA, "llm/tiny", "q4", weights)

	c := newTestClient(t)
	src := mustParse(t, regA.Host()+"/llm/tiny:q4")
	dst := mustParse(t, regB.Host()+"/llm/mirrored:q4")

	got, err := c.Copy(context.Background(), src, dst, Events{})
	if err != nil {
		t.Fatalf("cp: %v", err)
	}
	if got.Digest != mDesc.Digest {
		t.Errorf("copied digest %s, want %s", got.Digest, mDesc.Digest)
	}
	if !regB.HasBlob("llm/mirrored", wDesc.Digest) {
		t.Error("weights did not arrive at destination registry")
	}
	if !regB.HasManifest("llm/mirrored", "q4") {
		t.Error("manifest did not arrive at destination registry")
	}
}

// buildSignatureManifest returns a cosign-shaped signature manifest for a
// subject digest. The bytes are not a real signature: these tests cover how
// signatures travel, while internal/signing covers whether they verify.
func buildSignatureManifest(t *testing.T) (manifest, payload, cfg []byte, mDesc, plDesc, cfgDesc ocispec.Descriptor) {
	t.Helper()
	payload = []byte(`{"critical":{"identity":{"docker-reference":"registry.internal/llm/tiny"}}}`)
	plDesc = content.NewDescriptorFromBytes(signing.MediaTypeSimpleSigning, payload)
	plDesc.Annotations = map[string]string{signing.AnnotationSignature: "Zm9v"}
	cfg = []byte("{}")
	cfgDesc = content.NewDescriptorFromBytes(ocispec.MediaTypeImageConfig, cfg)

	m := ocispec.Manifest{MediaType: ocispec.MediaTypeImageManifest, Config: cfgDesc, Layers: []ocispec.Descriptor{plDesc}}
	m.SchemaVersion = 2
	var err error
	manifest, err = json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	mDesc = content.NewDescriptorFromBytes(ocispec.MediaTypeImageManifest, manifest)
	return manifest, payload, cfg, mDesc, plDesc, cfgDesc
}

// seedStoreSignature plants a signature for subject in the local store under
// the reference the store addresses it by.
func seedStoreSignature(t *testing.T, st *store.Store, ref registry.Reference, subject digest.Digest) string {
	t.Helper()
	ctx := context.Background()
	manifest, payload, cfg, mDesc, plDesc, cfgDesc := buildSignatureManifest(t)
	for _, part := range []struct {
		desc ocispec.Descriptor
		data []byte
	}{{plDesc, payload}, {cfgDesc, cfg}, {mDesc, manifest}} {
		if err := st.OCI().Push(ctx, part.desc, bytes.NewReader(part.data)); err != nil && !errors.Is(err, errdef.ErrAlreadyExists) {
			t.Fatalf("seed signature push: %v", err)
		}
	}
	sigRef := signing.SigRef(ref, subject)
	if err := st.Tag(ctx, mDesc, sigRef); err != nil {
		t.Fatalf("seed signature tag: %v", err)
	}
	return sigRef
}

func TestSaveCarriesTheSignature(t *testing.T) {
	ctx := context.Background()
	src := openTestStore(t)
	ref := mustParse(t, "registry.internal/llm/tiny:a")
	mDesc, _ := seedStoreModel(t, src, ref.String(), randomBytes(t, 512))
	sigRef := seedStoreSignature(t, src, ref, mDesc.Digest)

	var bundle bytes.Buffer
	sigs, err := Save(ctx, src, []string{ref.String()}, &bundle)
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	if sigs != 1 {
		t.Errorf("Save reported %d signatures, want 1", sigs)
	}

	// The point of carrying it is that the far side can address it, so assert
	// the imported store resolves the signature rather than that save said so.
	dst := openTestStore(t)
	if _, err := Load(ctx, dst, &bundle); err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, err := dst.Resolve(ctx, sigRef); err != nil {
		t.Errorf("signature missing from the imported store: %v", err)
	}
	if _, err := dst.Resolve(ctx, ref.String()); err != nil {
		t.Errorf("model missing from the imported store: %v", err)
	}
}

func TestPullStoresTheSignature(t *testing.T) {
	ctx := context.Background()
	reg := registrytest.New(t)
	weights := randomBytes(t, 1024)
	mDesc, _ := seedRegistryModel(t, reg, "llm/tiny", "q4", weights)

	manifest, payload, cfg, _, _, _ := buildSignatureManifest(t)
	reg.PutBlob("llm/tiny", payload)
	reg.PutBlob("llm/tiny", cfg)
	reg.PutManifest("llm/tiny", signing.SigTag(mDesc.Digest), ocispec.MediaTypeImageManifest, manifest)

	st := openTestStore(t)
	ref := mustParse(t, reg.Host()+"/llm/tiny:q4")
	var reported bool
	if _, err := newTestClient(t).Pull(ctx, st, ref, Events{
		OnSignature: func(stored bool) { reported = stored },
	}); err != nil {
		t.Fatalf("pull: %v", err)
	}
	if !reported {
		t.Error("pull must report that a signature travelled")
	}
	if _, err := st.Resolve(ctx, signing.SigRef(ref, mDesc.Digest)); err != nil {
		t.Errorf("signature not in the store after pull: %v", err)
	}
}

func TestPullWithoutSignatureIsNotAnError(t *testing.T) {
	ctx := context.Background()
	reg := registrytest.New(t)
	mDesc, _ := seedRegistryModel(t, reg, "llm/tiny", "q4", randomBytes(t, 1024))

	st := openTestStore(t)
	ref := mustParse(t, reg.Host()+"/llm/tiny:q4")
	reported := true
	if _, err := newTestClient(t).Pull(ctx, st, ref, Events{
		OnSignature: func(stored bool) { reported = stored },
	}); err != nil {
		t.Fatalf("pulling an unsigned model must succeed: %v", err)
	}
	if reported {
		t.Error("no signature exists, so none must be reported as stored")
	}
	if _, err := st.Resolve(ctx, signing.SigRef(ref, mDesc.Digest)); !errors.Is(err, errdef.ErrNotFound) {
		t.Errorf("expected no signature in the store, got %v", err)
	}
}

// TestCpCarriesTheSignature: mirroring into an offline registry is a
// documented way to cross an air gap, so a model that arrives there without
// its signature cannot be verified on the far side.
func TestCpCarriesTheSignature(t *testing.T) {
	regA := registrytest.New(t)
	regB := registrytest.New(t)
	mDesc, _ := seedRegistryModel(t, regA, "llm/tiny", "q4", randomBytes(t, 512))

	manifest, payload, cfg, _, _, _ := buildSignatureManifest(t)
	regA.PutBlob("llm/tiny", payload)
	regA.PutBlob("llm/tiny", cfg)
	sigTag := signing.SigTag(mDesc.Digest)
	regA.PutManifest("llm/tiny", sigTag, ocispec.MediaTypeImageManifest, manifest)

	c := newTestClient(t)
	src := mustParse(t, regA.Host()+"/llm/tiny:q4")
	dst := mustParse(t, regB.Host()+"/llm/mirrored:q4")
	if _, err := c.Copy(context.Background(), src, dst, Events{}); err != nil {
		t.Fatalf("cp: %v", err)
	}
	if !regB.HasManifest("llm/mirrored", sigTag) {
		t.Error("signature did not arrive at the destination registry")
	}
}

// TestCpWithoutSignatureIsNotAnError guards the common case: most artifacts
// are unsigned, and mirroring them must not start failing.
func TestCpWithoutSignatureIsNotAnError(t *testing.T) {
	regA := registrytest.New(t)
	regB := registrytest.New(t)
	mDesc, _ := seedRegistryModel(t, regA, "llm/tiny", "q4", randomBytes(t, 512))

	c := newTestClient(t)
	src := mustParse(t, regA.Host()+"/llm/tiny:q4")
	dst := mustParse(t, regB.Host()+"/llm/mirrored:q4")
	if _, err := c.Copy(context.Background(), src, dst, Events{}); err != nil {
		t.Fatalf("mirroring an unsigned model must succeed: %v", err)
	}
	if regB.HasManifest("llm/mirrored", signing.SigTag(mDesc.Digest)) {
		t.Error("no signature existed, so none should have been created")
	}
}
