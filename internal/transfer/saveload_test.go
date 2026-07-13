// Copyright The moci Authors
// SPDX-License-Identifier: Apache-2.0

package transfer

import (
	"archive/tar"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aimd54/moci/internal/registrytest"
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
	if err := Save(ctx, src, []string{"registry.internal/llm/tiny:a", "registry.internal/llm/tiny:b"}, &bundle); err != nil {
		t.Fatalf("save: %v", err)
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
	if len(blobs) != 3 { // config, weights, manifest — shared across both tags
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
