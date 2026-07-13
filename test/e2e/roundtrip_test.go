// Copyright The moci Authors
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package e2e

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/aimd54/moci/internal/gguf/gguftest"
)

// fixtures holds the on-disk inputs for one packed model.
type fixtures struct {
	dir       string
	ggufPath  string
	ggufBytes []byte
	licPath   string
}

func writeFixtures(t *testing.T, payloadSize int) fixtures {
	t.Helper()
	dir := t.TempDir()
	payload := make([]byte, payloadSize)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	f := fixtures{
		dir:       dir,
		ggufPath:  filepath.Join(dir, "tiny.gguf"),
		ggufBytes: gguftest.TinyModel("llama", "tiny", "15M", 2048, 15, payload),
		licPath:   filepath.Join(dir, "LICENSE"),
	}
	if err := os.WriteFile(f.ggufPath, f.ggufBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.licPath, []byte("Apache License 2.0 text"), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

// TestPushPullRoundTrip: pack on machine A, push to zot, pull on machine B
// (fresh store), and verify the manifest digest and weight bytes survive
// intact (M1/M2 acceptance).
func TestPushPullRoundTrip(t *testing.T) {
	host := registryHost(t)
	fx := writeFixtures(t, 1<<20)
	ref := host + "/llm/tiny:q4"

	homeA := t.TempDir()
	packOut := moci(t, homeA, "pack", fx.ggufPath, fx.licPath, "-t", ref, "--profile", "both", "--ctx", "2048")
	packedDigest := firstDigest(t, packOut)
	moci(t, homeA, "push", ref)
	moci(t, homeA, "push", ref+"-car")

	homeB := t.TempDir()
	pullOut := moci(t, homeB, "pull", ref)
	if got := firstDigest(t, pullOut); got != packedDigest {
		t.Errorf("pulled digest %s, want %s", got, packedDigest)
	}

	var rows []struct {
		Ref    string `json:"ref"`
		Kind   string `json:"kind"`
		Digest string `json:"digest"`
	}
	if err := json.Unmarshal([]byte(moci(t, homeB, "ls", "--json")), &rows); err != nil {
		t.Fatalf("ls --json: %v", err)
	}
	found := false
	for _, r := range rows {
		if r.Ref == ref {
			found = true
			if r.Kind != "model" || r.Digest != packedDigest {
				t.Errorf("ls row wrong: %+v", r)
			}
		}
	}
	if !found {
		t.Fatalf("pulled ref missing from ls: %+v", rows)
	}

	// The weight blob on machine B is byte-identical to the original file
	// and directly servable from the store.
	sum := sha256.Sum256(fx.ggufBytes)
	blobPath := filepath.Join(homeB, "blobs", "sha256", hex.EncodeToString(sum[:]))
	got, err := os.ReadFile(blobPath)
	if err != nil {
		t.Fatalf("weight blob not in store: %v", err)
	}
	if !bytes.Equal(got, fx.ggufBytes) {
		t.Error("weight blob corrupted in round trip")
	}
}

// TestSaveLoadAcrossStores: the sneakernet path — save on a connected
// machine, load on an air-gapped one, byte-identical (M5 acceptance).
func TestSaveLoadAcrossStores(t *testing.T) {
	fx := writeFixtures(t, 512<<10)
	ref := "registry.internal/llm/offline:v1"

	homeA := t.TempDir()
	packOut := moci(t, homeA, "pack", fx.ggufPath, "-t", ref)
	packedDigest := firstDigest(t, packOut)
	bundle := filepath.Join(t.TempDir(), "bundle.tar")
	moci(t, homeA, "save", ref, "-o", bundle)

	homeB := t.TempDir()
	moci(t, homeB, "load", "-i", bundle)
	var rows []struct {
		Ref    string `json:"ref"`
		Digest string `json:"digest"`
	}
	if err := json.Unmarshal([]byte(moci(t, homeB, "ls", "--json")), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Ref != ref || rows[0].Digest != packedDigest {
		t.Errorf("loaded store rows wrong: %+v (want %s @ %s)", rows, ref, packedDigest)
	}

	sum := sha256.Sum256(fx.ggufBytes)
	blob := filepath.Join(homeB, "blobs", "sha256", hex.EncodeToString(sum[:]))
	got, err := os.ReadFile(blob)
	if err != nil || !bytes.Equal(got, fx.ggufBytes) {
		t.Errorf("weights corrupted through the bundle (%v)", err)
	}
}

// TestRmAndGC: after rm + gc on a pulled model, the ref and its blobs are
// gone; a re-pull restores them from the registry.
func TestRmAndGC(t *testing.T) {
	host := registryHost(t)
	fx := writeFixtures(t, 256<<10)
	ref := host + "/llm/gc-check:v1"

	home := t.TempDir()
	moci(t, home, "pack", fx.ggufPath, "-t", ref)
	moci(t, home, "push", ref)
	moci(t, home, "rm", ref)
	moci(t, home, "gc")

	sum := sha256.Sum256(fx.ggufBytes)
	blobPath := filepath.Join(home, "blobs", "sha256", hex.EncodeToString(sum[:]))
	if _, err := os.Stat(blobPath); err == nil {
		t.Error("weight blob survived rm+gc")
	}

	moci(t, home, "pull", ref)
	if _, err := os.Stat(blobPath); err != nil {
		t.Errorf("re-pull did not restore the blob: %v", err)
	}
}
