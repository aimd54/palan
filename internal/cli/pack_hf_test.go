// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/aimd54/palan/internal/hf/hftest"
	"github.com/aimd54/palan/internal/omsig"
	"github.com/aimd54/palan/internal/omsig/omsigtest"
)

// newTestCommand returns a *cobra.Command with output discarded, for tests
// that call a command function directly rather than through Execute.
func newTestCommand(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "test"}
	cmd.SetErr(io.Discard)
	return cmd
}

func TestPackFromARepositoryCarriesEveryFilesPublishedDigest(t *testing.T) {
	hub := hftest.New(t, map[string][]byte{
		"model.safetensors":      []byte("weights-bytes"),
		"config.json":            []byte(`{"architectures":["Qwen3ForCausalLM"],"max_position_embeddings":4096}`),
		"tokenizer.json":         []byte("{}"),
		"generation_config.json": []byte(`{}`),
	})
	// generation_config.json is served inline, the way the real API serves a
	// small file that is not stored in LFS, so it publishes no digest at
	// all. Its content still hashes to something, so if OriginSHA256 were
	// ever recomputed from the downloaded bytes instead of passed through
	// from what the repository published, this file's assertion below is
	// the one that would catch it: every other seeded file's published
	// digest equals its content hash by construction of the fake hub, so
	// only an inline file tells the two apart.
	hub.Inline = map[string]bool{"generation_config.json": true}
	t.Setenv("HF_ENDPOINT", hub.URL())

	files, info, err := resolveSources(t.Context(), newTestCommand(t), []string{"hf://org/repo"})
	if info.tempDir != "" {
		t.Cleanup(func() { _ = os.RemoveAll(info.tempDir) })
	}
	if err != nil {
		t.Fatalf("resolveSources: %v", err)
	}
	if len(files) != 4 {
		t.Fatalf("resolved %d files, want the weights, the config, the tokenizer and the generation config", len(files))
	}
	for _, f := range files {
		if f.Name == "generation_config.json" {
			if f.OriginSHA256 != "" {
				t.Errorf("%s carries OriginSHA256 %q, want empty: the repository serves it inline with no digest", f.Path, f.OriginSHA256)
			}
			continue
		}
		if f.OriginSHA256 == "" {
			t.Errorf("%s reached the packer without the digest the repository published", f.Path)
		}
		if strings.HasPrefix(f.OriginSHA256, "sha256:") {
			t.Errorf("%s carries a prefixed digest %q; the layer annotation is bare hex", f.Path, f.OriginSHA256)
		}
	}
	if info.sourceURL == "" {
		t.Error("the artifact would not record which repository it came from")
	}
}

// signRepo builds a signature covering the SHA-256 of each named file, the
// way the model-signing tool would, and returns the PEM-encoded public key
// that verifies it alongside the encoded bundle.
func signRepo(t *testing.T, files map[string][]byte, covered []string) (publicKeyPEM []byte, bundle []byte) {
	t.Helper()
	subjects := make(map[string]string, len(covered))
	for _, name := range covered {
		sum := sha256.Sum256(files[name])
		subjects[name] = hex.EncodeToString(sum[:])
	}
	bundle, _, publicKeyPEM = omsigtest.Bundle(t, subjects)
	return publicKeyPEM, bundle
}

// testPublicKeyPEM returns the PEM of a fresh key unrelated to any
// signature a test builds, so a key can be supplied against a repository
// that never asked to be checked with it.
func testPublicKeyPEM(t *testing.T) []byte {
	t.Helper()
	_, pem := omsigtest.Key(t)
	return pem
}

func TestPackRefusesARepositoryWhoseSignatureOmitsAFile(t *testing.T) {
	files := map[string][]byte{
		"model.safetensors": []byte("weights-bytes"),
		"config.json":       []byte(`{"architectures":["Qwen3ForCausalLM"]}`),
	}
	// The signature covers the weights and says nothing about the config,
	// which is where a swapped tokenizer or config would hide.
	keyPEM, bundle := signRepo(t, files, []string{"model.safetensors"})
	files[omsig.FileName] = bundle
	hub := hftest.New(t, files)
	t.Setenv("HF_ENDPOINT", hub.URL())

	keyPath := filepath.Join(t.TempDir(), "key.pub")
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	omsKey = keyPath
	t.Cleanup(func() { omsKey = "" })

	_, _, err := resolveSources(t.Context(), newTestCommand(t), []string{"hf://org/repo"})
	if err == nil {
		t.Fatal("imported a file the publisher's signature does not cover")
	}
	if !strings.Contains(err.Error(), "config.json") {
		t.Errorf("the refusal does not name the uncovered file: %v", err)
	}
}

func TestPackRecordsWhoSignedTheRepository(t *testing.T) {
	files := map[string][]byte{
		"model.safetensors": []byte("weights-bytes"),
		"config.json":       []byte(`{"architectures":["Qwen3ForCausalLM"]}`),
	}
	keyPEM, bundle := signRepo(t, files, []string{"model.safetensors", "config.json"})
	files[omsig.FileName] = bundle
	hub := hftest.New(t, files)
	t.Setenv("HF_ENDPOINT", hub.URL())

	keyPath := filepath.Join(t.TempDir(), "key.pub")
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	omsKey = keyPath
	t.Cleanup(func() { omsKey = "" })

	_, info, err := resolveSources(t.Context(), newTestCommand(t), []string{"hf://org/repo"})
	if err != nil {
		t.Fatalf("resolveSources: %v", err)
	}
	if !strings.HasPrefix(info.signer, "sha256:") {
		t.Errorf("signer = %q, want the key that vouched for the files", info.signer)
	}
}

func TestPackWithAKeyRefusesARepositoryThatPublishesNoSignature(t *testing.T) {
	hub := hftest.New(t, map[string][]byte{
		"model.safetensors": []byte("weights-bytes"),
		"config.json":       []byte(`{}`),
	})
	t.Setenv("HF_ENDPOINT", hub.URL())
	keyPath := filepath.Join(t.TempDir(), "key.pub")
	if err := os.WriteFile(keyPath, testPublicKeyPEM(t), 0o600); err != nil {
		t.Fatal(err)
	}
	omsKey = keyPath
	t.Cleanup(func() { omsKey = "" })

	if _, _, err := resolveSources(t.Context(), newTestCommand(t), []string{"hf://org/repo"}); err == nil {
		t.Fatal("a verification key was supplied and an unsigned repository imported anyway")
	}
}

// TestPackRefusesAFileWhoseDownloadedBytesDontMatchTheSignature proves that
// what gets checked against the signature is the digest of the bytes that
// landed on disk, not the digest the API advertised. generation_config.json
// is served inline, the way Hugging Face serves a small file it does not
// store in LFS: paths-info reports no digest for it at all, so Download has
// nothing to check the downloaded bytes against and lets them through
// whatever they are. The signature was built over what the file is supposed
// to contain; the hub actually serves something else. If palan trusted the
// API's (absent) digest instead of hashing what it wrote to disk, this file
// would sail through unnoticed.
func TestPackRefusesAFileWhoseDownloadedBytesDontMatchTheSignature(t *testing.T) {
	published := []byte(`{"published":true}`)
	sum := sha256.Sum256(published)

	files := map[string][]byte{
		"model.safetensors":      []byte("weights-bytes"),
		"config.json":            []byte(`{"architectures":["Qwen3ForCausalLM"]}`),
		"generation_config.json": []byte(`{"tampered":true}`), // what the hub actually serves
	}
	modelSum := sha256.Sum256(files["model.safetensors"])
	configSum := sha256.Sum256(files["config.json"])
	subjects := map[string]string{
		"model.safetensors":      hex.EncodeToString(modelSum[:]),
		"config.json":            hex.EncodeToString(configSum[:]),
		"generation_config.json": hex.EncodeToString(sum[:]), // covers the published bytes, not the tampered ones
	}
	bundle, _, keyPEM := omsigtest.Bundle(t, subjects)
	files[omsig.FileName] = bundle
	hub := hftest.New(t, files)
	hub.Inline = map[string]bool{"generation_config.json": true}
	t.Setenv("HF_ENDPOINT", hub.URL())

	keyPath := filepath.Join(t.TempDir(), "key.pub")
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	omsKey = keyPath
	t.Cleanup(func() { omsKey = "" })

	_, _, err := resolveSources(t.Context(), newTestCommand(t), []string{"hf://org/repo"})
	if err == nil {
		t.Fatal("packed a file whose downloaded bytes do not match what the signature covers")
	}
	if !strings.Contains(err.Error(), "generation_config.json") {
		t.Errorf("the refusal does not name the tampered file: %v", err)
	}
	// The file has no advertised digest at all (it is served inline), so a
	// check that fell back to the API's digest would refuse with "no sha256
	// given" rather than a mismatch, for the wrong reason: it would refuse
	// this file no matter what bytes it held. Only a refusal that names an
	// actual computed digest proves the check hashed what was downloaded.
	if !strings.Contains(err.Error(), "hashes to") {
		t.Errorf("refusal = %q, want a digest mismatch naming the hash of the downloaded bytes, not a fallback to the API's absent digest", err)
	}
}
