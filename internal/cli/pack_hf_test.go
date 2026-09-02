// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/aimd54/palan/internal/gguf/gguftest"
	"github.com/aimd54/palan/internal/hf/hftest"
	"github.com/aimd54/palan/internal/omsig"
	"github.com/aimd54/palan/internal/omsig/omsigtest"
	"github.com/aimd54/palan/internal/pack"
	"github.com/aimd54/palan/internal/safetensors"
	"github.com/aimd54/palan/internal/safetensors/safetensorstest"
	"github.com/aimd54/palan/internal/store"
	"github.com/aimd54/palan/pkg/modelspec"
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

// TestPackFromTwoRepositoriesKeepsEachFilesOwnBytes proves that naming two
// repositories in one invocation cannot make one repository's file overwrite
// the other's on disk. Both repositories here publish a config.json, each
// under different content and a different published digest; if the two
// downloads ever landed in the same directory under the same basename, the
// second write would clobber the first while the resolved file list still
// carried an entry claiming the first repository's digest for whatever bytes
// happen to be on disk at that shared path, an artifact asserting a
// publisher released bytes they did not.
func TestPackFromTwoRepositoriesKeepsEachFilesOwnBytes(t *testing.T) {
	hub := hftest.New(t, nil)
	hub.Repos = map[string]map[string][]byte{
		"org/a": {
			"model.safetensors": []byte("a-weights"),
			"config.json":       []byte(`{"repo":"a"}`),
		},
		"org/b": {
			"model.safetensors": []byte("b-weights"),
			"config.json":       []byte(`{"repo":"b"}`),
		},
	}
	t.Setenv("HF_ENDPOINT", hub.URL())

	files, info, err := resolveSources(t.Context(), newTestCommand(t), []string{"hf://org/a", "hf://org/b"})
	if info.tempDir != "" {
		t.Cleanup(func() { _ = os.RemoveAll(info.tempDir) })
	}
	if err != nil {
		t.Fatalf("resolveSources: %v", err)
	}
	if len(files) != 4 {
		t.Fatalf("resolved %d files, want two each from two repositories: %+v", len(files), files)
	}

	type want struct{ content, digest string }
	byRepo := make(map[string]want, len(hub.Repos))
	for repo, rf := range hub.Repos {
		sum := sha256.Sum256(rf["config.json"])
		byRepo[repo] = want{content: string(rf["config.json"]), digest: hex.EncodeToString(sum[:])}
	}

	var sawA, sawB bool
	for _, f := range files {
		if f.Name != "config.json" {
			continue
		}
		if f.Name != filepath.Base(f.Name) {
			t.Errorf("layer name %q carries a directory component", f.Name)
		}
		got, err := os.ReadFile(f.Path)
		if err != nil {
			t.Fatalf("reading %s: %v", f.Path, err)
		}
		switch {
		case string(got) == byRepo["org/a"].content:
			sawA = true
			if f.OriginSHA256 != byRepo["org/a"].digest {
				t.Errorf("org/a config.json OriginSHA256 = %q, want %q (org/a's own published digest)", f.OriginSHA256, byRepo["org/a"].digest)
			}
		case string(got) == byRepo["org/b"].content:
			sawB = true
			if f.OriginSHA256 != byRepo["org/b"].digest {
				t.Errorf("org/b config.json OriginSHA256 = %q, want %q (org/b's own published digest)", f.OriginSHA256, byRepo["org/b"].digest)
			}
		default:
			t.Errorf("a config.json on disk holds %q, matching neither repository's published content", got)
		}
	}
	if !sawA || !sawB {
		t.Fatalf("did not find both repositories' own config.json intact (org/a seen=%v, org/b seen=%v): %+v", sawA, sawB, files)
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

// signerKeyID independently recomputes the identity Verify assigns to a
// key, by hashing the DER bytes carried inside its PEM the same way omsig's
// own keyID does, so a test can check an artifact's signer annotation
// against a value it did not get from Verify's own output.
func signerKeyID(t *testing.T, publicKeyPEM []byte) string {
	t.Helper()
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		t.Fatal("decoding the test public key PEM")
	}
	sum := sha256.Sum256(block.Bytes)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func TestPackWithAKeyRefusesAPurelyLocalInvocation(t *testing.T) {
	localPath := filepath.Join(t.TempDir(), "model.gguf")
	if err := os.WriteFile(localPath, []byte("not fetched from anywhere"), 0o600); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "key.pub")
	if err := os.WriteFile(keyPath, testPublicKeyPEM(t), 0o600); err != nil {
		t.Fatal(err)
	}
	omsKey = keyPath
	t.Cleanup(func() { omsKey = "" })

	files, info, err := resolveSources(t.Context(), newTestCommand(t), []string{localPath})
	if info.tempDir != "" {
		t.Cleanup(func() { _ = os.RemoveAll(info.tempDir) })
	}
	if err == nil {
		t.Fatal("a key was supplied with only a local file and the import proceeded unverified")
	}
	if !strings.Contains(err.Error(), localPath) {
		t.Errorf("the refusal does not name the local file: %v", err)
	}
	if files != nil {
		t.Error("resolveSources returned files alongside an error")
	}
}

func TestPackWithAKeyRefusesMixingALocalFileWithARepository(t *testing.T) {
	files := map[string][]byte{
		"model.safetensors": []byte("weights-bytes"),
		"config.json":       []byte(`{"architectures":["Qwen3ForCausalLM"]}`),
	}
	keyPEM, bundle := signRepo(t, files, []string{"model.safetensors", "config.json"})
	files[omsig.FileName] = bundle
	hub := hftest.New(t, files)
	t.Setenv("HF_ENDPOINT", hub.URL())

	extra := filepath.Join(t.TempDir(), "extra.json")
	if err := os.WriteFile(extra, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "key.pub")
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	omsKey = keyPath
	t.Cleanup(func() { omsKey = "" })

	// The repository is genuinely signed and would otherwise verify; only
	// the local file, which the signature says nothing about, makes this
	// invocation refuse.
	_, info, err := resolveSources(t.Context(), newTestCommand(t), []string{"hf://org/repo", extra})
	if info.tempDir != "" {
		t.Cleanup(func() { _ = os.RemoveAll(info.tempDir) })
	}
	if err == nil {
		t.Fatal("a key was supplied and a local file was packed alongside a signed repository, unverified")
	}
	if !strings.Contains(err.Error(), extra) {
		t.Errorf("the refusal does not name the local file: %v", err)
	}
}

func TestPackWithAKeyRefusesAnEmptySignatureFile(t *testing.T) {
	files := map[string][]byte{
		"model.safetensors": []byte("weights-bytes"),
		"config.json":       []byte(`{}`),
	}
	files[omsig.FileName] = []byte{}
	hub := hftest.New(t, files)
	t.Setenv("HF_ENDPOINT", hub.URL())

	keyPath := filepath.Join(t.TempDir(), "key.pub")
	if err := os.WriteFile(keyPath, testPublicKeyPEM(t), 0o600); err != nil {
		t.Fatal(err)
	}
	omsKey = keyPath
	t.Cleanup(func() { omsKey = "" })

	_, info, err := resolveSources(t.Context(), newTestCommand(t), []string{"hf://org/repo"})
	if info.tempDir != "" {
		t.Cleanup(func() { _ = os.RemoveAll(info.tempDir) })
	}
	if err == nil {
		t.Fatal("an empty model.sig verified as a valid signature")
	}
}

func TestPackWithAKeyRefusesAMalformedSignatureFile(t *testing.T) {
	files := map[string][]byte{
		"model.safetensors": []byte("weights-bytes"),
		"config.json":       []byte(`{}`),
	}
	files[omsig.FileName] = []byte("this is not a signature bundle")
	hub := hftest.New(t, files)
	t.Setenv("HF_ENDPOINT", hub.URL())

	keyPath := filepath.Join(t.TempDir(), "key.pub")
	if err := os.WriteFile(keyPath, testPublicKeyPEM(t), 0o600); err != nil {
		t.Fatal(err)
	}
	omsKey = keyPath
	t.Cleanup(func() { omsKey = "" })

	_, info, err := resolveSources(t.Context(), newTestCommand(t), []string{"hf://org/repo"})
	if info.tempDir != "" {
		t.Cleanup(func() { _ = os.RemoveAll(info.tempDir) })
	}
	if err == nil {
		t.Fatal("a malformed model.sig verified as a valid signature")
	}
}

// TestPackRecordsTheSignerOnThePackedManifest exercises both hops the signer
// annotation depends on: resolveSources threading the verified key's
// identity into fetchedSources.signer, and pack.Model threading
// Options.Signer into the manifest's io.palan.origin.signer annotation. The
// want value is computed independently of Verify's own output, so this
// checks the annotation actually equals the key's identity, not merely that
// it looks like one.
func TestPackRecordsTheSignerOnThePackedManifest(t *testing.T) {
	weights := gguftest.TinyModel("llama", "tiny-signed", "15M", 2048, 1, []byte("deterministic-fake-weights"))
	files := map[string][]byte{"model.gguf": weights}
	keyPEM, bundle := signRepo(t, files, []string{"model.gguf"})
	files[omsig.FileName] = bundle
	hub := hftest.New(t, files)
	t.Setenv("HF_ENDPOINT", hub.URL())

	keyPath := filepath.Join(t.TempDir(), "key.pub")
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	omsKey = keyPath
	t.Cleanup(func() { omsKey = "" })

	resolved, fetched, err := resolveSources(t.Context(), newTestCommand(t), []string{"hf://org/repo/model.gguf"})
	if fetched.tempDir != "" {
		t.Cleanup(func() { _ = os.RemoveAll(fetched.tempDir) })
	}
	if err != nil {
		t.Fatalf("resolveSources: %v", err)
	}

	st, err := store.Open(t.Context(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	desc, err := pack.Model(t.Context(), st, resolved, "registry.example/llm/tiny:v1", pack.Options{Signer: fetched.signer})
	if err != nil {
		t.Fatalf("pack.Model: %v", err)
	}
	manifest, err := store.FetchManifest(t.Context(), st.OCI(), desc)
	if err != nil {
		t.Fatalf("fetch manifest: %v", err)
	}

	want := signerKeyID(t, keyPEM)
	if got := manifest.Annotations[modelspec.AnnotationOriginSigner]; got != want {
		t.Errorf("io.palan.origin.signer = %q, want %q (the digest of the key that verified)", got, want)
	}
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

	_, info, err := resolveSources(t.Context(), newTestCommand(t), []string{"hf://org/repo"})
	if info.tempDir != "" {
		t.Cleanup(func() { _ = os.RemoveAll(info.tempDir) })
	}
	if err == nil {
		t.Fatal("imported a file the publisher's signature does not cover")
	}
	if !strings.Contains(err.Error(), "config.json") {
		t.Errorf("the refusal does not name the uncovered file: %v", err)
	}
}

// TestPackCommandRefusesAnUncoveredFileWhenOMSKeyIsSetThroughTheFlag runs the
// pack command through cobra's own flag parsing instead of assigning the
// omsKey package variable directly, which is how every other --oms-key test
// in this file drives verification. If newPackCmd's "--oms-key" flag
// registration ever stopped binding to the command line, omsKey would stay
// empty, resolveSources would skip verification entirely, and pack would
// exit 0 against an unsigned or partly-covered repository: the silent
// success this whole feature exists to prevent. The refusal asserted below,
// an uncovered file wrapped in omsig.ErrNotCovered, is only reachable once a
// signature has actually been fetched and verified against the supplied
// key, so seeing it proves the flag reached resolveSources and that RunE
// went on to read the verified result back out of fetchedSources.
func TestPackCommandRefusesAnUncoveredFileWhenOMSKeyIsSetThroughTheFlag(t *testing.T) {
	files := map[string][]byte{
		"model.safetensors": []byte("weights-bytes"),
		"config.json":       []byte(`{"architectures":["Qwen3ForCausalLM"]}`),
	}
	keyPEM, bundle := signRepo(t, files, []string{"model.safetensors"})
	files[omsig.FileName] = bundle
	hub := hftest.New(t, files)
	t.Setenv("HF_ENDPOINT", hub.URL())
	t.Setenv(store.EnvHome, t.TempDir())

	keyPath := filepath.Join(t.TempDir(), "key.pub")
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { omsKey = "" })

	cmd := newPackCmd(viper.New())
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{
		"hf://org/repo",
		"-t", "registry.example/llm/tiny:v1",
		"--oms-key", keyPath,
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("pack exited 0 for a repository whose signature does not cover every file")
	}
	if !strings.Contains(err.Error(), "config.json") {
		t.Errorf("the refusal does not name the uncovered file: %v", err)
	}
	if !errors.Is(err, omsig.ErrNotCovered) {
		t.Errorf("error = %v, want it to wrap omsig.ErrNotCovered, the refusal only a verified path produces", err)
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
	if info.tempDir != "" {
		t.Cleanup(func() { _ = os.RemoveAll(info.tempDir) })
	}
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

	_, info, err := resolveSources(t.Context(), newTestCommand(t), []string{"hf://org/repo"})
	if info.tempDir != "" {
		t.Cleanup(func() { _ = os.RemoveAll(info.tempDir) })
	}
	if err == nil {
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

	_, info, err := resolveSources(t.Context(), newTestCommand(t), []string{"hf://org/repo"})
	if info.tempDir != "" {
		t.Cleanup(func() { _ = os.RemoveAll(info.tempDir) })
	}
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

func TestPackCarriesTheSourceOfEveryFetchedFile(t *testing.T) {
	hub := hftest.New(t, map[string][]byte{
		"model.safetensors": []byte("weights-bytes"),
		"config.json":       []byte(`{"architectures":["Qwen3ForCausalLM"]}`),
	})
	hub.Revision = "e4f2c1d0000000000000000000000000000000aa"
	t.Setenv("HF_ENDPOINT", hub.URL())

	files, _, err := resolveSources(t.Context(), newTestCommand(t), []string{"hf://org/repo"})
	if err != nil {
		t.Fatalf("resolveSources: %v", err)
	}
	// Asserted against the hub's own endpoint and each file's actual path,
	// rather than merely checking the fields are non-empty and do not carry
	// the hf:// scheme: a source built from the wrong reference, a
	// hardcoded placeholder, or the literal argument string rather than
	// what was actually fetched would all satisfy a shape check and still
	// be wrong.
	wantRepo := strings.TrimPrefix(hub.URL(), "http://") + "/org/repo"
	wantPath := map[string]string{
		"model.safetensors": "model.safetensors",
		"config.json":       "config.json",
	}
	if len(files) != len(wantPath) {
		t.Fatalf("resolved %d files, want %d", len(files), len(wantPath))
	}
	for _, f := range files {
		if f.SourceRepo != wantRepo {
			t.Errorf("%s SourceRepo = %q, want %q", f.Name, f.SourceRepo, wantRepo)
		}
		want, ok := wantPath[f.Name]
		if !ok {
			t.Fatalf("resolveSources returned unexpected file %s", f.Name)
		}
		if f.SourcePath != want {
			t.Errorf("%s SourcePath = %q, want %q", f.Name, f.SourcePath, want)
		}
		if f.SourceRevision != hub.Revision {
			t.Errorf("%s SourceRevision = %q, want %q", f.Name, f.SourceRevision, hub.Revision)
		}
	}
}

// TestPackRecordsARepositoryRelativePathNotTheDownloadedFilename: Download
// writes each file to filepath.Join(destDir, filepath.Base(f.Path)), so on
// disk a file published at onnx/model.safetensors is just
// model.safetensors. SourcePath must stay the path within the repository,
// because it goes into the signed statement and is what a reader would use
// to fetch the file again. Every other fixture publishes flat, single
// segment paths, where the repository-relative path and the basename are
// byte identical and this confusion cannot be seen.
func TestPackRecordsARepositoryRelativePathNotTheDownloadedFilename(t *testing.T) {
	const nested = "onnx/model.safetensors"
	hub := hftest.New(t, map[string][]byte{nested: []byte("weights-under-a-subdirectory")})
	hub.Revision = "b7c3d9e1000000000000000000000000000000cc"
	t.Setenv("HF_ENDPOINT", hub.URL())

	files, _, err := resolveSources(t.Context(), newTestCommand(t), []string{"hf://org/repo/" + nested})
	if err != nil {
		t.Fatalf("resolveSources: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("resolved %d files, want 1", len(files))
	}
	f := files[0]
	if f.SourcePath != nested {
		t.Errorf("SourcePath = %q, want %q: the basename alone cannot address the file in its repository", f.SourcePath, nested)
	}
	if f.SourceRevision != hub.Revision {
		t.Errorf("SourceRevision = %q, want %q", f.SourceRevision, hub.Revision)
	}
}

// TestPackNamingTwoRepositoriesKeepsEachFilesOwnSource proves that naming two
// hf:// references in one command cannot let one reference's repository or
// revision reach the other reference's files. Both repositories publish a
// model.safetensors and a config.json under different content and, crucially,
// under different revisions: a file that carried the wrong reference's
// SourceRepo or SourceRevision would still pass a check that only looked at
// non-emptiness, so this identifies each file by its actual bytes and checks
// the source recorded against the repository that bytes actually came from.
func TestPackNamingTwoRepositoriesKeepsEachFilesOwnSource(t *testing.T) {
	hub := hftest.New(t, nil)
	hub.Repos = map[string]map[string][]byte{
		"org/a": {
			"model.safetensors": []byte("a-weights"),
			"config.json":       []byte(`{"repo":"a"}`),
		},
		"org/b": {
			"model.safetensors": []byte("b-weights"),
			"config.json":       []byte(`{"repo":"b"}`),
		},
	}
	hub.Revisions = map[string]string{
		"org/a": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"org/b": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	t.Setenv("HF_ENDPOINT", hub.URL())

	files, info, err := resolveSources(t.Context(), newTestCommand(t), []string{"hf://org/a", "hf://org/b"})
	if info.tempDir != "" {
		t.Cleanup(func() { _ = os.RemoveAll(info.tempDir) })
	}
	if err != nil {
		t.Fatalf("resolveSources: %v", err)
	}
	if len(files) != 4 {
		t.Fatalf("resolved %d files, want two each from two repositories: %+v", len(files), files)
	}

	wantHost := strings.TrimPrefix(hub.URL(), "http://")
	type want struct{ repo, revision string }
	byContent := make(map[string]want, 4)
	for repo, rf := range hub.Repos {
		for _, b := range rf {
			byContent[string(b)] = want{repo: repo, revision: hub.Revisions[repo]}
		}
	}

	var sawA, sawB int
	for _, f := range files {
		got, err := os.ReadFile(f.Path)
		if err != nil {
			t.Fatalf("reading %s: %v", f.Path, err)
		}
		w, ok := byContent[string(got)]
		if !ok {
			t.Fatalf("a file on disk holds %q, matching neither repository's published content", got)
		}
		wantRepo := wantHost + "/" + w.repo
		if f.SourceRepo != wantRepo {
			t.Errorf("%s SourceRepo = %q, want %q (the repository this file's bytes actually came from)", f.Name, f.SourceRepo, wantRepo)
		}
		if f.SourceRevision != w.revision {
			t.Errorf("%s SourceRevision = %q, want %q (%s's own commit)", f.Name, f.SourceRevision, w.revision, w.repo)
		}
		if w.repo == "org/a" {
			sawA++
		} else {
			sawB++
		}
	}
	if sawA != 2 || sawB != 2 {
		t.Fatalf("did not find both repositories' own two files (org/a=%d, org/b=%d): %+v", sawA, sawB, files)
	}
}

// TestPackDownloadsFromTheResolvedRevision proves the download itself, not
// just the SourceRevision annotation, reaches the commit Resolve reported.
// SourceRevision could be threaded through to the manifest correctly while
// Download quietly kept fetching from main regardless; only inspecting what
// the hub actually received for the download request tells the two apart.
func TestPackDownloadsFromTheResolvedRevision(t *testing.T) {
	hub := hftest.New(t, map[string][]byte{
		"model.safetensors": []byte("weights-bytes"),
		"config.json":       []byte(`{"architectures":["Qwen3ForCausalLM"]}`),
	})
	hub.Revision = "e4f2c1d0000000000000000000000000000000aa"
	t.Setenv("HF_ENDPOINT", hub.URL())

	_, info, err := resolveSources(t.Context(), newTestCommand(t), []string{"hf://org/repo"})
	if info.tempDir != "" {
		t.Cleanup(func() { _ = os.RemoveAll(info.tempDir) })
	}
	if err != nil {
		t.Fatalf("resolveSources: %v", err)
	}
	if len(hub.Fetched) == 0 {
		t.Fatal("no download reached the hub")
	}
	for _, got := range hub.Fetched {
		if got != hub.Revision {
			t.Errorf("downloaded from revision %q, want %q: a branch can move between listing and download", got, hub.Revision)
		}
	}
}

func TestPackFromDiskCarriesNoSource(t *testing.T) {
	dir := t.TempDir()
	local := filepath.Join(dir, "model.gguf")
	if err := os.WriteFile(local, []byte("not really a gguf"), 0o600); err != nil {
		t.Fatal(err)
	}
	files, _, err := resolveSources(t.Context(), newTestCommand(t), []string{local})
	if err != nil {
		t.Fatalf("resolveSources: %v", err)
	}
	for _, f := range files {
		if f.SourceRepo != "" || f.SourcePath != "" || f.SourceRevision != "" {
			t.Errorf("%s claims a source for a local file", f.Path)
		}
	}
}

// TestPackKeepsTwoNestedFilesSharingABasenameApart: a repository can
// publish two files with the same name in different directories. Download
// names a file by its basename, so without a directory of its own per file
// the second overwrites the first, and pack then hashes one file's bytes
// twice while each layer carries the other's published digest and source
// path. The artifact is signed and attested as genuine, and nothing
// reports the loss, because each download verified its own bytes before
// being overwritten.
func TestPackKeepsTwoNestedFilesSharingABasenameApart(t *testing.T) {
	first := []byte("first shard bytes, definitely not the second")
	second := []byte("second shard bytes, definitely not the first")
	// Both shards come from ONE reference. Two references already get a
	// directory each, so naming them separately would not collide and
	// would prove nothing.
	index := `{"metadata":{"total_size":86},"weight_map":{"x":"a/model.safetensors","y":"b/model.safetensors"}}`
	hub := hftest.New(t, map[string][]byte{
		"model.safetensors.index.json": []byte(index),
		"a/model.safetensors":          first,
		"b/model.safetensors":          second,
	})
	hub.Revision = "c9d1e2f3000000000000000000000000000000dd"
	t.Setenv("HF_ENDPOINT", hub.URL())

	files, _, err := resolveSources(t.Context(), newTestCommand(t), []string{"hf://org/repo"})
	if err != nil {
		t.Fatalf("resolveSources: %v", err)
	}
	if len(files) < 2 {
		t.Fatalf("resolved %d files, want at least the two shards", len(files))
	}

	// Each layer must hold the bytes of the file its source names. Reading
	// the files back is the assertion: comparing only digests or only
	// annotations would pass while both entries pointed at one file.
	want := map[string][]byte{"a/model.safetensors": first, "b/model.safetensors": second}
	for _, f := range files {
		expected, ok := want[f.SourcePath]
		if !ok {
			continue // the index itself, and anything else packed alongside
		}
		got, err := os.ReadFile(f.Path)
		if err != nil {
			t.Fatalf("reading %s: %v", f.Path, err)
		}
		if !bytes.Equal(got, expected) {
			t.Errorf("%s holds %q, want %q: the layer would carry another file's bytes under this one's provenance",
				f.SourcePath, got, expected)
		}
		delete(want, f.SourcePath)
	}
	if len(want) != 0 {
		t.Errorf("no layer resolved for %v", want)
	}
}

// TestPackRecordsOneOriginNotTwo: an artifact carries the repository's web
// address as org.opencontainers.image.source and the repository it was
// fetched from in the signed source annotations. Deriving the first from a
// hardcoded host and the second from the configured endpoint puts two
// contradictory origins on one artifact, one of them signed.
func TestPackRecordsOneOriginNotTwo(t *testing.T) {
	hub := hftest.New(t, map[string][]byte{"model.gguf": []byte("weights")})
	hub.Revision = "d4e5f6a7000000000000000000000000000000ee"
	t.Setenv("HF_ENDPOINT", hub.URL())

	files, info, err := resolveSources(t.Context(), newTestCommand(t), []string{"hf://org/repo/model.gguf"})
	if err != nil {
		t.Fatalf("resolveSources: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no files resolved")
	}
	host := strings.TrimPrefix(hub.URL(), "http://")
	if !strings.Contains(info.sourceURL, host) {
		t.Errorf("source URL = %q, want it to name the endpoint the bytes came from (%s)", info.sourceURL, host)
	}
	// The two must name the same repository on the same host, since a
	// reader comparing them is why both are recorded.
	if !strings.HasSuffix(info.sourceURL, files[0].SourceRepo) {
		t.Errorf("source URL %q does not end in the source repo %q, so they disagree about where the bytes came from",
			info.sourceURL, files[0].SourceRepo)
	}
	if strings.Contains(info.sourceURL, "huggingface.co") {
		t.Errorf("source URL = %q, but nothing was fetched from huggingface.co", info.sourceURL)
	}
}

// tinyShard builds a minimal but real safetensors container, small enough
// for a fixture and large enough for the format's own reader to parse.
func tinyShard(tensorName string) []byte {
	return safetensorstest.Shard(safetensorstest.Tensor{
		Name: tensorName, DType: "BF16", Shape: []int64{8, 8},
	})
}

// layerFilepaths reads the org.cncf.model.filepath annotation off every
// layer in a manifest, which is where a packed file's name lands.
func layerFilepaths(manifest ocispec.Manifest) map[string]bool {
	out := make(map[string]bool, len(manifest.Layers))
	for _, l := range manifest.Layers {
		out[l.Annotations[modelspec.AnnotationFilepath]] = true
	}
	return out
}

// TestPackWholeSafetensorsRepositoryEndToEnd packs a single-file
// safetensors repository through the pack command itself, not just
// resolveSources. Every other hf:// safetensors test in this file stops at
// the resolved file list and never calls pack, so a resolve that looked
// right but left config.json unreachable from the weight file's directory
// would still pass the whole suite while the command failed for every user.
func TestPackWholeSafetensorsRepositoryEndToEnd(t *testing.T) {
	hub := hftest.New(t, map[string][]byte{
		"model.safetensors": tinyShard("w"),
		"config.json":       []byte(`{"architectures":["Qwen3ForCausalLM"],"max_position_embeddings":4096}`),
	})
	t.Setenv("HF_ENDPOINT", hub.URL())
	home := t.TempDir()
	t.Setenv(store.EnvHome, home)

	cmd := newPackCmd(viper.New())
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"hf://org/repo", "-t", "registry.example/llm/tiny-st:v1"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("pack exited with an error: %v", err)
	}

	st, err := store.Open(t.Context(), home)
	if err != nil {
		t.Fatal(err)
	}
	desc, err := st.Resolve(t.Context(), "registry.example/llm/tiny-st:v1")
	if err != nil {
		t.Fatalf("the packed artifact is not in the store: %v", err)
	}
	manifest, err := store.FetchManifest(t.Context(), st.OCI(), desc)
	if err != nil {
		t.Fatalf("fetching the packed manifest: %v", err)
	}
	names := layerFilepaths(manifest)
	for _, want := range []string{"model.safetensors", "config.json"} {
		if !names[want] {
			t.Errorf("packed artifact does not carry %s; layers: %v", want, names)
		}
	}
}

// TestPackShardedSafetensorsRepositoryEndToEnd packs a sharded safetensors
// repository through the pack command. The shard index is stated at the
// repository root, and gatherSafetensorsShards stats each shard beside it,
// so this fails a step earlier than the single-file case when the fetched
// files do not land beside each other.
func TestPackShardedSafetensorsRepositoryEndToEnd(t *testing.T) {
	shard1 := tinyShard("t1")
	shard2 := tinyShard("t2")
	// total_size counts tensor bytes only; each shard file also carries its
	// own header, so the true bytes on disk comfortably clear this figure,
	// the same margin internal/pack's own sharded fixtures rely on.
	index := `{"metadata":{"total_size":256},"weight_map":{"t1":"model-00001-of-00002.safetensors","t2":"model-00002-of-00002.safetensors"}}`
	hub := hftest.New(t, map[string][]byte{
		safetensors.IndexName:              []byte(index),
		"model-00001-of-00002.safetensors": shard1,
		"model-00002-of-00002.safetensors": shard2,
		safetensors.ConfigName:             []byte(`{"architectures":["Qwen3ForCausalLM"],"max_position_embeddings":4096}`),
	})
	t.Setenv("HF_ENDPOINT", hub.URL())
	home := t.TempDir()
	t.Setenv(store.EnvHome, home)

	cmd := newPackCmd(viper.New())
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"hf://org/repo", "-t", "registry.example/llm/tiny-sharded:v1"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("pack exited with an error: %v", err)
	}

	st, err := store.Open(t.Context(), home)
	if err != nil {
		t.Fatal(err)
	}
	desc, err := st.Resolve(t.Context(), "registry.example/llm/tiny-sharded:v1")
	if err != nil {
		t.Fatalf("the packed artifact is not in the store: %v", err)
	}
	manifest, err := store.FetchManifest(t.Context(), st.OCI(), desc)
	if err != nil {
		t.Fatalf("fetching the packed manifest: %v", err)
	}
	names := layerFilepaths(manifest)
	for _, want := range []string{
		"model-00001-of-00002.safetensors",
		"model-00002-of-00002.safetensors",
		safetensors.IndexName,
		safetensors.ConfigName,
	} {
		if !names[want] {
			t.Errorf("packed artifact does not carry %s; layers: %v", want, names)
		}
	}

	// Both names being present is not enough: if the two shards had
	// collapsed onto one file on disk, both layers would carry that one
	// file's digest under their own name and origin annotation, and the
	// assertion above would still pass.
	digests := map[string]digest.Digest{}
	for _, l := range manifest.Layers {
		digests[l.Annotations[modelspec.AnnotationFilepath]] = l.Digest
	}
	d1, d2 := digests["model-00001-of-00002.safetensors"], digests["model-00002-of-00002.safetensors"]
	if d1 == "" || d2 == "" {
		t.Fatalf("could not find both shard layers; layers: %v", names)
	}
	if d1 == d2 {
		t.Errorf("both shards carry digest %s: they collapsed onto one file", d1)
	}
}

// TestRepoFileDirRefusesAPathEscapingItsDirectory: a file's repository-relative
// path is publisher-supplied text arriving from a remote API, and it becomes
// half of a local filesystem path once a directory is laid out per file. An
// absolute path, a ".." component, or a backslash must be refused outright
// rather than joined and hoped clean, the same way gatherSafetensorsShards
// refuses a shard name that is not a plain file beside the index.
func TestRepoFileDirRefusesAPathEscapingItsDirectory(t *testing.T) {
	srcDir := t.TempDir()
	for _, bad := range []string{
		"../evil.bin",
		"a/../../evil.bin",
		"/etc/passwd",
		"a/./b.bin",
		"",
	} {
		_, err := repoFileDir(srcDir, "org/repo", bad)
		if err == nil {
			t.Errorf("repoFileDir(%q) succeeded, want a refusal", bad)
			continue
		}
		if !strings.Contains(err.Error(), "not a path inside the repository") {
			t.Errorf("repoFileDir(%q) error = %q, want it to name the refusal rather than a generic error", bad, err)
		}
	}
}

// TestClaimDestRefusesRepositoryPathsThatResolveToOneFile covers two
// repository paths differing only in case, such as an index naming
// Model-A.safetensors and model-a.safetensors, which a case-insensitive
// filesystem such as APFS or NTFS resolves to one file. Where the
// filesystem folds them itself, writing the first destination already
// creates the second and the condition is the real one; where it does not,
// a hard link stands in, making destB name the exact file destA does.
// Either way claimDest sees two destinations that are one file, which is
// what it must detect regardless of how they got that way.
func TestClaimDestRefusesRepositoryPathsThatResolveToOneFile(t *testing.T) {
	dir := t.TempDir()
	destA := filepath.Join(dir, "Model-A.safetensors")
	destB := filepath.Join(dir, "model-a.safetensors")
	if err := os.WriteFile(destA, []byte("weights"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(destB); os.IsNotExist(err) {
		if err := os.Link(destA, destB); err != nil {
			t.Fatal(err)
		}
	} else if err != nil {
		t.Fatal(err)
	}

	written := map[string]string{destA: "Model-A.safetensors"}
	err := claimDest(written, "org/repo", "model-a.safetensors", destB)
	if err == nil {
		t.Fatal("claimDest succeeded for two paths resolving to one file, want a refusal")
	}
	for _, want := range []string{"Model-A.safetensors", "model-a.safetensors"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to name %q", err, want)
		}
	}
}

// TestClaimDestAllowsDistinctFiles proves claimDest does not refuse two
// repository paths whose destinations are genuinely different files, so the
// collision check above is catching an actual collision and not merely
// refusing a second file on principle. It claims and writes each
// destination in the same order resolveSources does, since claimDest is
// meant to run before the file it guards exists on disk.
func TestClaimDestAllowsDistinctFiles(t *testing.T) {
	dir := t.TempDir()
	destA := filepath.Join(dir, "a.safetensors")
	destB := filepath.Join(dir, "b.safetensors")

	written := map[string]string{}
	if err := claimDest(written, "org/repo", "a.safetensors", destA); err != nil {
		t.Fatalf("claimDest: %v", err)
	}
	if err := os.WriteFile(destA, []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := claimDest(written, "org/repo", "b.safetensors", destB); err != nil {
		t.Fatalf("claimDest: %v", err)
	}
}
