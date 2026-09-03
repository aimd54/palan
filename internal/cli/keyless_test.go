// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/viper"
	oras "oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/aimd54/palan/internal/keyless/keylesstest"
	"github.com/aimd54/palan/internal/refname"
	"github.com/aimd54/palan/internal/registrytest"
	"github.com/aimd54/palan/internal/signing"
	"github.com/aimd54/palan/internal/store"
)

const bundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"

var keylessSigner = keylesstest.Signer{
	Subject: "https://forge.example/org/models/.github/workflows/release.yml@refs/tags/v2.0.0",
	Issuer:  "https://token.forge.example",
}

// attachBundle publishes a keyless signature the way a signing tool does:
// as a referrer of the model with no tag of its own, so the test exercises
// the discovery path a real bundle arrives by rather than a tag palan
// invented for its own store.
func attachBundle(t *testing.T, repo *remote.Repository, subject ocispec.Descriptor, bundleJSON []byte) {
	t.Helper()
	ctx := context.Background()

	cfg := []byte("{}")
	cfgDesc := content.NewDescriptorFromBytes(ocispec.MediaTypeImageConfig, cfg)
	pushBlob(t, repo, cfgDesc, cfg)
	blobDesc := content.NewDescriptorFromBytes(bundleMediaType, bundleJSON)
	pushBlob(t, repo, blobDesc, bundleJSON)

	manifest := ocispec.Manifest{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: bundleMediaType,
		Config:       cfgDesc,
		Layers:       []ocispec.Descriptor{blobDesc},
		Subject:      &subject,
	}
	manifest.SchemaVersion = 2
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	mDesc := content.NewDescriptorFromBytes(manifest.MediaType, raw)
	mDesc.ArtifactType = manifest.ArtifactType
	if err := repo.Manifests().Push(ctx, mDesc, bytes.NewReader(raw)); err != nil {
		t.Fatalf("attaching the keyless signature: %v", err)
	}
}

func pushBlob(t *testing.T, repo *remote.Repository, desc ocispec.Descriptor, data []byte) {
	t.Helper()
	if err := repo.Blobs().Push(context.Background(), desc, bytes.NewReader(data)); err != nil {
		t.Fatalf("pushing %s: %v", desc.MediaType, err)
	}
}

// writeTrustRoot puts a log's pinned material on disk, which is where a
// policy names it.
func writeTrustRoot(t *testing.T, l *keylesstest.Log) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "trusted-root.json")
	if err := os.WriteFile(path, l.TrustedRoot, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// keylessPolicy is the config a host verifying keyless signatures carries:
// a pattern, the identities allowed under it, and the root they are checked
// against.
func keylessPolicy(host, trustRoot, subject, issuer string) []map[string]any {
	return []map[string]any{{
		"pattern":    host + "/**",
		"trust-root": trustRoot,
		"identities": []map[string]any{{"subject": subject, "issuer": issuer}},
	}}
}

// seedKeylessModel plants a model on reg and attaches a keyless signature
// over it, returning the reference and the log that signed it.
func seedKeylessModel(t *testing.T, reg *registrytest.Registry, layers []ocispec.Descriptor) (string, *keylesstest.Log) {
	t.Helper()
	desc := seedModel(t, reg, "llm/qwen3", "v1", layers)
	l := keylesstest.NewLog(t)
	attachBundle(t, attestTestRepo(t, reg, "llm/qwen3"), desc,
		l.Bundle(t, desc.Digest, keylessSigner))
	return reg.Host() + "/llm/qwen3:v1", l
}

// TestVerifyAcceptsAKeylessSignature is the milestone's claim end to end: a
// signature carrying its own certificate and inclusion proof, checked
// against a root pinned in the policy, with no certificate authority and no
// transparency log reached.
func TestVerifyAcceptsAKeylessSignature(t *testing.T) {
	reg := registrytest.New(t)
	weights := []byte("weights signed without a key")
	reg.PutBlob("llm/qwen3", weights)
	ref, l := seedKeylessModel(t, reg, []ocispec.Descriptor{localLayer(weights, "model.gguf")})

	out, err := runVerifyUnderPolicy(t, ref, keylessPolicy(
		reg.Host(), writeTrustRoot(t, l), keylessSigner.Subject, keylessSigner.Issuer))
	if err != nil {
		t.Fatalf("verifying a keyless signature: %v", err)
	}
	// The identity is reported rather than merely accepted: it is the one
	// thing a keyless verification learns that the config did not already
	// state, and an operator reading the output needs to see who signed.
	if !strings.Contains(out, keylessSigner.Subject) {
		t.Errorf("verify output = %q, want it to name the signer", out)
	}
	if !strings.Contains(out, keylessSigner.Issuer) {
		t.Errorf("verify output = %q, want it to name the issuer", out)
	}
}

// TestVerifyRefusesAKeylessSignatureWithNoInclusionProof is the milestone's
// other half. Everything else about the signature is intact, so what is
// under test is whether proof of being logged is required at all.
func TestVerifyRefusesAKeylessSignatureWithNoInclusionProof(t *testing.T) {
	reg := registrytest.New(t)
	desc := seedModel(t, reg, "llm/qwen3", "v1",
		[]ocispec.Descriptor{localLayer([]byte("weights"), "model.gguf")})
	l := keylesstest.NewLog(t)

	full := l.Bundle(t, desc.Digest, keylessSigner)
	var parsed map[string]any
	if err := json.Unmarshal(full, &parsed); err != nil {
		t.Fatal(err)
	}
	entry := parsed["verificationMaterial"].(map[string]any)["tlogEntries"].([]any)[0].(map[string]any)
	delete(entry, "inclusionProof")
	stripped, err := json.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	attachBundle(t, attestTestRepo(t, reg, "llm/qwen3"), desc, stripped)

	_, err = runVerifyUnderPolicy(t, reg.Host()+"/llm/qwen3:v1", keylessPolicy(
		reg.Host(), writeTrustRoot(t, l), keylessSigner.Subject, keylessSigner.Issuer))
	if err == nil {
		t.Fatal("a keyless signature with no inclusion proof verified")
	}
	if !strings.Contains(err.Error(), "no offline evidence") {
		t.Errorf("refusal does not say what is missing: %v", err)
	}
}

// TestVerifyRefusesAKeylessSignerNoRuleNames holds the policy half at the
// command level, not just inside the verifying package.
func TestVerifyRefusesAKeylessSignerNoRuleNames(t *testing.T) {
	reg := registrytest.New(t)
	ref, l := seedKeylessModel(t, reg,
		[]ocispec.Descriptor{localLayer([]byte("weights"), "model.gguf")})

	_, err := runVerifyUnderPolicy(t, ref, keylessPolicy(
		reg.Host(), writeTrustRoot(t, l),
		"https://forge.example/someone/else/.github/workflows/release.yml@refs/tags/*",
		keylessSigner.Issuer))
	if err == nil {
		t.Fatal("a keyless signature from an unnamed identity verified")
	}
	if !strings.Contains(err.Error(), keylessSigner.Subject) {
		t.Errorf("refusal does not name who actually signed: %v", err)
	}
}

// TestAPulledKeylessSignatureVerifiesWithTheRegistryGone is what "carried
// material" has to mean. The registry is closed before verification, so
// anything still reaching for it fails here, and the model can only be
// verified from what pull brought into the store.
func TestAPulledKeylessSignatureVerifiesWithTheRegistryGone(t *testing.T) {
	reg := registrytest.New(t)
	weights := []byte("weights that must verify after the registry is gone")
	reg.PutBlob("llm/qwen3", weights)
	ref, l := seedKeylessModel(t, reg, []ocispec.Descriptor{localLayer(weights, "model.gguf")})

	home := t.TempDir()
	rules := keylessPolicy(reg.Host(), writeTrustRoot(t, l),
		keylessSigner.Subject, keylessSigner.Issuer)
	if err := runPullUnderPolicy(t, home, ref, rules); err != nil {
		t.Fatalf("pulling under a keyless policy: %v", err)
	}

	// Asserted before the registry goes away, because "the store holds it"
	// is the claim, and a verification that happens to succeed would not
	// distinguish a stored bundle from a cached descriptor.
	assertStoreHoldsBundle(t, home, ref)

	reg.Close()
	out, err := runVerifyUnderPolicyInHome(t, home, ref, rules)
	if err != nil {
		t.Fatalf("verifying from the store with no registry: %v", err)
	}
	if !strings.Contains(out, "source: local store") {
		t.Errorf("verify output = %q, want it to name the local store", out)
	}
	if !strings.Contains(out, keylessSigner.Subject) {
		t.Errorf("verify output = %q, want it to name the signer", out)
	}
}

// assertStoreHoldsBundle checks the store for the keyless signature itself
// rather than for a successful command, since a command can succeed by
// reaching the registry it was supposed to have stopped needing.
func assertStoreHoldsBundle(t *testing.T, home, ref string) {
	t.Helper()
	t.Setenv("PALAN_HOME", home)
	ctx := context.Background()
	st, err := store.Open(ctx, "")
	if err != nil {
		t.Fatalf("opening the store: %v", err)
	}
	desc, err := st.Resolve(ctx, ref)
	if err != nil {
		t.Fatalf("the store does not hold %s: %v", ref, err)
	}
	parsed := mustParseRef(t, ref)
	bundleRef := signing.BundleRef(parsed, desc.Digest)
	bundleDesc, err := st.Resolve(ctx, bundleRef)
	if err != nil {
		t.Fatalf("the store does not hold the keyless signature %s: %v", bundleRef, err)
	}
	raw, err := content.FetchAll(ctx, st.OCI(), bundleDesc)
	if err != nil {
		t.Fatalf("reading the stored keyless signature: %v", err)
	}
	var man ocispec.Manifest
	if err := json.Unmarshal(raw, &man); err != nil {
		t.Fatal(err)
	}
	if man.Subject == nil || man.Subject.Digest != desc.Digest {
		t.Fatalf("the stored keyless signature does not name %s as its subject", desc.Digest)
	}
	// The bundle's own bytes have to be present, not merely its manifest:
	// a manifest whose layer never arrived verifies nothing.
	for _, layer := range man.Layers {
		if _, err := content.FetchAll(ctx, st.OCI(), layer); err != nil {
			t.Fatalf("the stored keyless signature is missing its %s layer: %v", layer.MediaType, err)
		}
	}
}

// TestSaveAndLoadCarryAKeylessSignature is the air gap: everything needed to
// check the signature has to fit in the tar, since the far side has no
// registry at all.
func TestSaveAndLoadCarryAKeylessSignature(t *testing.T) {
	reg := registrytest.New(t)
	weights := []byte("weights crossing a gap")
	reg.PutBlob("llm/qwen3", weights)
	ref, l := seedKeylessModel(t, reg, []ocispec.Descriptor{localLayer(weights, "model.gguf")})

	rules := keylessPolicy(reg.Host(), writeTrustRoot(t, l),
		keylessSigner.Subject, keylessSigner.Issuer)
	source := t.TempDir()
	if err := runPullUnderPolicy(t, source, ref, rules); err != nil {
		t.Fatalf("pulling under a keyless policy: %v", err)
	}

	var tar bytes.Buffer
	saveFromHome(t, source, ref, &tar)

	reg.Close()
	far := t.TempDir()
	if err := runLoadUnderPolicyInHome(t, far, tar.Bytes(), rules); err != nil {
		t.Fatalf("loading under a keyless policy with no registry: %v", err)
	}
	assertStoreHoldsBundle(t, far, ref)
}

// TestLoadRefusesAKeylessSignatureBelongingToNoModel keeps the import guard
// covering the shape this milestone adds. A bundle is whatever a courier
// handed over, so a reference merely shaped like a keyless signature must
// not be waved past the check that every model verified.
func TestLoadRefusesAKeylessSignatureBelongingToNoModel(t *testing.T) {
	reg := registrytest.New(t)
	weights := []byte("weights smuggled under a keyless-shaped tag")
	reg.PutBlob("llm/qwen3", weights)
	ref, l := seedKeylessModel(t, reg, []ocispec.Descriptor{localLayer(weights, "model.gguf")})

	rules := keylessPolicy(reg.Host(), writeTrustRoot(t, l),
		keylessSigner.Subject, keylessSigner.Issuer)
	source := t.TempDir()
	if err := runPullUnderPolicy(t, source, ref, rules); err != nil {
		t.Fatalf("pulling under a keyless policy: %v", err)
	}

	// A second model, unsigned, tagged as though it were the keyless
	// signature of something. Nothing verified it, so nothing may import it.
	smuggled := reg.Host() + "/llm/qwen3:" +
		signing.BundleTag(digest.FromString("a digest naming no model in this bundle"))
	tagInStore(t, source, ref, smuggled)

	var tar bytes.Buffer
	saveFromHome(t, source, ref, &tar, smuggled)

	reg.Close()
	err := runLoadUnderPolicyInHome(t, t.TempDir(), tar.Bytes(), rules)
	if err == nil {
		t.Fatal("a keyless-shaped reference belonging to no verified model imported")
	}
	if !strings.Contains(err.Error(), "not the keyless signature of any verified model") {
		t.Errorf("refusal does not name the smuggled reference: %v", err)
	}
}

// runVerifyUnderPolicyInHome is runVerifyUnderPolicy against an existing
// store rather than an empty one, which is the only way to ask whether a
// pulled artifact verifies from what pull actually left behind.
func runVerifyUnderPolicyInHome(
	t *testing.T, home, ref string, rules []map[string]any,
) (string, error) {
	t.Helper()
	t.Setenv("PALAN_HOME", home)
	v := viper.New()
	v.Set(keyRegistryPlainHTTP, true)
	v.Set(keyVerifyPolicy, rules)
	cmd := newVerifyCmd(v)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{ref})
	err := cmd.Execute()
	return out.String(), err
}

// runLoadUnderPolicyInHome is runLoadUnderPolicy against a named home, so a
// test can look at what the import left in the store.
func runLoadUnderPolicyInHome(t *testing.T, home string, tar []byte, rules []map[string]any) error {
	t.Helper()
	t.Setenv("PALAN_HOME", home)
	v := viper.New()
	v.Set(keyRegistryPlainHTTP, true)
	v.Set(keyVerifyRequired, true)
	v.Set(keyVerifyPolicy, rules)
	cmd := newLoadCmd(v)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetIn(bytes.NewReader(tar))
	cmd.SetArgs([]string{"-i", "-"})
	return cmd.Execute()
}

// saveFromHome exports refs out of an existing store through the real save
// command, so the tar under test is the one an operator would carry.
func saveFromHome(t *testing.T, home, ref string, w io.Writer, extra ...string) {
	t.Helper()
	t.Setenv("PALAN_HOME", home)
	out := filepath.Join(t.TempDir(), "bundle.tar")
	cmd := newSaveCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(append(append([]string{ref}, extra...), "-o", out))
	if err := cmd.Execute(); err != nil {
		t.Fatalf("saving: %v", err)
	}
	f, err := os.Open(out) // #nosec G304 -- test-owned path
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := io.Copy(w, f); err != nil {
		t.Fatal(err)
	}
}

// tagInStore gives an existing artifact a second name, which is how a test
// plants a reference shaped like a signature without signing anything.
func tagInStore(t *testing.T, home, ref, as string) {
	t.Helper()
	t.Setenv("PALAN_HOME", home)
	ctx := context.Background()
	st, err := store.Open(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := st.Lock(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, err := oras.Copy(ctx, st.OCI(), ref, st.OCI(), as, oras.DefaultCopyOptions); err != nil {
		t.Fatalf("tagging %s as %s: %v", ref, as, err)
	}
}

// mustParseRef parses a reference the way the commands do.
func mustParseRef(t *testing.T, ref string) registry.Reference {
	t.Helper()
	parsed, err := refname.Parse(ref, "")
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

// TestAnUntaggedBundleInTheStoreVerifiesOffline covers a keyless signature
// that reached the store without palan's tag on it.
//
// The store is a plain OCI layout so that other OCI tooling can work on it,
// which means a bundle can be attached there by something that knows only
// the subject relationship and nothing about palan's naming. Looking only
// under palan's own tag would send such a host to a registry for a
// signature already on its disk, and on a disconnected one that is a
// refusal.
func TestAnUntaggedBundleInTheStoreVerifiesOffline(t *testing.T) {
	reg := registrytest.New(t)
	weights := []byte("weights whose keyless signature carries no palan tag")
	reg.PutBlob("llm/qwen3", weights)
	ref, l := seedKeylessModel(t, reg, []ocispec.Descriptor{localLayer(weights, "model.gguf")})

	home := t.TempDir()
	rules := keylessPolicy(reg.Host(), writeTrustRoot(t, l),
		keylessSigner.Subject, keylessSigner.Issuer)
	if err := runPullUnderPolicy(t, home, ref, rules); err != nil {
		t.Fatalf("pulling under a keyless policy: %v", err)
	}
	untagBundle(t, home, ref)

	reg.Close()
	out, err := runVerifyUnderPolicyInHome(t, home, ref, rules)
	if err != nil {
		t.Fatalf("verifying an untagged bundle with no registry: %v", err)
	}
	if !strings.Contains(out, "source: local store") {
		t.Errorf("verify output = %q, want it to name the local store", out)
	}
}

// untagBundle removes palan's tag from a stored keyless signature, leaving
// the manifest and its subject in place. That is the state a bundle written
// by another OCI tool arrives in.
func untagBundle(t *testing.T, home, ref string) {
	t.Helper()
	t.Setenv("PALAN_HOME", home)
	ctx := context.Background()
	st, err := store.Open(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := st.Lock(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	desc, err := st.Resolve(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	bundleRef := signing.BundleRef(mustParseRef(t, ref), desc.Digest)
	if err := st.OCI().Untag(ctx, bundleRef); err != nil {
		t.Fatalf("untagging %s: %v", bundleRef, err)
	}
	// Asserted, because a test that silently kept the tag would be
	// exercising the tagged path it means to avoid.
	if _, err := st.Resolve(ctx, bundleRef); err == nil {
		t.Fatalf("%s is still tagged, so this test would not reach the referrer path", bundleRef)
	}
}
