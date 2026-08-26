// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/spf13/viper"
	oras "oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"

	"github.com/aimd54/palan/internal/attest"
	"github.com/aimd54/palan/internal/gguf/gguftest"
	"github.com/aimd54/palan/internal/refname"
	"github.com/aimd54/palan/internal/registrytest"
	"github.com/aimd54/palan/internal/router"
	"github.com/aimd54/palan/internal/signing"
	"github.com/aimd54/palan/internal/store"
	"github.com/aimd54/palan/internal/transfer"
)

func TestNoPolicyConfiguredLeavesVerifyKeyInCharge(t *testing.T) {
	v := viper.New()
	v.Set(keyVerifyKey, "/keys/only.pub")
	p, err := loadPolicy(v)
	if err != nil {
		t.Fatal(err)
	}
	if p != nil {
		t.Fatal("a config with no verify.policy must produce no policy")
	}
}

func TestAConfiguredPolicyDecodesItsRulesInOrder(t *testing.T) {
	v := viper.New()
	v.Set(keyVerifyPolicy, []map[string]any{
		{"pattern": "registry.example/llm/*", "keys": []string{"/keys/team.pub"}},
		{"pattern": "registry.example/**", "keys": []string{"/keys/house.pub"}},
	})
	p, err := loadPolicy(v)
	if err != nil {
		t.Fatal(err)
	}
	if p == nil {
		t.Fatal("verify.policy was set and produced no policy")
	}
	keys, ok := p.KeyFilesFor("registry.example/llm/qwen3")
	if !ok || len(keys) != 1 || keys[0] != "/keys/team.pub" {
		t.Fatalf("KeyFilesFor = %v (matched %v), want the first rule's key", keys, ok)
	}
}

func TestAnEmptyPolicyListIsRefused(t *testing.T) {
	v := viper.New()
	v.Set(keyVerifyPolicy, []map[string]any{})
	if _, err := loadPolicy(v); err == nil {
		t.Fatal("verify.policy set to an empty list must be refused, " +
			"not silently deny all")
	}
}

// runVerifyUnderPolicy executes verify with a policy in the config and no
// --key flag, which is how a policy-governed host runs it.
func runVerifyUnderPolicy(
	t *testing.T, ref string, rules []map[string]any,
) (string, error) {
	t.Helper()
	return runVerifyUnderPolicyWithKey(t, ref, rules, "")
}

// runVerifyUnderPolicyWithKey is runVerifyUnderPolicy plus a verify.key left
// set in the config alongside the policy, for tests exercising a host that
// added a policy without removing an old verify.key line. keyPath == ""
// leaves verify.key unset, exactly as runVerifyUnderPolicy does.
func runVerifyUnderPolicyWithKey(
	t *testing.T, ref string, rules []map[string]any, keyPath string,
) (string, error) {
	t.Helper()
	t.Setenv("PALAN_HOME", t.TempDir())
	v := viper.New()
	v.Set(keyRegistryPlainHTTP, true)
	v.Set(keyVerifyPolicy, rules)
	if keyPath != "" {
		v.Set(keyVerifyKey, keyPath)
	}
	cmd := newVerifyCmd(v)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{ref})
	err := cmd.Execute()
	return out.String(), err
}

// TestAValidKeyThePolicyDoesNotNameForThatReferenceRefuses pins the core
// behaviour a trust policy exists to provide: a signature that is
// genuinely valid still refuses when no rule names the key for this
// reference. One signature, two policies: it passes under the pattern that
// names its key and refuses under the one that does not, so the refusal is
// the policy's doing and not a broken signature.
func TestAValidKeyThePolicyDoesNotNameForThatReferenceRefuses(t *testing.T) {
	reg := registrytest.New(t)
	priv, keyFile := attestKeypair(t)
	pubFile := attestPubKeyFile(t, priv)

	seedModel(t, reg, "llm/qwen3", "v1", []ocispec.Descriptor{
		localLayer([]byte("weights"), "model.gguf"),
	})
	ref := reg.Host() + "/llm/qwen3:v1"
	if err := runSign(t, ref, keyFile); err != nil {
		t.Fatalf("signing the fixture: %v", err)
	}

	out, err := runVerifyUnderPolicy(t, ref, []map[string]any{
		{"pattern": reg.Host() + "/llm/*", "keys": []string{pubFile}},
	})
	if err != nil {
		t.Fatalf(
			"the policy names this key for this reference and it refused: %v",
			err)
	}
	if !strings.Contains(out, "Verified") {
		t.Fatalf("verify passed but did not report it: %q", out)
	}

	_, err = runVerifyUnderPolicy(t, ref, []map[string]any{
		{"pattern": reg.Host() + "/other/*", "keys": []string{pubFile}},
	})
	if err == nil {
		t.Fatal("a reference no rule names must refuse, not fall back to the key")
	}
	if !strings.Contains(err.Error(), "policy") {
		t.Fatalf("the refusal must say the policy caused it, got: %v", err)
	}
}

// TestAnAttestationSignedByADifferentAllowedKeyRefuses pins the binding
// between the two claims. Both keys are named by the policy, so each object
// verifies on its own; what must refuse is the pair, because an artifact
// whose signature and whose provenance were vouched for by different
// identities has had neither vouch for the whole.
//
// Signing again with a second key would only overwrite the first
// attestation, leaving a matched pair that proves nothing about this case,
// so the mismatch is built directly: key A signs and attests, then an
// envelope signed by key B is pushed over the same subject, leaving A's
// signature beside B's attestation.
func TestAnAttestationSignedByADifferentAllowedKeyRefuses(t *testing.T) {
	reg := registrytest.New(t)
	privA, keyFileA := attestKeypair(t)
	privB, _ := attestKeypair(t)
	pubA := attestPubKeyFile(t, privA)
	pubB := attestPubKeyFile(t, privB)

	seedModel(t, reg, "llm/qwen3", "v1", []ocispec.Descriptor{
		sourceLayer([]byte("weights"), "Qwen/Qwen3-8B", "model.gguf", "abc123",
			digest.FromBytes([]byte("weights")).Encoded()),
	})
	ref := reg.Host() + "/llm/qwen3:v1"

	if err := runSign(t, ref, keyFileA); err != nil {
		t.Fatalf("signing with key A: %v", err)
	}

	// Overwrite the attestation with one signed by key B, over the same
	// subject, leaving key A's signature untouched.
	ctx := context.Background()
	parsed, err := refname.Parse(ref, "")
	if err != nil {
		t.Fatal(err)
	}
	repo := attestTestRepo(t, reg, "llm/qwen3")
	desc, err := repo.Resolve(ctx, parsed.Reference)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := content.FetchAll(ctx, repo, desc)
	if err != nil {
		t.Fatal(err)
	}
	var man ocispec.Manifest
	if err := json.Unmarshal(raw, &man); err != nil {
		t.Fatal(err)
	}
	layers := signing.LayersFromManifest(man)
	signerB, err := signature.LoadSigner(privB, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	envelopeB, err := attest.Build(desc, layers, signerB)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signing.PushAttestation(ctx, repo, desc, envelopeB); err != nil {
		t.Fatal(err)
	}

	// verify.key is set to key B's public half alongside the policy. Pinning
	// the mismatch needs this: the policy alone accepts the signature under
	// key A and reaches checkAttestation regardless of which key it later
	// checks the attestation against, so a verify.key left unset would make
	// this refuse for the unrelated reason Test B exists to close, not for
	// the identity mismatch this test is about. With verify.key naming B,
	// the pre-fix code's own policy-blind path finds a key that happens to
	// match the attestation it is holding and wrongly accepts the pair.
	_, err = runVerifyUnderPolicyWithKey(t, ref, []map[string]any{
		{"pattern": reg.Host() + "/**", "keys": []string{pubA, pubB}},
	}, pubB)
	if err == nil {
		t.Fatal("a signature and an attestation from different identities must refuse")
	}
	// The refusal must name its actual cause. Asserting only that it
	// refused would keep passing if this verify.key-plus-policy setup ever
	// stopped reaching checkAttestation at all, at which point the test
	// would no longer exercise the identity mismatch it exists to catch.
	if !strings.Contains(err.Error(), "attestation verification FAILED") {
		t.Fatalf("the refusal must come from attestation verification, got: %v", err)
	}
}

// TestAPolicyWithNoVerifyKeySucceedsForAnAttestedArtifact guards an
// availability regression: a host that has moved to verify.policy and left
// verify.key entirely unset must still verify an artifact carrying a
// source attestation, rather than refuse every such artifact with "no
// verification key configured".
func TestAPolicyWithNoVerifyKeySucceedsForAnAttestedArtifact(t *testing.T) {
	reg := registrytest.New(t)
	priv, keyFile := attestKeypair(t)
	pubFile := attestPubKeyFile(t, priv)

	seedModel(t, reg, "llm/qwen3", "v1", []ocispec.Descriptor{
		sourceLayer([]byte("weights"), "Qwen/Qwen3-8B", "model.gguf", "abc123",
			digest.FromBytes([]byte("weights")).Encoded()),
	})
	ref := reg.Host() + "/llm/qwen3:v1"
	if err := runSign(t, ref, keyFile); err != nil {
		t.Fatalf("signing the fixture: %v", err)
	}

	// runVerifyUnderPolicy never sets verify.key and passes no --key flag,
	// which is exactly the configuration this regression breaks.
	out, err := runVerifyUnderPolicy(t, ref, []map[string]any{
		{"pattern": reg.Host() + "/**", "keys": []string{pubFile}},
	})
	if err != nil {
		t.Fatalf(
			"a policy naming the signing key, with verify.key unset, must succeed: %v",
			err)
	}
	want := "provenance: Qwen/Qwen3-8B@abc123"
	if !strings.Contains(out, want) {
		t.Errorf("verify output = %q, want it to contain %q", out, want)
	}
}

// The four tests below prove that a configured policy actually governs pull,
// load, run and serve, not merely that their code happens to call the same
// function verify does. Each is run against a pattern that names the signing
// key for the reference under test (must pass) and against one that does not
// (must refuse), so the outcome is shown to track the policy rather than
// something else about the fixture.
//
// A refusal and a success both leave a command exiting non-zero look
// identical if the check is "did it error". What actually matters is
// whether any of the artifact's bytes were used before the refusal, so
// each test inspects the store (or the object a caller would have gone on
// to use) instead of stopping at the returned error.

// runPullUnderPolicy runs the real pull command against home, the way a
// policy-governed host would: verify.required set, no --key flag, no --verify
// flag, and no pre-existing config beyond the policy under test.
func runPullUnderPolicy(t *testing.T, home, ref string, rules []map[string]any) error {
	t.Helper()
	t.Setenv("PALAN_HOME", home)
	v := viper.New()
	v.Set(keyRegistryPlainHTTP, true)
	v.Set(keyVerifyRequired, true)
	v.Set(keyVerifyPolicy, rules)
	cmd := newPullCmd(v)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{ref})
	return cmd.Execute()
}

// TestPullRefusesBeforeAnyWeightByteMovesUnderPolicy checks the store rather
// than the error, because a pull that refuses after writing blobs and a pull
// that refuses before writing any both return a non-nil error. Only the
// store's own contents say which one actually happened.
func TestPullRefusesBeforeAnyWeightByteMovesUnderPolicy(t *testing.T) {
	reg := registrytest.New(t)
	priv, keyFile := attestKeypair(t)
	pubFile := attestPubKeyFile(t, priv)
	weights := []byte("weights that must not land under a refusing policy")
	reg.PutBlob("llm/qwen3", weights)
	layer := localLayer(weights, "model.gguf")
	seedModel(t, reg, "llm/qwen3", "v1", []ocispec.Descriptor{layer})
	ref := reg.Host() + "/llm/qwen3:v1"
	if err := runSign(t, ref, keyFile); err != nil {
		t.Fatalf("signing the fixture: %v", err)
	}

	// A policy naming the signing key for this repository: pull must
	// succeed, and the weight blob must actually be in the store.
	matchHome := t.TempDir()
	if err := runPullUnderPolicy(t, matchHome, ref, []map[string]any{
		{"pattern": reg.Host() + "/llm/*", "keys": []string{pubFile}},
	}); err != nil {
		t.Fatalf("the policy names this key for this reference and pull refused: %v", err)
	}
	matched, err := store.Open(context.Background(), matchHome)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := matched.BlobPath(layer.Digest); err != nil {
		t.Fatalf("pull succeeded under a matching policy but the weight blob is not in the store: %v", err)
	}

	// The same key, but a pattern naming a different repository: pull must
	// refuse, and the store it refused into must hold nothing.
	refuseHome := t.TempDir()
	err = runPullUnderPolicy(t, refuseHome, ref, []map[string]any{
		{"pattern": reg.Host() + "/other/*", "keys": []string{pubFile}},
	})
	if err == nil {
		t.Fatal("a reference no rule names must refuse, not pull unchecked")
	}
	refused, err := store.Open(context.Background(), refuseHome)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := refused.BlobPath(layer.Digest); err == nil {
		t.Fatal("the store holds the weight blob after a refusal under policy")
	}
}

// bundleTarForRef builds the tar a real `palan save` would write for ref: a
// source store holding the model and its signature, exported through
// transfer.Save exactly as the save command does. Building it this way
// rather than assembling an OCI layout by hand is what makes the load test
// below exercise the same bundle format save actually produces.
func bundleTarForRef(t *testing.T, reg *registrytest.Registry, ref string) []byte {
	t.Helper()
	ctx := context.Background()
	parsed, err := refname.Parse(ref, "")
	if err != nil {
		t.Fatal(err)
	}
	src, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	repo := attestTestRepo(t, reg, parsed.Repository)
	if _, err := oras.Copy(ctx, repo, parsed.Reference, src.OCI(), parsed.String(), oras.DefaultCopyOptions); err != nil {
		t.Fatalf("copying the model into the source store: %v", err)
	}
	mDesc, err := src.Resolve(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	sigRef := signing.SigRef(parsed, mDesc.Digest)
	if _, err := oras.Copy(ctx, repo, signing.SigTag(mDesc.Digest), src.OCI(), sigRef, oras.DefaultCopyOptions); err != nil {
		t.Fatalf("copying the signature into the source store: %v", err)
	}
	var buf bytes.Buffer
	if _, err := transfer.Save(ctx, src, []string{ref}, &buf); err != nil {
		t.Fatalf("saving the bundle: %v", err)
	}
	return buf.Bytes()
}

// runLoadUnderPolicy runs the real load command against home, reading bundle
// from stdin so the test never depends on a bundle file left on disk.
func runLoadUnderPolicy(t *testing.T, home string, bundle []byte, rules []map[string]any) error {
	t.Helper()
	t.Setenv("PALAN_HOME", home)
	v := viper.New()
	v.Set(keyRegistryPlainHTTP, true)
	v.Set(keyVerifyRequired, true)
	v.Set(keyVerifyPolicy, rules)
	cmd := newLoadCmd(v)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetIn(bytes.NewReader(bundle))
	cmd.SetArgs([]string{"-i", "-"})
	return cmd.Execute()
}

// TestLoadImportsNothingUnderPolicy is load's counterpart to the pull test
// above: the bundle's own layout is checked before any of it reaches the
// store (bundleVerifier's doc comment says as much), and this test is what
// holds that claim to the store's actual contents rather than to the error
// load returns.
func TestLoadImportsNothingUnderPolicy(t *testing.T) {
	reg := registrytest.New(t)
	priv, keyFile := attestKeypair(t)
	pubFile := attestPubKeyFile(t, priv)
	weights := []byte("weights that must not import under a refusing policy")
	reg.PutBlob("llm/qwen3", weights)
	layer := localLayer(weights, "model.gguf")
	seedModel(t, reg, "llm/qwen3", "v1", []ocispec.Descriptor{layer})
	ref := reg.Host() + "/llm/qwen3:v1"
	if err := runSign(t, ref, keyFile); err != nil {
		t.Fatalf("signing the fixture: %v", err)
	}
	bundle := bundleTarForRef(t, reg, ref)

	// A policy naming the signing key for this repository: load must
	// succeed, and the weight blob must actually land in the store.
	matchHome := t.TempDir()
	if err := runLoadUnderPolicy(t, matchHome, bundle, []map[string]any{
		{"pattern": reg.Host() + "/llm/*", "keys": []string{pubFile}},
	}); err != nil {
		t.Fatalf("the policy names this key for this bundle and load refused: %v", err)
	}
	matched, err := store.Open(context.Background(), matchHome)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := matched.BlobPath(layer.Digest); err != nil {
		t.Fatalf("load succeeded under a matching policy but the weight blob is not in the store: %v", err)
	}

	// The same key, but a pattern naming a different repository: load must
	// refuse, and the destination store must hold nothing at all, not just
	// be missing this one reference.
	refuseHome := t.TempDir()
	err = runLoadUnderPolicy(t, refuseHome, bundle, []map[string]any{
		{"pattern": reg.Host() + "/other/*", "keys": []string{pubFile}},
	})
	if err == nil {
		t.Fatal("a bundle no rule names must refuse, not import unchecked")
	}
	refused, err := store.Open(context.Background(), refuseHome)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := refused.BlobPath(layer.Digest); err == nil {
		t.Fatal("the store holds the weight blob after a refused load")
	}
	entries, err := refused.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("the store holds %d entries after a refused load, want none", len(entries))
	}
}

// TestRunRefusesAModelAlreadyInTheStoreUnderPolicy seeds the local store
// with the model and its signature before the command ever runs, the way an
// earlier successful pull would leave it. An empty store would refuse for
// the unrelated reason that there is nothing to run, which would say
// nothing about whether run's own policy check works; seeding first forces
// the command to reach that check on a model already sitting there to use.
//
// runtime.ref is pointed at an artifact that does not exist. Resolving it
// fails by a route with nothing to do with verification, so a run that gets
// past the policy gate fails there instead, and its error names the runtime
// reference rather than the policy. That gives the two outcomes distinct,
// checkable shapes without needing a real llama-server in the test
// environment.
func TestRunRefusesAModelAlreadyInTheStoreUnderPolicy(t *testing.T) {
	reg := registrytest.New(t)
	priv, keyFile := attestKeypair(t)
	pubFile := attestPubKeyFile(t, priv)
	weights := gguftest.TinyModel("llama", "tiny", "15M", 2048, 15,
		[]byte("weights already resident when run loads them"))
	reg.PutBlob("llm/qwen3", weights)
	seedModel(t, reg, "llm/qwen3", "v1", []ocispec.Descriptor{localLayer(weights, "model.gguf")})
	ref := reg.Host() + "/llm/qwen3:v1"
	if err := runSign(t, ref, keyFile); err != nil {
		t.Fatalf("signing the fixture: %v", err)
	}
	parsed, err := refname.Parse(ref, "")
	if err != nil {
		t.Fatal(err)
	}

	home := t.TempDir()
	t.Setenv("PALAN_HOME", home)
	ctx := context.Background()
	st, err := store.Open(ctx, home)
	if err != nil {
		t.Fatal(err)
	}
	repo := attestTestRepo(t, reg, "llm/qwen3")
	if _, err := oras.Copy(ctx, repo, parsed.Reference, st.OCI(), parsed.String(), oras.DefaultCopyOptions); err != nil {
		t.Fatalf("seeding the local store with the model: %v", err)
	}
	mDesc, err := st.Resolve(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	sigRef := signing.SigRef(parsed, mDesc.Digest)
	if _, err := oras.Copy(ctx, repo, signing.SigTag(mDesc.Digest), st.OCI(), sigRef, oras.DefaultCopyOptions); err != nil {
		t.Fatalf("seeding the local store with the signature: %v", err)
	}

	const bogusRuntime = "llm/no-such-runtime:v1"

	matching := viper.New()
	matching.Set(keyRegistryPlainHTTP, true)
	matching.Set(keyVerifyRequired, true)
	matching.Set(keyRuntimeRef, bogusRuntime)
	matching.Set(keyVerifyPolicy, []map[string]any{
		{"pattern": reg.Host() + "/llm/*", "keys": []string{pubFile}},
	})
	cmd := newRunCmd(matching)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{ref})
	if err := cmd.Execute(); err == nil {
		t.Fatal("run was pointed at a runtime that does not exist; it must have failed somewhere")
	} else {
		if !strings.Contains(err.Error(), bogusRuntime) {
			t.Fatalf("the policy names this key for this reference, so run should have "+
				"reached runtime resolution and failed on %q; got: %v", bogusRuntime, err)
		}
		if strings.Contains(err.Error(), "policy") {
			t.Fatalf("run refused at the policy gate despite a matching policy: %v", err)
		}
	}

	refusing := viper.New()
	refusing.Set(keyRegistryPlainHTTP, true)
	refusing.Set(keyVerifyRequired, true)
	refusing.Set(keyRuntimeRef, bogusRuntime)
	refusing.Set(keyVerifyPolicy, []map[string]any{
		{"pattern": reg.Host() + "/other/*", "keys": []string{pubFile}},
	})
	cmd = newRunCmd(refusing)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{ref})
	err = cmd.Execute()
	if err == nil {
		t.Fatal("a reference no rule names must refuse, not run the already-resident model")
	}
	if !strings.Contains(err.Error(), "policy") {
		t.Fatalf("the refusal must say the policy caused it, got: %v", err)
	}
	if strings.Contains(err.Error(), bogusRuntime) {
		t.Fatalf("run reached runtime resolution despite a policy refusal: %v", err)
	}

	// Positive state: the model the gate stood in front of is exactly what
	// was there before either run, untouched by a refusal that landed in
	// front of it rather than after it was already loaded.
	after, err := st.Resolve(ctx, ref)
	if err != nil {
		t.Fatalf("the model is gone from the store after a policy refusal: %v", err)
	}
	if after.Digest != mDesc.Digest {
		t.Fatalf("the store's copy of %s changed after a policy refusal: %s vs %s", ref, after.Digest, mDesc.Digest)
	}
}

// TestRunRefusesBeforeFetchingUnderPolicy starts from an empty store, unlike
// the test above. With the model already resident, ensureModel never fetches
// anything, so moving the gate below ensureModel would still leave that test
// green even though run.go's own comment claims the gate runs "before
// anything is fetched or spawned". Starting empty is what actually holds
// that ordering to account: a non-matching policy must refuse before the
// registry is ever asked for the model, leaving the store's blob directory
// empty, and a matching policy must let the fetch happen and only then run
// into the runtime that does not exist.
func TestRunRefusesBeforeFetchingUnderPolicy(t *testing.T) {
	reg := registrytest.New(t)
	priv, keyFile := attestKeypair(t)
	pubFile := attestPubKeyFile(t, priv)
	weights := gguftest.TinyModel("llama", "tiny", "15M", 2048, 15,
		[]byte("weights nothing has fetched yet"))
	reg.PutBlob("llm/qwen3", weights)
	layer := localLayer(weights, "model.gguf")
	seedModel(t, reg, "llm/qwen3", "v1", []ocispec.Descriptor{layer})
	ref := reg.Host() + "/llm/qwen3:v1"
	if err := runSign(t, ref, keyFile); err != nil {
		t.Fatalf("signing the fixture: %v", err)
	}

	const bogusRuntime = "llm/no-such-runtime:v1"

	// A pattern naming a different repository: run must refuse before the
	// registry is ever asked for the model, so a store that started empty
	// must still be empty.
	refuseHome := t.TempDir()
	t.Setenv("PALAN_HOME", refuseHome)
	refusing := viper.New()
	refusing.Set(keyRegistryPlainHTTP, true)
	refusing.Set(keyVerifyRequired, true)
	refusing.Set(keyRuntimeRef, bogusRuntime)
	refusing.Set(keyVerifyPolicy, []map[string]any{
		{"pattern": reg.Host() + "/other/*", "keys": []string{pubFile}},
	})
	cmd := newRunCmd(refusing)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{ref})
	if err := cmd.Execute(); err == nil {
		t.Fatal("a reference no rule names must refuse, not fetch the model first")
	} else if !strings.Contains(err.Error(), "policy") {
		t.Fatalf("the refusal must say the policy caused it, got: %v", err)
	}
	blobsDir := filepath.Join(refuseHome, "blobs", "sha256")
	switch entries, err := os.ReadDir(blobsDir); {
	case err == nil:
		if len(entries) > 0 {
			t.Fatalf("a refused run fetched %d blob(s) before refusing", len(entries))
		}
	case os.IsNotExist(err):
		// A store that never fetched anything may never have created the
		// blob directory at all, which is the same "nothing fetched" result.
	default:
		t.Fatalf("reading %s: %v", blobsDir, err)
	}

	// The same key, naming this repository: run gets past the gate, fetches
	// the model into the (still empty until now) store, and only then fails
	// on the runtime artifact that does not exist.
	matchHome := t.TempDir()
	t.Setenv("PALAN_HOME", matchHome)
	matching := viper.New()
	matching.Set(keyRegistryPlainHTTP, true)
	matching.Set(keyVerifyRequired, true)
	matching.Set(keyRuntimeRef, bogusRuntime)
	matching.Set(keyVerifyPolicy, []map[string]any{
		{"pattern": reg.Host() + "/llm/*", "keys": []string{pubFile}},
	})
	cmd = newRunCmd(matching)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{ref})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("run was pointed at a runtime that does not exist; it must have failed somewhere")
	}
	if !strings.Contains(err.Error(), bogusRuntime) {
		t.Fatalf("the policy names this key for this reference, so run should have "+
			"fetched the model and failed on runtime resolution instead; got: %v", err)
	}
	matched, err := store.Open(context.Background(), matchHome)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := matched.BlobPath(layer.Digest); err != nil {
		t.Fatalf("run got past the policy but the model was never fetched into the store: %v", err)
	}
}

// TestServeRefusesAModelAlreadyInTheStoreUnderPolicy exercises storeBackend
// directly rather than the full serve command. serve resolves a runtime
// binary unconditionally before a single request is ever routed, and doing
// that without depending on whatever the test environment happens to have
// in PATH would need its own fake runtime artifact; storeBackend.Spec is
// the actual code the router calls each time a model is about to be
// loaded (see its gate field's own comment: "runs once per load"), so
// calling it directly still exercises serve's real gate wiring.
//
// The store already holds the model and its signature before Spec is ever
// called, for the same reason run's test seeds first: an empty store would
// refuse regardless of policy, which would prove nothing.
func TestServeRefusesAModelAlreadyInTheStoreUnderPolicy(t *testing.T) {
	reg := registrytest.New(t)
	priv, keyFile := attestKeypair(t)
	pubFile := attestPubKeyFile(t, priv)
	weights := gguftest.TinyModel("llama", "tiny", "15M", 2048, 15,
		[]byte("weights already resident when serve loads them"))
	reg.PutBlob("llm/qwen3", weights)
	seedModel(t, reg, "llm/qwen3", "v1", []ocispec.Descriptor{localLayer(weights, "model.gguf")})
	ref := reg.Host() + "/llm/qwen3:v1"
	if err := runSign(t, ref, keyFile); err != nil {
		t.Fatalf("signing the fixture: %v", err)
	}
	parsed, err := refname.Parse(ref, "")
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	repo := attestTestRepo(t, reg, "llm/qwen3")
	if _, err := oras.Copy(ctx, repo, parsed.Reference, st.OCI(), parsed.String(), oras.DefaultCopyOptions); err != nil {
		t.Fatalf("seeding the local store with the model: %v", err)
	}
	mDesc, err := st.Resolve(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	sigRef := signing.SigRef(parsed, mDesc.Digest)
	if _, err := oras.Copy(ctx, repo, signing.SigTag(mDesc.Digest), st.OCI(), sigRef, oras.DefaultCopyOptions); err != nil {
		t.Fatalf("seeding the local store with the signature: %v", err)
	}

	matching := viper.New()
	matching.Set(keyRegistryPlainHTTP, true)
	matching.Set(keyVerifyRequired, true)
	matching.Set(keyVerifyPolicy, []map[string]any{
		{"pattern": reg.Host() + "/llm/*", "keys": []string{pubFile}},
	})
	matchBackend := &storeBackend{st: st, bin: "irrelevant-to-this-test", logDir: t.TempDir(), gate: verifyGate(matching, st, false, "")}
	spec, _, err := matchBackend.Spec(ctx, ref)
	if err != nil {
		t.Fatalf("the policy names this key for this reference and serve refused: %v", err)
	}
	got, err := os.ReadFile(spec.ModelPath)
	if err != nil {
		t.Fatalf("serve returned a spec but its weight file is unreadable: %v", err)
	}
	if string(got) != string(weights) {
		t.Fatalf("serve resolved a weight file whose bytes do not match the model in the store")
	}

	refusing := viper.New()
	refusing.Set(keyRegistryPlainHTTP, true)
	refusing.Set(keyVerifyRequired, true)
	refusing.Set(keyVerifyPolicy, []map[string]any{
		{"pattern": reg.Host() + "/other/*", "keys": []string{pubFile}},
	})
	refuseBackend := &storeBackend{st: st, bin: "irrelevant-to-this-test", logDir: t.TempDir(), gate: verifyGate(refusing, st, false, "")}
	spec, _, err = refuseBackend.Spec(ctx, ref)
	if err == nil {
		t.Fatal("a reference no rule names must refuse, not hand back a loadable spec")
	}
	if !errors.Is(err, router.ErrUnverified) {
		t.Fatalf("a policy refusal must be reported as ErrUnverified, so callers see 403 rather than 404 or 500: %v", err)
	}
	// Positive state: no path to real weight bytes came back with the
	// refusal. A caller that checked only the error and then used the spec
	// anyway would still load nothing, because there is nothing here to use.
	if spec.ModelPath != "" || spec.Bin != "" {
		t.Fatalf("serve returned a usable spec alongside a refusal: %+v", spec)
	}
}
