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
	"github.com/aimd54/palan/internal/hf/hftest"
	"github.com/aimd54/palan/internal/omsig"
	"github.com/aimd54/palan/internal/refname"
	"github.com/aimd54/palan/internal/registrytest"
	"github.com/aimd54/palan/internal/router"
	"github.com/aimd54/palan/internal/signing"
	"github.com/aimd54/palan/internal/store"
	"github.com/aimd54/palan/internal/transfer"
	"github.com/aimd54/palan/pkg/modelspec"
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

// ggufRepoFiles builds a minimal, genuinely parseable single-file GGUF
// repository, so a pack that reaches pack.Model can actually finish instead
// of failing on unrelated bytes.
func ggufRepoFiles() map[string][]byte {
	return map[string][]byte{
		"model.gguf": gguftest.TinyModel("llama", "tiny", "15M", 2048, 1,
			[]byte("deterministic weights for a source policy test")),
	}
}

// TestPackUnderSourcesPolicyRefusesAnUncoveredFile reaches
// TestPackCommandRefusesAnUncoveredFileWhenOMSKeyIsSetThroughTheFlag's
// refusal through verify.sources instead of the --oms-key flag: no flag is
// passed, and the key comes from a source rule whose pattern matches the
// repository being packed.
func TestPackUnderSourcesPolicyRefusesAnUncoveredFile(t *testing.T) {
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
	t.Setenv(store.EnvHome, t.TempDir())

	keyPath := filepath.Join(t.TempDir(), "key.pub")
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	v := viper.New()
	v.Set(keyVerifySources, []map[string]any{
		{"pattern": "org/**", "oms-key": keyPath},
	})
	cmd := newPackCmd(v)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"hf://org/repo", "-t", "registry.example/llm/tiny:v1"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("pack exited 0 for a repository whose signature does not cover every file, under a source rule naming its key")
	}
	if !strings.Contains(err.Error(), "config.json") {
		t.Errorf("the refusal does not name the uncovered file: %v", err)
	}
	if !errors.Is(err, omsig.ErrNotCovered) {
		t.Errorf("error = %v, want it to wrap omsig.ErrNotCovered, the refusal only a verified path produces", err)
	}
}

// TestPackUnderSourcesPolicyPacksWhenSignatureCoversEveryFile is the pass
// side of the refusal above: the same kind of source rule, over a
// repository whose signature covers every file it publishes, actually
// produces the artifact rather than merely returning no error.
func TestPackUnderSourcesPolicyPacksWhenSignatureCoversEveryFile(t *testing.T) {
	files := ggufRepoFiles()
	keyPEM, bundle := signRepo(t, files, []string{"model.gguf"})
	files[omsig.FileName] = bundle
	hub := hftest.New(t, files)
	t.Setenv("HF_ENDPOINT", hub.URL())
	home := t.TempDir()
	t.Setenv(store.EnvHome, home)

	keyPath := filepath.Join(t.TempDir(), "key.pub")
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	v := viper.New()
	v.Set(keyVerifySources, []map[string]any{
		{"pattern": "org/**", "oms-key": keyPath},
	})
	cmd := newPackCmd(v)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	const ref = "registry.example/llm/tiny:v1"
	cmd.SetArgs([]string{"hf://org/repo/model.gguf", "-t", ref})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("a source rule names the key that signed this repository and pack refused: %v", err)
	}

	st, err := store.Open(t.Context(), home)
	if err != nil {
		t.Fatal(err)
	}
	desc, err := st.Resolve(t.Context(), ref)
	if err != nil {
		t.Fatalf("pack exited 0 but the artifact is not resolvable in the store: %v", err)
	}
	manifest, err := store.FetchManifest(t.Context(), st.OCI(), desc)
	if err != nil {
		t.Fatalf("fetch manifest: %v", err)
	}
	for _, l := range manifest.Layers {
		if _, err := st.BlobPath(l.Digest); err != nil {
			t.Errorf("manifest names layer %s but its blob is not in the store: %v", l.Digest, err)
		}
	}
	want := signerKeyID(t, keyPEM)
	if got := manifest.Annotations[modelspec.AnnotationOriginSigner]; got != want {
		t.Errorf("io.palan.origin.signer = %q, want %q (the key the source rule named)", got, want)
	}
}

// TestPackUnderSourcesPolicyLeavesAnUnmatchedSourceUnchecked proves the
// fallback is scoped to what a rule actually names: a source pattern that
// does not match the repository being packed must leave the import with no
// publisher-signature check at all, the same as when verify.sources is
// unset entirely. The manifest's absent signer annotation is the positive
// state that shows this, not merely the absence of an error.
func TestPackUnderSourcesPolicyLeavesAnUnmatchedSourceUnchecked(t *testing.T) {
	files := ggufRepoFiles()
	hub := hftest.New(t, files)
	t.Setenv("HF_ENDPOINT", hub.URL())
	home := t.TempDir()
	t.Setenv(store.EnvHome, home)

	v := viper.New()
	v.Set(keyVerifySources, []map[string]any{
		{"pattern": "other/**", "oms-key": "/etc/palan/other.pub"},
	})
	cmd := newPackCmd(v)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	const ref = "registry.example/llm/tiny:v1"
	cmd.SetArgs([]string{"hf://org/repo/model.gguf", "-t", ref})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("a source rule that does not match this repository made pack refuse: %v", err)
	}

	st, err := store.Open(t.Context(), home)
	if err != nil {
		t.Fatal(err)
	}
	desc, err := st.Resolve(t.Context(), ref)
	if err != nil {
		t.Fatalf("pack exited 0 but the artifact is not resolvable in the store: %v", err)
	}
	manifest, err := store.FetchManifest(t.Context(), st.OCI(), desc)
	if err != nil {
		t.Fatalf("fetch manifest: %v", err)
	}
	for _, l := range manifest.Layers {
		if _, err := st.BlobPath(l.Digest); err != nil {
			t.Errorf("manifest names layer %s but its blob is not in the store: %v", l.Digest, err)
		}
	}
	if got, ok := manifest.Annotations[modelspec.AnnotationOriginSigner]; ok {
		t.Errorf("io.palan.origin.signer = %q, want no such annotation: no rule named this repository, so nothing checked its publisher signature", got)
	}
	// The absent signer means nothing unless the packer was recording
	// provenance at all, and the upstream digest is what it always records.
	if manifest.Annotations[modelspec.AnnotationOriginSHA256] == "" {
		t.Error("the manifest records no upstream digest, so an absent signer says nothing about whether a signature was checked")
	}
}

// TestPackUnderSourcesPolicyRefusesALocalFileBesideARepository covers the
// mixed argument list: a rule names a key for the repository, and a local
// file sits beside it. The repository's signature covers the files that
// repository published and nothing else, so packing the local file anyway
// would put bytes no signature covers into an artifact whose manifest then
// names the key as having vouched for it.
func TestPackUnderSourcesPolicyRefusesALocalFileBesideARepository(t *testing.T) {
	files := ggufRepoFiles()
	keyPEM, bundle := signRepo(t, files, []string{"model.gguf"})
	files[omsig.FileName] = bundle
	hub := hftest.New(t, files)
	t.Setenv("HF_ENDPOINT", hub.URL())
	home := t.TempDir()
	t.Setenv(store.EnvHome, home)

	keyPath := filepath.Join(t.TempDir(), "key.pub")
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	local := filepath.Join(t.TempDir(), "tokenizer.json")
	if err := os.WriteFile(local, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}

	v := viper.New()
	v.Set(keyVerifySources, []map[string]any{
		{"pattern": "org/**", "oms-key": keyPath},
	})
	cmd := newPackCmd(v)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	const ref = "registry.example/llm/tiny:v1"
	cmd.SetArgs([]string{"hf://org/repo/model.gguf", local, "-t", ref})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("a local file packed beside a repository whose rule names a key")
	}
	if !strings.Contains(err.Error(), "tokenizer.json") {
		t.Errorf("the refusal does not name the local file: %v", err)
	}
	// Nothing may reach the store: an artifact annotated with the key while
	// holding an uncovered file is the outcome being prevented.
	st, err := store.Open(t.Context(), home)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Resolve(t.Context(), ref); err == nil {
		t.Fatal("the refused pack still left a resolvable artifact in the store")
	}
}

// TestPackUnderSourcesPolicyPacksLocalFilesWhenNoRepositoryIsNamed proves
// the refusal above is scoped to a mixed list. A purely local pack consults
// no rule and carries no publisher claim, so a configured policy must leave
// it exactly as it was.
func TestPackUnderSourcesPolicyPacksLocalFilesWhenNoRepositoryIsNamed(t *testing.T) {
	home := t.TempDir()
	t.Setenv(store.EnvHome, home)
	dir := t.TempDir()
	local := filepath.Join(dir, "model.gguf")
	if err := os.WriteFile(local, ggufRepoFiles()["model.gguf"], 0o600); err != nil {
		t.Fatal(err)
	}

	v := viper.New()
	v.Set(keyVerifySources, []map[string]any{
		{"pattern": "org/**", "oms-key": filepath.Join(dir, "absent.pub")},
	})
	cmd := newPackCmd(v)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	const ref = "registry.example/llm/local:v1"
	cmd.SetArgs([]string{local, "-t", ref})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("a purely local pack was refused under a configured policy: %v", err)
	}
	st, err := store.Open(t.Context(), home)
	if err != nil {
		t.Fatal(err)
	}
	desc, err := st.Resolve(t.Context(), ref)
	if err != nil {
		t.Fatalf("pack exited 0 but the artifact is not resolvable: %v", err)
	}
	manifest, err := store.FetchManifest(t.Context(), st.OCI(), desc)
	if err != nil {
		t.Fatal(err)
	}
	if got := manifest.Annotations[modelspec.AnnotationOriginSigner]; got != "" {
		t.Errorf("io.palan.origin.signer = %q on a local pack, want none", got)
	}
}

// TestPackUnderSourcesPolicyPacksAMixedListNoRuleNames proves the refusal
// tracks the key rather than the argument shape: with no rule matching the
// repository, no key is consulted, nothing is vouched for, and a local file
// beside it is as unremarkable as it is with no policy at all.
func TestPackUnderSourcesPolicyPacksAMixedListNoRuleNames(t *testing.T) {
	files := ggufRepoFiles()
	hub := hftest.New(t, files)
	t.Setenv("HF_ENDPOINT", hub.URL())
	home := t.TempDir()
	t.Setenv(store.EnvHome, home)

	dir := t.TempDir()
	local := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(local, []byte("notes"), 0o600); err != nil {
		t.Fatal(err)
	}

	v := viper.New()
	v.Set(keyVerifySources, []map[string]any{
		{"pattern": "other/**", "oms-key": filepath.Join(dir, "absent.pub")},
	})
	cmd := newPackCmd(v)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	const ref = "registry.example/llm/mixed:v1"
	cmd.SetArgs([]string{"hf://org/repo/model.gguf", local, "-t", ref})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("no rule names this repository, so nothing was vouched for and the pack should stand: %v", err)
	}
	st, err := store.Open(t.Context(), home)
	if err != nil {
		t.Fatal(err)
	}
	desc, err := st.Resolve(t.Context(), ref)
	if err != nil {
		t.Fatalf("pack exited 0 but the artifact is not resolvable: %v", err)
	}
	manifest, err := store.FetchManifest(t.Context(), st.OCI(), desc)
	if err != nil {
		t.Fatal(err)
	}
	if got := manifest.Annotations[modelspec.AnnotationOriginSigner]; got != "" {
		t.Errorf("io.palan.origin.signer = %q where no rule matched, want none", got)
	}
}

func TestAnEmptySourcesListIsRefused(t *testing.T) {
	v := viper.New()
	v.Set(keyVerifySources, []map[string]any{})
	if _, err := loadSourcePolicy(v); err == nil {
		t.Fatal("verify.sources set to an empty list must be refused, " +
			"not read as a host that checks nothing")
	}
}

func TestASourceRuleNamingNoKeyIsRefused(t *testing.T) {
	v := viper.New()
	v.Set(keyVerifySources, []map[string]any{{"pattern": "org/**"}})
	if _, err := loadSourcePolicy(v); err == nil {
		t.Fatal("a source rule with no key must be refused at load, " +
			"not ignored at the point it would have been used")
	}
}

func TestASourceRuleWithAnUnusablePatternIsRefused(t *testing.T) {
	for _, pattern := range []string{"", "org//repo", "or**g/**"} {
		v := viper.New()
		v.Set(keyVerifySources, []map[string]any{
			{"pattern": pattern, "oms-key": "/etc/palan/k.pub"},
		})
		if _, err := loadSourcePolicy(v); err == nil {
			t.Errorf("pattern %q must be refused at load", pattern)
		}
	}
}

// TestSourceRulesAreTriedInOrder pins first-match-wins: a narrow rule ahead
// of a broad one keeps its key for what it names, and the broad one covers
// only what the narrow one did not.
func TestSourceRulesAreTriedInOrder(t *testing.T) {
	v := viper.New()
	v.Set(keyVerifySources, []map[string]any{
		{"pattern": "org/tiny", "oms-key": "/etc/palan/narrow.pub"},
		{"pattern": "org/**", "oms-key": "/etc/palan/broad.pub"},
	})
	sp, err := loadSourcePolicy(v)
	if err != nil {
		t.Fatalf("loadSourcePolicy: %v", err)
	}
	for _, tc := range []struct{ repo, want string }{
		{"org/tiny", "/etc/palan/narrow.pub"},
		{"org/other", "/etc/palan/broad.pub"},
	} {
		got, ok := sp.keyFor(tc.repo)
		if !ok || got != tc.want {
			t.Errorf("keyFor(%q) = %q, %v; want %q, true", tc.repo, got, ok, tc.want)
		}
	}
	if got, ok := sp.keyFor("other/tiny"); ok {
		t.Errorf("keyFor(\"other/tiny\") = %q, true; want no rule to name it", got)
	}
}

// TestAPolicyMissRefusesEvenWhenVerifyKeyIsAlsoConfigured is the branch's
// load-bearing property in the one configuration where it can be got wrong:
// a host that sets both. A reference no rule names must refuse because the
// policy governs, not because no key happened to be configured.
func TestAPolicyMissRefusesEvenWhenVerifyKeyIsAlsoConfigured(t *testing.T) {
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

	// verify.key names the very key that signed this model, so a fallback
	// would succeed and be indistinguishable from a policy that allowed it.
	_, err := runVerifyUnderPolicyWithKey(t, ref, []map[string]any{
		{"pattern": reg.Host() + "/other/*", "keys": []string{pubFile}},
	}, pubFile)
	if err == nil {
		t.Fatal("a reference no rule names must refuse; verify.key must not be consulted once a policy is set")
	}
	if !strings.Contains(err.Error(), "trust policy") {
		t.Fatalf("the refusal must name the policy as its cause, not a missing key: %v", err)
	}
}

// TestARuleAcceptsASignatureUnderAnyKeyItNames pins the rotation story: a
// rule naming the outgoing and incoming key must accept either, so the
// second entry is not decoration.
func TestARuleAcceptsASignatureUnderAnyKeyItNames(t *testing.T) {
	reg := registrytest.New(t)
	stalePriv, _ := attestKeypair(t)
	stalePub := attestPubKeyFile(t, stalePriv)
	priv, keyFile := attestKeypair(t)
	pubFile := attestPubKeyFile(t, priv)

	seedModel(t, reg, "llm/qwen3", "v1", []ocispec.Descriptor{
		localLayer([]byte("weights"), "model.gguf"),
	})
	ref := reg.Host() + "/llm/qwen3:v1"
	if err := runSign(t, ref, keyFile); err != nil {
		t.Fatalf("signing the fixture: %v", err)
	}

	// The signing key is listed second, so a loop that stopped at the first
	// key that failed would refuse a model the rule allows.
	out, err := runVerifyUnderPolicy(t, ref, []map[string]any{
		{"pattern": reg.Host() + "/llm/*", "keys": []string{stalePub, pubFile}},
	})
	if err != nil {
		t.Fatalf("a rule naming this key second refused the signature: %v", err)
	}
	if !strings.Contains(out, "Verified") {
		t.Fatalf("verify passed but did not report it: %q", out)
	}
}

// TestAnExplicitKeyOverridesAConfiguredPolicy pins the documented escape
// hatch: a key someone typed wins over the standing configuration, so a
// reference the policy does not name still verifies under it.
func TestAnExplicitKeyOverridesAConfiguredPolicy(t *testing.T) {
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

	t.Setenv("PALAN_HOME", t.TempDir())
	v := viper.New()
	v.Set(keyRegistryPlainHTTP, true)
	// A policy that names no rule for this reference: without --key it refuses.
	v.Set(keyVerifyPolicy, []map[string]any{
		{"pattern": reg.Host() + "/other/*", "keys": []string{pubFile}},
	})
	cmd := newVerifyCmd(v)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{ref, "--key", pubFile})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("an explicit key must override the policy for that invocation: %v", err)
	}
	if !strings.Contains(out.String(), "Verified") {
		t.Fatalf("verify passed but did not report it: %q", out.String())
	}
}

// TestPackUnderSourcesPolicyRefusesAListItCoversOnlyInPart covers a list
// holding a repository a rule names and one no rule names. One artifact
// records one signer, so packing both would annotate the whole of it as
// vouched for by a key that never saw the second repository's files.
func TestPackUnderSourcesPolicyRefusesAListItCoversOnlyInPart(t *testing.T) {
	files := ggufRepoFiles()
	keyPEM, bundle := signRepo(t, files, []string{"model.gguf"})
	files[omsig.FileName] = bundle
	hub := hftest.New(t, files)
	t.Setenv("HF_ENDPOINT", hub.URL())
	home := t.TempDir()
	t.Setenv(store.EnvHome, home)

	keyPath := filepath.Join(t.TempDir(), "key.pub")
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	v := viper.New()
	v.Set(keyVerifySources, []map[string]any{
		{"pattern": "org/repo", "oms-key": keyPath},
	})
	cmd := newPackCmd(v)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	const ref = "registry.example/llm/mixed:v1"
	cmd.SetArgs([]string{
		"hf://org/repo/model.gguf", "hf://org/unruled/model.gguf", "-t", ref,
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("a list a rule covers only in part must refuse, not vouch for the whole of it")
	}
	if !strings.Contains(err.Error(), "org/unruled") {
		t.Errorf("the refusal does not name the repository no rule covers: %v", err)
	}
	st, oerr := store.Open(t.Context(), home)
	if oerr != nil {
		t.Fatal(oerr)
	}
	if _, err := st.Resolve(t.Context(), ref); err == nil {
		t.Fatal("the refused pack still left a resolvable artifact in the store")
	}
}

// TestPackUnderSourcesPolicyRefusesRulesNamingDifferentKeyFiles covers two
// repositories each named by a rule, but by a different key file. The
// artifact records one signer, so the annotation would name only whichever
// was resolved last. The comparison is between the paths a rule names, not
// between the bytes they hold, which is why this fixture writes the same key
// under two names and still expects a refusal: two files are two claims
// until something proves otherwise.
func TestPackUnderSourcesPolicyRefusesRulesNamingDifferentKeyFiles(t *testing.T) {
	files := ggufRepoFiles()
	keyPEM, bundle := signRepo(t, files, []string{"model.gguf"})
	files[omsig.FileName] = bundle
	hub := hftest.New(t, files)
	t.Setenv("HF_ENDPOINT", hub.URL())
	home := t.TempDir()
	t.Setenv(store.EnvHome, home)

	dir := t.TempDir()
	first := filepath.Join(dir, "first.pub")
	second := filepath.Join(dir, "second.pub")
	for _, f := range []string{first, second} {
		if err := os.WriteFile(f, keyPEM, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	v := viper.New()
	v.Set(keyVerifySources, []map[string]any{
		{"pattern": "org/repo", "oms-key": first},
		{"pattern": "org/other", "oms-key": second},
	})
	cmd := newPackCmd(v)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	const ref = "registry.example/llm/two:v1"
	cmd.SetArgs([]string{
		"hf://org/repo/model.gguf", "hf://org/other/model.gguf", "-t", ref,
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("two rules naming different keys must refuse: one artifact records one signer")
	}
	if !strings.Contains(err.Error(), "org/repo") || !strings.Contains(err.Error(), "org/other") {
		t.Errorf("the refusal should name both repositories: %v", err)
	}
	st, oerr := store.Open(t.Context(), home)
	if oerr != nil {
		t.Fatal(oerr)
	}
	if _, err := st.Resolve(t.Context(), ref); err == nil {
		t.Fatal("the refused pack still left a resolvable artifact in the store")
	}
}

// TestPackUnderSourcesPolicySaysWhetherItChecked pins the reporting. A rule
// that matches and one that matches nothing otherwise produce identical
// output, so a pattern with a typo in it would disable the check on a host
// that looks configured and leave no trace of having done so.
func TestPackUnderSourcesPolicySaysWhetherItChecked(t *testing.T) {
	files := ggufRepoFiles()
	keyPEM, bundle := signRepo(t, files, []string{"model.gguf"})
	files[omsig.FileName] = bundle
	keyPath := filepath.Join(t.TempDir(), "key.pub")
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name    string
		pattern string
		want    string
		absent  string
	}{
		{
			name:    "a rule that matches",
			pattern: "org/**",
			want:    "Holding every fetched file",
			absent:  "No source rule names",
		},
		{
			name:    "a rule that matches nothing",
			pattern: "elsewhere/**",
			want:    "No source rule names",
			absent:  "Holding every fetched file",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hub := hftest.New(t, files)
			t.Setenv("HF_ENDPOINT", hub.URL())
			t.Setenv(store.EnvHome, t.TempDir())

			v := viper.New()
			v.Set(keyVerifySources, []map[string]any{
				{"pattern": tc.pattern, "oms-key": keyPath},
			})
			cmd := newPackCmd(v)
			var errOut bytes.Buffer
			cmd.SetOut(io.Discard)
			cmd.SetErr(&errOut)
			cmd.SetArgs([]string{"hf://org/repo/model.gguf", "-t", "registry.example/llm/tiny:v1"})
			if err := cmd.Execute(); err != nil {
				t.Fatalf("pack: %v", err)
			}
			if !strings.Contains(errOut.String(), tc.want) {
				t.Errorf("the import does not say what it did, want %q in:\n%s", tc.want, errOut.String())
			}
			if strings.Contains(errOut.String(), tc.absent) {
				t.Errorf("the import reports the other outcome too, %q in:\n%s", tc.absent, errOut.String())
			}
			if tc.want == "Holding every fetched file" && !strings.Contains(errOut.String(), keyPath) {
				t.Errorf("the import does not name the key it checked with:\n%s", errOut.String())
			}
		})
	}
}

// TestARuleCanNameAKeylessIdentity covers the shape M11 adds: a signer
// named by who they are rather than by a key file, with the trusted root
// the certificate is held against.
func TestARuleCanNameAKeylessIdentity(t *testing.T) {
	v := viper.New()
	v.Set(keyVerifyPolicy, []map[string]any{{
		"pattern":    "registry.example/llm/**",
		"trust-root": "/etc/palan/sigstore-root.json",
		"identities": []map[string]any{{
			"subject": "https://forge.example/org/repo/.github/workflows/release.yml@refs/tags/*",
			"issuer":  "https://token.forge.example",
		}},
	}})

	p, err := loadPolicy(v)
	if err != nil {
		t.Fatal(err)
	}
	rule, ok := p.RuleFor("registry.example/llm/qwen3")
	if !ok {
		t.Fatal("the rule does not match the reference it names")
	}
	if rule.TrustRoot != "/etc/palan/sigstore-root.json" {
		t.Errorf("trust root = %q, want the configured path", rule.TrustRoot)
	}
	if len(rule.Identities) != 1 {
		t.Fatalf("the rule carries %d identities, want 1", len(rule.Identities))
	}
	if got := rule.Identities[0].Issuer; got != "https://token.forge.example" {
		t.Errorf("issuer = %q, want the configured provider", got)
	}
}

// TestARuleMayNameBothAKeyAndAnIdentity is what a migration looks like from
// the inside: signatures made either way are accepted while publishers move
// from one to the other.
func TestARuleMayNameBothAKeyAndAnIdentity(t *testing.T) {
	v := viper.New()
	v.Set(keyVerifyPolicy, []map[string]any{{
		"pattern":    "registry.example/**",
		"keys":       []string{"/keys/team.pub"},
		"trust-root": "/etc/palan/sigstore-root.json",
		"identities": []map[string]any{{
			"subject": "release@example.com",
			"issuer":  "https://token.forge.example",
		}},
	}})

	p, err := loadPolicy(v)
	if err != nil {
		t.Fatal(err)
	}
	rule, ok := p.RuleFor("registry.example/llm/qwen3")
	if !ok {
		t.Fatal("the rule does not match the reference it names")
	}
	if len(rule.KeyFiles) != 1 || len(rule.Identities) != 1 {
		t.Fatalf("rule carries %d keys and %d identities, want one of each",
			len(rule.KeyFiles), len(rule.Identities))
	}
}

// TestAKeylessRuleWithNoTrustRootIsRefused: without a pinned root there is
// nothing to check a certificate against, so the rule could never admit
// anything and would refuse for a reason pointing at the signature.
func TestAKeylessRuleWithNoTrustRootIsRefused(t *testing.T) {
	v := viper.New()
	v.Set(keyVerifyPolicy, []map[string]any{{
		"pattern": "registry.example/**",
		"identities": []map[string]any{{
			"subject": "release@example.com",
			"issuer":  "https://token.forge.example",
		}},
	}})

	_, err := loadPolicy(v)
	if err == nil {
		t.Fatal("a keyless rule with no trust root loaded")
	}
	if !strings.Contains(err.Error(), "trust-root") {
		t.Errorf("refusal does not name what is missing: %v", err)
	}
}

// TestATrustRootWithNoIdentityIsRefused catches the other half-finished
// edit, where somebody pins a root and believes it is doing something.
func TestATrustRootWithNoIdentityIsRefused(t *testing.T) {
	v := viper.New()
	v.Set(keyVerifyPolicy, []map[string]any{{
		"pattern":    "registry.example/**",
		"keys":       []string{"/keys/team.pub"},
		"trust-root": "/etc/palan/sigstore-root.json",
	}})

	_, err := loadPolicy(v)
	if err == nil {
		t.Fatal("a trust root that nothing reads loaded")
	}
	if !strings.Contains(err.Error(), "nothing would be checked") {
		t.Errorf("refusal does not say the root is unread: %v", err)
	}
}

// TestARuleNamingNeitherIsRefused keeps the empty allow-list refusal that
// predates keyless identities, now that a rule has two ways to name a
// signer and could satisfy neither.
func TestARuleNamingNeitherIsRefused(t *testing.T) {
	v := viper.New()
	v.Set(keyVerifyPolicy, []map[string]any{
		{"pattern": "registry.example/**"},
	})

	_, err := loadPolicy(v)
	if err == nil {
		t.Fatal("a rule naming no signer at all loaded")
	}
	if !strings.Contains(err.Error(), "neither a key nor an identity") {
		t.Errorf("refusal does not say what is missing: %v", err)
	}
}

// TestAnIdentityMatchingEverySignerIsRefusedAtLoad reports the pattern
// somebody writes to make a refusal go away when the config is read, rather
// than at the moment a signature is checked against it.
func TestAnIdentityMatchingEverySignerIsRefusedAtLoad(t *testing.T) {
	v := viper.New()
	v.Set(keyVerifyPolicy, []map[string]any{{
		"pattern":    "registry.example/**",
		"trust-root": "/etc/palan/sigstore-root.json",
		"identities": []map[string]any{{
			"subject": "*",
			"issuer":  "https://token.forge.example",
		}},
	}})

	if _, err := loadPolicy(v); err == nil {
		t.Fatal("an identity matching every signer loaded")
	}
}

// TestAnIdentityWithNoIssuerIsRefused: a subject is a name any provider can
// mint, so one without the provider that asserted it is not an identity.
func TestAnIdentityWithNoIssuerIsRefused(t *testing.T) {
	v := viper.New()
	v.Set(keyVerifyPolicy, []map[string]any{{
		"pattern":    "registry.example/**",
		"trust-root": "/etc/palan/sigstore-root.json",
		"identities": []map[string]any{{"subject": "release@example.com"}},
	}})

	_, err := loadPolicy(v)
	if err == nil {
		t.Fatal("an identity with no issuer loaded")
	}
	if !strings.Contains(err.Error(), "issuer") {
		t.Errorf("refusal does not name what is missing: %v", err)
	}
}
