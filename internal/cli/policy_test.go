// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"io"
	"strings"
	"testing"

	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/spf13/viper"
	"oras.land/oras-go/v2/content"

	"github.com/aimd54/palan/internal/attest"
	"github.com/aimd54/palan/internal/refname"
	"github.com/aimd54/palan/internal/registrytest"
	"github.com/aimd54/palan/internal/signing"
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

// TestAValidKeyThePolicyDoesNotNameForThatReferenceRefuses is the milestone's
// acceptance criterion. One signature, two policies: it passes under the
// pattern that names its key and refuses under the one that does not, so the
// refusal is the policy's doing and not a broken signature.
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

// TestAPolicyWithNoVerifyKeySucceedsForAnAttestedArtifact is the
// availability regression this task closes: a host that has moved to
// verify.policy and left verify.key entirely unset must still verify an
// artifact carrying a source attestation, rather than refuse every such
// artifact with "no verification key configured".
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
