// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"io"
	"strings"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/viper"

	"github.com/aimd54/palan/internal/registrytest"
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
	t.Setenv("PALAN_HOME", t.TempDir())
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
