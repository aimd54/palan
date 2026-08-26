// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"testing"

	"github.com/spf13/viper"
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
