// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package trustpolicy

import "testing"

func TestTheFirstMatchingRuleDecides(t *testing.T) {
	p, err := New([]Rule{
		{Pattern: "registry.example/llm/*", KeyFiles: []string{"/keys/team.pub"}},
		{Pattern: "registry.example/**", KeyFiles: []string{"/keys/house.pub"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	keys, ok := p.KeyFilesFor("registry.example/llm/qwen3")
	if !ok {
		t.Fatal("expected the first rule to match")
	}
	if len(keys) != 1 || keys[0] != "/keys/team.pub" {
		t.Fatalf("KeyFilesFor = %v, want the first matching rule's key", keys)
	}
}

func TestAReferenceOutsideEveryPatternMatchesNothing(t *testing.T) {
	p, err := New([]Rule{
		{Pattern: "registry.example/**", KeyFiles: []string{"/keys/house.pub"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	keys, ok := p.KeyFilesFor("other.example/llm/qwen3")
	if ok {
		t.Fatalf("a reference no rule names must not match, got %v", keys)
	}
}

func TestACatchAllRuleMatchesEveryReference(t *testing.T) {
	p, err := New([]Rule{{Pattern: "**", KeyFiles: []string{"/keys/house.pub"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.KeyFilesFor("other.example/llm/qwen3"); !ok {
		t.Fatal("** must match every reference")
	}
}

func TestARuleNamingNoKeyIsRefusedWhenThePolicyLoads(t *testing.T) {
	if _, err := New([]Rule{{Pattern: "**"}}); err == nil {
		t.Fatal("a rule with no key allows nothing and must be refused on load")
	}
}

func TestPatternsReportsEveryRuleInOrder(t *testing.T) {
	p, err := New([]Rule{
		{Pattern: "registry.example/llm/*", KeyFiles: []string{"/k/a.pub"}},
		{Pattern: "registry.example/**", KeyFiles: []string{"/k/b.pub"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := p.Patterns()
	want := []string{"registry.example/llm/*", "registry.example/**"}
	if len(got) != len(want) {
		t.Fatalf("Patterns() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Patterns()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestAPolicyIsUnaffectedByLaterChangesToTheCallersRules(
	t *testing.T) {
	rules := []Rule{{
		Pattern:  "registry.example/**",
		KeyFiles: []string{"/keys/house.pub"},
	}}
	p, err := New(rules)
	if err != nil {
		t.Fatal(err)
	}

	// Mutate both the outer slice and the inner KeyFiles slice
	rules[0].Pattern = "other.example/**"
	rules[0].KeyFiles[0] = "/keys/attacker.pub"

	// The policy should still work with the original values
	keys, ok := p.KeyFilesFor("registry.example/llm/qwen3")
	if !ok {
		t.Fatal("pattern must still match after mutation")
	}
	if len(keys) != 1 || keys[0] != "/keys/house.pub" {
		t.Fatalf("KeyFilesFor = %v, want [/keys/house.pub]", keys)
	}
}

func TestKeyFilesForDoesNotHandOutThePolicysOwnStorage(t *testing.T) {
	p, err := New([]Rule{
		{Pattern: "registry.example/**",
			KeyFiles: []string{"/keys/original.pub"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Get the keys and mutate them
	keys1, ok := p.KeyFilesFor("registry.example/model")
	if !ok {
		t.Fatal("expected match")
	}
	keys1[0] = "/keys/mutated.pub"

	// A subsequent call should return the original key, not the mutated one
	keys2, ok := p.KeyFilesFor("registry.example/model")
	if !ok {
		t.Fatal("expected match")
	}
	if len(keys2) != 1 || keys2[0] != "/keys/original.pub" {
		t.Fatalf("KeyFilesFor = %v, want [/keys/original.pub]", keys2)
	}
}
