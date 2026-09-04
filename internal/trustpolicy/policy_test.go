// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package trustpolicy

import "testing"

func TestTheFirstMatchingRuleDecides(t *testing.T) {
	p, err := New([]Rule{
		{Pattern: "registry.example/llm/*", KeyFiles: []string{"/rule.KeyFiles/team.pub"}},
		{Pattern: "registry.example/**", KeyFiles: []string{"/rule.KeyFiles/house.pub"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	rule, ok := p.RuleFor("registry.example/llm/qwen3")
	if !ok {
		t.Fatal("expected the first rule to match")
	}
	if len(rule.KeyFiles) != 1 || rule.KeyFiles[0] != "/rule.KeyFiles/team.pub" {
		t.Fatalf("RuleFor rule.KeyFiles = %v, want the first matching rule's key", rule.KeyFiles)
	}
}

func TestAReferenceOutsideEveryPatternMatchesNothing(t *testing.T) {
	p, err := New([]Rule{
		{Pattern: "registry.example/**", KeyFiles: []string{"/rule.KeyFiles/house.pub"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	rule, ok := p.RuleFor("other.example/llm/qwen3")
	if ok {
		t.Fatalf("a reference no rule names must not match, got %v", rule.KeyFiles)
	}
}

func TestACatchAllRuleMatchesEveryReference(t *testing.T) {
	p, err := New([]Rule{{Pattern: "**", KeyFiles: []string{"/rule.KeyFiles/house.pub"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.RuleFor("other.example/llm/qwen3"); !ok {
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
		KeyFiles: []string{"/rule.KeyFiles/house.pub"},
	}}
	p, err := New(rules)
	if err != nil {
		t.Fatal(err)
	}

	// Mutate both the outer slice and the inner KeyFiles slice
	rules[0].Pattern = "other.example/**"
	rules[0].KeyFiles[0] = "/rule.KeyFiles/attacker.pub"

	// The policy should still work with the original values
	rule, ok := p.RuleFor("registry.example/llm/qwen3")
	if !ok {
		t.Fatal("pattern must still match after mutation")
	}
	if len(rule.KeyFiles) != 1 || rule.KeyFiles[0] != "/rule.KeyFiles/house.pub" {
		t.Fatalf("RuleFor rule.KeyFiles = %v, want [/rule.KeyFiles/house.pub]", rule.KeyFiles)
	}
}

func TestRuleForDoesNotHandOutThePolicysOwnStorage(t *testing.T) {
	p, err := New([]Rule{
		{Pattern: "registry.example/**",
			KeyFiles: []string{"/rule.KeyFiles/original.pub"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Get the rule.KeyFiles and mutate them
	rule1, ok := p.RuleFor("registry.example/model")
	if !ok {
		t.Fatal("expected match")
	}
	rule1.KeyFiles[0] = "/rule.KeyFiles/mutated.pub"

	// A subsequent call should return the original key, not the mutated one
	rule2, ok := p.RuleFor("registry.example/model")
	if !ok {
		t.Fatal("expected match")
	}
	if len(rule2.KeyFiles) != 1 || rule2.KeyFiles[0] != "/rule.KeyFiles/original.pub" {
		t.Fatalf("RuleFor rule.KeyFiles = %v, want [/rule.KeyFiles/original.pub]", rule2.KeyFiles)
	}
}
