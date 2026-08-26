// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package trustpolicy

import "testing"

func TestMatchHoldsAStarInsideOneSegment(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"registry.example/llm/*", "registry.example/llm/qwen3", true},
		{"registry.example/llm/*", "registry.example/llm/team/qwen3", false},
		{"registry.example/**", "registry.example/llm/team/qwen3", true},
		{"registry.example/**", "registry.example", true},
		{"**", "registry.example/llm/qwen3", true},
		{"registry.example/llm/qwen*", "registry.example/llm/qwen3", true},
		{"registry.example/llm/qwen*", "registry.example/llm/llama3", false},
		{"other.example/**", "registry.example/llm/qwen3", false},
		{"registry.example/llm/qwen3", "registry.example/llm/qwen3", true},
		{"registry.example/llm/qwen3", "registry.example/llm/qwen3x", false},
	}
	for _, c := range cases {
		if got := Match(c.pattern, c.name); got != c.want {
			t.Errorf("Match(%q, %q) = %v, want %v", c.pattern, c.name, got, c.want)
		}
	}
}

func TestValidatePatternRefusesWhatCannotMatch(t *testing.T) {
	for _, bad := range []string{"", "registry.example//llm", "registry.example/a**b"} {
		if err := ValidatePattern(bad); err == nil {
			t.Errorf("ValidatePattern(%q) accepted a pattern that cannot be meant", bad)
		}
	}
	for _, good := range []string{"**", "registry.example/**", "registry.example/llm/*"} {
		if err := ValidatePattern(good); err != nil {
			t.Errorf("ValidatePattern(%q) = %v, want nil", good, err)
		}
	}
}
