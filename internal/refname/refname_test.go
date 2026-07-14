// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package refname

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	cases := []struct {
		raw, def string
		want     string // expected ref.String(); "" means error expected
	}{
		{"registry.internal/llm/qwen3:8b-q4", "", "registry.internal/llm/qwen3:8b-q4"},
		{"localhost:5000/llm/tiny:v1", "", "localhost:5000/llm/tiny:v1"},
		{"llm/qwen3:8b-q4", "registry.internal", "registry.internal/llm/qwen3:8b-q4"},
		{"llm/qwen3", "registry.internal", "registry.internal/llm/qwen3:latest"},
		{"registry.internal/llm/qwen3", "", "registry.internal/llm/qwen3:latest"},
		{"llm/qwen3:8b-q4", "", ""},            // no host, no default
		{"", "registry.internal", ""},          // empty
		{"UPPER/x:y", "registry.internal", ""}, // invalid repo name
		{
			"registry.internal/llm/qwen3@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			"",
			"registry.internal/llm/qwen3@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
	}
	for _, c := range cases {
		ref, err := Parse(c.raw, c.def)
		if c.want == "" {
			if err == nil {
				t.Errorf("Parse(%q, %q): expected error, got %q", c.raw, c.def, ref.String())
			}
			continue
		}
		if err != nil {
			t.Errorf("Parse(%q, %q): %v", c.raw, c.def, err)
			continue
		}
		if got := ref.String(); got != c.want {
			t.Errorf("Parse(%q, %q) = %q, want %q", c.raw, c.def, got, c.want)
		}
	}
}

func TestParseLowercaseHint(t *testing.T) {
	_, err := Parse("localhost:5000/llm/Gemma-3-1B", "")
	if err == nil {
		t.Fatal("expected error for uppercase repository")
	}
	if !strings.Contains(err.Error(), "lowercase") {
		t.Errorf("error should hint at lowercase repositories: %v", err)
	}

	_, err = Parse("registry.internal/llm/foo bar", "")
	if err == nil {
		t.Fatal("expected error for repository with a space")
	}
	if strings.Contains(err.Error(), "lowercase") {
		t.Errorf("hint should not fire when lowercasing does not fix the reference: %v", err)
	}
}
