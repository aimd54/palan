// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package refname

import (
	"strings"
	"testing"
)

// FuzzParse exercises reference normalization. Every CLI argument naming a
// model reaches Parse, so it must never panic on hostile or malformed input,
// and a successful parse must be fully qualified: callers build registry
// URLs from the result.
func FuzzParse(f *testing.F) {
	f.Add("llm/qwen3:8b-q4", "registry.example")
	f.Add("localhost:5000/llm/model:tag", "")
	f.Add("registry.example/repo@sha256:"+strings.Repeat("a", 64), "")
	f.Add("", "")
	f.Add("UPPERCASE/Repo:Tag", "registry.example")
	f.Add("///", "registry.example")
	f.Add(":", ":")

	f.Fuzz(func(t *testing.T, raw, defaultRegistry string) {
		ref, err := Parse(raw, defaultRegistry)
		if err != nil {
			return // rejecting bad input is the expected outcome
		}
		if ref.Registry == "" {
			t.Fatalf("Parse(%q, %q) succeeded with no registry host", raw, defaultRegistry)
		}
		if ref.Repository == "" {
			t.Fatalf("Parse(%q, %q) succeeded with no repository", raw, defaultRegistry)
		}
		if ref.Reference == "" {
			t.Fatalf("Parse(%q, %q) succeeded with neither tag nor digest", raw, defaultRegistry)
		}
	})
}
