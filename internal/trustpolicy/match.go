// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

// Package trustpolicy decides which identities are allowed to sign which
// references. It holds no keys and opens no files: it answers questions
// about names, so it needs neither a registry nor a keyring to test. A rule
// names key files and keyless identities; reading either is somebody
// else's job.
package trustpolicy

import (
	"fmt"
	"strings"
)

// Match reports whether name satisfies pattern.
//
// A pattern is a slash-separated glob over a repository reference such as
// "registry.example/llm/qwen3". Within a segment "*" matches any run of
// characters that does not cross a slash; a segment of "**" matches any
// number of segments including none. Everything else is literal.
func Match(pattern, name string) bool {
	return matchSegments(strings.Split(pattern, "/"),
		strings.Split(name, "/"))
}

func matchSegments(pat, name []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			// "**" may swallow any number of segments, so every split has to
			// be tried before the pattern can be called a miss.
			for i := 0; i <= len(name); i++ {
				if matchSegments(pat[1:], name[i:]) {
					return true
				}
			}
			return false
		}
		if len(name) == 0 || !matchSegment(pat[0], name[0]) {
			return false
		}
		pat, name = pat[1:], name[1:]
	}
	return len(name) == 0
}

// matchSegment matches one segment, where "*" stands for any run of
// characters that does not cross a slash.
func matchSegment(pat, s string) bool {
	parts := strings.Split(pat, "*")
	if len(parts) == 1 {
		return pat == s
	}
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	for _, part := range parts[1 : len(parts)-1] {
		i := strings.Index(s, part)
		if i < 0 {
			return false
		}
		s = s[i+len(part):]
	}
	return strings.HasSuffix(s, parts[len(parts)-1])
}

// ValidatePattern refuses a pattern that cannot match anything, so a typo is
// reported when the policy loads rather than as a verification that finds no
// rule and refuses for a reason nobody can see.
func ValidatePattern(pattern string) error {
	if pattern == "" {
		return fmt.Errorf("pattern is empty")
	}
	doubleStar := 0
	for _, seg := range strings.Split(pattern, "/") {
		if seg == "" {
			return fmt.Errorf("pattern %q has an empty segment", pattern)
		}
		if strings.Contains(seg, "**") && seg != "**" {
			return fmt.Errorf("pattern %q: ** must stand alone as a segment",
				pattern)
		}
		if seg == "**" {
			doubleStar++
		}
	}
	if doubleStar > 4 {
		return fmt.Errorf("pattern %q has more than 4 ** segments to prevent "+
			"exponential backtracking during matching", pattern)
	}
	return nil
}
