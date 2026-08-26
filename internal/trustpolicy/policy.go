// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package trustpolicy

import "fmt"

// Rule allows the identities it names to sign any reference its pattern
// matches.
type Rule struct {
	Pattern string
	// KeyFiles are paths to public keys. A signature that verifies under any
	// one of them satisfies the rule, so a rotation can list both keys.
	KeyFiles []string
}

// Policy is an ordered list of rules. The first rule whose pattern matches a
// reference decides which identities may sign it, so a narrow rule above a
// broad one wins and the file reads top to bottom.
type Policy struct {
	rules []Rule
}

// New validates rules and returns the policy they describe. A rule naming no
// identity is refused, because an empty allow-list denies every signature
// under its pattern and nobody writes that on purpose. The policy takes its
// own copy of the rules and their key lists; later changes to the caller's
// slices do not affect the policy.
func New(rules []Rule) (*Policy, error) {
	for i, r := range rules {
		if err := ValidatePattern(r.Pattern); err != nil {
			return nil, fmt.Errorf("policy rule %d: %w", i+1, err)
		}
		if len(r.KeyFiles) == 0 {
			return nil, fmt.Errorf("policy rule %d (%s) names no key",
				i+1, r.Pattern)
		}
	}
	out := make([]Rule, 0, len(rules))
	for _, r := range rules {
		out = append(out, Rule{
			Pattern:  r.Pattern,
			KeyFiles: append([]string(nil), r.KeyFiles...),
		})
	}
	return &Policy{rules: out}, nil
}

// KeyFilesFor returns the keys allowed to sign repoRef, and whether any rule
// matched. A miss is a refusal rather than a fallback: a policy is
// configured deliberately, and a pattern typo must not quietly restore the
// single-key behaviour it replaced. The returned slice is the caller's own
// and does not alias the policy's internal storage.
func (p *Policy) KeyFilesFor(repoRef string) ([]string, bool) {
	for _, r := range p.rules {
		if Match(r.Pattern, repoRef) {
			return append([]string(nil), r.KeyFiles...), true
		}
	}
	return nil, false
}

// Patterns returns each rule's pattern in order, so a refusal can tell an
// operator what the policy actually contains.
func (p *Policy) Patterns() []string {
	out := make([]string, 0, len(p.rules))
	for _, r := range p.rules {
		out = append(out, r.Pattern)
	}
	return out
}
