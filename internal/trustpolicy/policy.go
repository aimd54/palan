// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package trustpolicy

import (
	"fmt"

	"github.com/aimd54/palan/internal/keyless"
)

// Rule allows the identities it names to sign any reference its pattern
// matches.
//
// A rule may name keys, keyless identities, or both. Both is what a
// migration looks like from the inside: signatures made either way are
// accepted while publishers move from one to the other, and the rule
// narrows again when they have.
type Rule struct {
	Pattern string
	// KeyFiles are paths to public keys. A signature that verifies under any
	// one of them satisfies the rule, so a rotation can list both keys.
	KeyFiles []string
	// Identities are keyless signers, named by who they are rather than by
	// a key file. A keyless signature carries its own certificate, so the
	// rule names the holder and the provider that authenticated them.
	Identities []keyless.Identity
	// TrustRoot is the path to the Sigstore trusted root that Identities
	// are checked against: which certificate authorities may issue, and
	// which transparency logs are believed. It is pinned per rule because
	// two registries need not draw on the same Sigstore instance.
	TrustRoot string
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
// own copy of the rules and their lists; later changes to the caller's
// slices do not affect the policy.
func New(rules []Rule) (*Policy, error) {
	for i, r := range rules {
		if err := validateRule(r); err != nil {
			return nil, fmt.Errorf("policy rule %d: %w", i+1, err)
		}
	}
	out := make([]Rule, 0, len(rules))
	for _, r := range rules {
		out = append(out, Rule{
			Pattern:    r.Pattern,
			KeyFiles:   append([]string(nil), r.KeyFiles...),
			Identities: append([]keyless.Identity(nil), r.Identities...),
			TrustRoot:  r.TrustRoot,
		})
	}
	return &Policy{rules: out}, nil
}

// validateRule refuses a rule that cannot mean what it says.
func validateRule(r Rule) error {
	if err := ValidatePattern(r.Pattern); err != nil {
		return err
	}
	if len(r.KeyFiles) == 0 && len(r.Identities) == 0 {
		return fmt.Errorf("(%s) names neither a key nor an identity", r.Pattern)
	}
	// A trusted root says which authorities may issue and which logs are
	// believed, and nothing else in a rule needs it. Each half without the
	// other is a half-finished edit: identities with no root cannot be
	// checked at all, and a root with no identities is read by nothing,
	// which would leave somebody believing they had pinned something.
	if len(r.Identities) > 0 && r.TrustRoot == "" {
		return fmt.Errorf(
			"(%s) names a keyless identity but no trust-root to check it against",
			r.Pattern)
	}
	if r.TrustRoot != "" && len(r.Identities) == 0 {
		return fmt.Errorf(
			"(%s) names a trust-root but no identity, so nothing would be checked against it",
			r.Pattern)
	}
	for j, id := range r.Identities {
		if err := id.Validate(); err != nil {
			return fmt.Errorf("(%s) identity %d: %w", r.Pattern, j+1, err)
		}
	}
	return nil
}

// RuleFor returns the rule that decides who may sign repoRef, and whether
// any rule matched. A miss is a refusal rather than a fallback: a policy is
// configured deliberately, and a pattern typo must not quietly restore the
// single-key behaviour it replaced. The returned rule is the caller's own
// and does not alias the policy's internal storage.
func (p *Policy) RuleFor(repoRef string) (Rule, bool) {
	for _, r := range p.rules {
		if Match(r.Pattern, repoRef) {
			return Rule{
				Pattern:    r.Pattern,
				KeyFiles:   append([]string(nil), r.KeyFiles...),
				Identities: append([]keyless.Identity(nil), r.Identities...),
				TrustRoot:  r.TrustRoot,
			}, true
		}
	}
	return Rule{}, false
}

// KeyFilesFor returns the keys allowed to sign repoRef, and whether any
// rule matched.
func (p *Policy) KeyFilesFor(repoRef string) ([]string, bool) {
	r, ok := p.RuleFor(repoRef)
	if !ok {
		return nil, false
	}
	return r.KeyFiles, true
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
