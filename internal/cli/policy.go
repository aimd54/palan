// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"

	"github.com/spf13/viper"

	"github.com/aimd54/palan/internal/keyless"
	"github.com/aimd54/palan/internal/trustpolicy"
)

// policyRule is the YAML shape of one verify.policy entry. It exists so the
// config format and the policy model can move independently.
type policyRule struct {
	Pattern    string         `mapstructure:"pattern"`
	Keys       []string       `mapstructure:"keys"`
	Identities []identityRule `mapstructure:"identities"`
	TrustRoot  string         `mapstructure:"trust-root"`
}

// identityRule is the YAML shape of one keyless signer: who they are, and
// which OpenID provider is trusted to say so.
type identityRule struct {
	Subject string `mapstructure:"subject"`
	Issuer  string `mapstructure:"issuer"`
}

// loadPolicy reads verify.policy from the config, returning nil when none is
// configured so verify.key stays in charge exactly as it was.
//
// An empty list is refused rather than read as "deny everything": a policy
// key present with nothing under it is a half-finished edit far more often
// than it is a posture.
func loadPolicy(v *viper.Viper) (*trustpolicy.Policy, error) {
	if !v.IsSet(keyVerifyPolicy) {
		return nil, nil
	}
	var raw []policyRule
	if err := v.UnmarshalKey(keyVerifyPolicy, &raw); err != nil {
		return nil, fmt.Errorf("reading %s: %w", keyVerifyPolicy, err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf(
			"%s is set but names no rule; remove it to fall back to %s, or add a rule",
			keyVerifyPolicy, keyVerifyKey)
	}
	rules := make([]trustpolicy.Rule, 0, len(raw))
	for _, r := range raw {
		ids := make([]keyless.Identity, 0, len(r.Identities))
		for _, id := range r.Identities {
			ids = append(ids, keyless.Identity{Subject: id.Subject, Issuer: id.Issuer})
		}
		rules = append(rules, trustpolicy.Rule{
			Pattern:    r.Pattern,
			KeyFiles:   r.Keys,
			Identities: ids,
			TrustRoot:  r.TrustRoot,
		})
	}
	return trustpolicy.New(rules)
}

// sourceRule is the YAML shape of one verify.sources entry: the key a
// Hugging Face repository matching pattern must have signed its published
// file digests with.
type sourceRule struct {
	Pattern string `mapstructure:"pattern"`
	OMSKey  string `mapstructure:"oms-key"`
}

// sourcePolicy names, per source pattern, the key a repository's own
// signature must be checked against. Unlike Policy it supplies a key rather
// than gating: a source no rule names is imported with no
// publisher-signature check at all, exactly as though no key had been
// passed. First match wins, the same as Policy.
type sourcePolicy struct {
	rules []sourceRule
}

// loadSourcePolicy reads verify.sources from the config, returning nil when
// none is configured so --oms-key alone stays in charge.
//
// An empty list is refused for the same reason loadPolicy's is: a key
// present with nothing under it is a half-finished edit far more often than
// a posture.
func loadSourcePolicy(v *viper.Viper) (*sourcePolicy, error) {
	if !v.IsSet(keyVerifySources) {
		return nil, nil
	}
	var raw []sourceRule
	if err := v.UnmarshalKey(keyVerifySources, &raw); err != nil {
		return nil, fmt.Errorf("reading %s: %w", keyVerifySources, err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf(
			"%s is set but names no rule; remove it to import every source unchecked, or add a rule",
			keyVerifySources)
	}
	for i, r := range raw {
		if err := trustpolicy.ValidatePattern(r.Pattern); err != nil {
			return nil, fmt.Errorf("%s rule %d: %w", keyVerifySources, i+1, err)
		}
		if r.OMSKey == "" {
			return nil, fmt.Errorf("%s rule %d (%s) names no oms-key",
				keyVerifySources, i+1, r.Pattern)
		}
	}
	rules := make([]sourceRule, len(raw))
	copy(rules, raw)
	return &sourcePolicy{rules: rules}, nil
}

// keyFor returns the key the first rule matching repo names, and whether any
// rule matched at all. repo is the "org/repo" of an hf:// reference; it never
// carries a revision or a filename. A nil policy matches nothing, so a
// caller need not check for one before asking.
func (p *sourcePolicy) keyFor(repo string) (string, bool) {
	if p == nil {
		return "", false
	}
	for _, r := range p.rules {
		if trustpolicy.Match(r.Pattern, repo) {
			return r.OMSKey, true
		}
	}
	return "", false
}
