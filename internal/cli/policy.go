// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"

	"github.com/spf13/viper"

	"github.com/aimd54/palan/internal/trustpolicy"
)

// policyRule is the YAML shape of one verify.policy entry. It exists so the
// config format and the policy model can move independently.
type policyRule struct {
	Pattern string   `mapstructure:"pattern"`
	Keys    []string `mapstructure:"keys"`
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
		rules = append(rules, trustpolicy.Rule{
			Pattern:  r.Pattern,
			KeyFiles: r.Keys,
		})
	}
	return trustpolicy.New(rules)
}
