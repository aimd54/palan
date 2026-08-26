// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package e2e

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writePolicyConfig writes a config that turns verify.required on and names
// pattern as the only rule allowed to sign under it, keyed to pub. This is
// how a deployment governs which identities may sign which references,
// rather than trusting one key for everything the way verify.key does.
func writePolicyConfig(t *testing.T, pattern, pub string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	cfg := "registry:\n  plain-http: true\nverify:\n  required: true\n  policy:\n" +
		"    - pattern: \"" + pattern + "\"\n      keys:\n        - " + pub + "\n"
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestServeHonoursConfigPolicyPattern starts a real `palan serve` process
// twice against the same store, once under a policy naming the signing key
// for this repository and once under one that names it for a different
// repository, and checks the HTTP status each config leaves a request with.
// A unit test that builds storeBackend and passes it a gate directly proves
// the gate's own logic accepts or refuses correctly, but says nothing about
// whether newServeCmd ever reads verify.policy and wires that gate into the
// backend it hands the router; only a serve process started from a real
// config file exercises that connection.
func TestServeHonoursConfigPolicyPattern(t *testing.T) {
	t.Setenv("COSIGN_PASSWORD", testKeyPassword)
	host := registryHost(t)
	fx := writeFixtures(t, 64<<10)
	priv, pub := writeTestKeys(t)

	ref := host + "/llm/policy-serve:v1"
	home := t.TempDir()
	palan(t, home, "pack", fx.ggufPath, "-t", ref)
	palan(t, home, "push", ref)
	palan(t, home, "sign", ref, "--key", priv)
	// Pull the signature down so serve's check needs no registry.
	palan(t, home, "pull", ref)

	matching := startServe(t, home, "--config", writePolicyConfig(t, host+"/llm/*", pub))
	if code, body := chatStatus(t, matching, ref); code != http.StatusOK {
		t.Errorf("the policy names this key for this reference; got %d, want 200\n%s", code, body)
	}

	refusing := startServe(t, home, "--config", writePolicyConfig(t, host+"/other/*", pub))
	code, body := chatStatus(t, refusing, ref)
	if code != http.StatusForbidden {
		t.Errorf("a reference no rule names must refuse; got %d, want 403\n%s", code, body)
	}
	if !strings.Contains(body, "verification") {
		t.Errorf("refusal should say why:\n%s", body)
	}
	// The router wraps every gate failure in the same generic "signature
	// verification" phrasing, so that check alone would still pass for a
	// refusal caused by something other than the policy. Naming "trust
	// policy" pins the actual mechanism this test exercises.
	if !strings.Contains(body, "trust policy") {
		t.Errorf("refusal should name the trust policy as its cause:\n%s", body)
	}
}
