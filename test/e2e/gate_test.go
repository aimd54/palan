// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package e2e

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// palanWithBlockedStdin runs the real binary with stdin held open and never
// written to, under a deadline.
//
// That is the measurement, not a precaution. An init container has no
// terminal and nothing to answer a prompt with, so a command that decides to
// ask for anything blocks until the pod's own deadline and reports nothing.
// The failure this guards against is a hang, and a hang cannot be told from
// slow work by reading an error message: the process either came back or it
// did not.
func palanWithBlockedStdin(t *testing.T, home string, args ...string) (string, error, time.Duration) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	defer func() { _ = w.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, palanBin, append([]string{"--plain-http", "--quiet"}, args...)...)
	cmd.Stdin = r
	cmd.Env = append(os.Environ(), "PALAN_HOME="+home, "PATH="+runtimeDir+":"+os.Getenv("PATH"))
	start := time.Now()
	out, runErr := cmd.CombinedOutput()
	elapsed := time.Since(start)
	if ctx.Err() != nil {
		t.Fatalf("palan %s never returned; with stdin open and empty it waited for input, "+
			"which in an init container is a pod that hangs with nothing on its logs\n%s",
			strings.Join(args, " "), out)
	}
	return string(out), runErr, elapsed
}

// countEntries reports how many files a directory holds, which is what the
// gate pattern's manifests actually depend on: the serving container mounts
// this volume, and a refusal that left a partial file behind would hand it
// something to try to load.
func countEntries(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	return len(entries)
}

// TestGateRefusalLeavesTheSharedVolumeEmpty measures the two properties the
// init-container gate pattern rests on: a refusal writes nothing into the
// volume the serving container will mount, and it comes back rather than
// waiting for input that will never arrive.
//
// Both halves of the fixture matter. An empty output directory proves
// nothing on its own, since a command that never works leaves one too, so
// the same pull under a policy that admits the signature must fill it.
func TestGateRefusalLeavesTheSharedVolumeEmpty(t *testing.T) {
	t.Setenv("COSIGN_PASSWORD", testKeyPassword)
	host := registryHost(t)
	fx := writeFixtures(t, 64<<10)
	priv, pub := writeTestKeys(t)

	ref := host + "/llm/gate:v1"
	publisher := t.TempDir()
	palan(t, publisher, "pack", fx.ggufPath, "-t", ref)
	palan(t, publisher, "push", ref)
	palan(t, publisher, "sign", ref, "--key", priv)

	// The policy admits this signature: the volume must end up holding the
	// model, which is what the serving container is waiting for.
	admitted := filepath.Join(t.TempDir(), "models")
	if err := os.MkdirAll(admitted, 0o750); err != nil {
		t.Fatal(err)
	}
	out, err, elapsed := palanWithBlockedStdin(t, t.TempDir(),
		"--config", writePolicyConfig(t, host+"/llm/*", pub),
		"pull", ref, "--output="+admitted)
	if err != nil {
		t.Fatalf("the policy names this key for this reference and the pull refused after %s: %v\n%s", elapsed, err, out)
	}
	if n := countEntries(t, admitted); n == 0 {
		t.Fatal("the pull reported success and wrote nothing into the shared volume")
	}

	// The same signature under a policy that names another repository: the
	// volume must be untouched, and the init container must exit.
	refused := filepath.Join(t.TempDir(), "models")
	if err := os.MkdirAll(refused, 0o750); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	out, err, elapsed = palanWithBlockedStdin(t, home,
		"--config", writePolicyConfig(t, host+"/other/*", pub),
		"pull", ref, "--output="+refused)
	if err == nil {
		t.Fatalf("a reference no rule names must refuse, not fill the volume:\n%s", out)
	}
	if n := countEntries(t, refused); n != 0 {
		t.Fatalf("the refusal left %d file(s) in the volume the serving container mounts", n)
	}
	if !strings.Contains(out, "trust policy") {
		t.Errorf("the refusal does not name the policy as its cause, so an operator cannot act on it:\n%s", out)
	}
	t.Logf("refusal returned in %s, leaving the shared volume empty", elapsed)
}
