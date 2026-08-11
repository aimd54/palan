//go:build e2e

// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// startServe runs `palan serve` against home and waits for it to answer,
// returning its base URL. The caller gets a running router, so these tests
// cover the CLI and the router together rather than either alone.
func startServe(t *testing.T, home string, args ...string) string {
	t.Helper()
	port, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	ctx, cancel := context.WithCancel(context.Background())
	full := append([]string{"--plain-http", "--quiet", "serve", "--addr", addr,
		"--memory-budget", "8GiB"}, args...)
	cmd := exec.CommandContext(ctx, palanBin, full...)
	// Cancelling a CommandContext sends SIGKILL by default, which serve cannot
	// handle, so its shutdown never runs and the llama-server it supervises is
	// orphaned rather than stopped. Signal instead, and keep the kill only as
	// the fallback for a process that ignores it.
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 15 * time.Second
	cmd.Env = append(os.Environ(), "PALAN_HOME="+home, "PATH="+runtimeDir+":"+os.Getenv("PATH"))
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
	})

	base := "http://" + addr
	for i := 0; i < 100; i++ {
		resp, err := http.Get(base + "/health") //nolint:noctx // short-lived readiness poll
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return base
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("serve did not become ready:\n%s", out.String())
	return ""
}

// chatStatus posts a completion request and reports the status and body.
func chatStatus(t *testing.T, base, model string) (int, string) {
	t.Helper()
	body := fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"hi"}]}`, model)
	resp, err := http.Post(base+"/v1/chat/completions", "application/json", strings.NewReader(body)) //nolint:noctx // test client
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// writeVerifyConfig writes a config that turns the policy on, which is how a
// deployment enables it. Note registry.plain-http is nested; a top-level
// plain-http key is silently ignored.
func writeVerifyConfig(t *testing.T, pub string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	cfg := "registry:\n  plain-http: true\nverify:\n  required: true\n  key: " + pub + "\n"
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestServeRefusesUnverifiedModel: verify.required has to mean something at
// the moment a model is served, not only when it entered the store. A store
// can change after import, and until now nothing re-read it.
func TestServeRefusesUnverifiedModel(t *testing.T) {
	t.Setenv("COSIGN_PASSWORD", testKeyPassword)
	host := registryHost(t)
	fx := writeFixtures(t, 64<<10)
	priv, pub := writeTestKeys(t)

	signedRef := host + "/llm/serve-signed:v1"
	unsignedRef := host + "/llm/serve-unsigned:v1"

	home := t.TempDir()
	palan(t, home, "pack", fx.ggufPath, "-t", signedRef)
	palan(t, home, "push", signedRef)
	palan(t, home, "sign", signedRef, "--key", priv)
	palan(t, home, "pack", fx.ggufPath, "-t", unsignedRef)
	palan(t, home, "push", unsignedRef)
	// Pull the signature down so the check needs no registry.
	palan(t, home, "pull", signedRef)

	base := startServe(t, home, "--verify", "--verify-key", pub)

	if code, body := chatStatus(t, base, unsignedRef); code != http.StatusForbidden {
		t.Errorf("unsigned model: got %d, want 403\n%s", code, body)
	} else if !strings.Contains(body, "verification") {
		t.Errorf("refusal should say why:\n%s", body)
	}
	if code, body := chatStatus(t, base, signedRef); code != http.StatusOK {
		t.Errorf("signed model must still serve: %d\n%s", code, body)
	}

	// Listing reports what exists; refusal happens on use.
	resp, err := http.Get(base + "/v1/models") //nolint:noctx // test client
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	listed, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(listed), "serve-unsigned") {
		t.Errorf("an unverified model should still be listed:\n%s", listed)
	}
}

// TestServeHonoursConfigPolicy: a deployment sets verify.required in the
// config rather than passing flags, so that path has to work on its own.
func TestServeHonoursConfigPolicy(t *testing.T) {
	t.Setenv("COSIGN_PASSWORD", testKeyPassword)
	host := registryHost(t)
	fx := writeFixtures(t, 64<<10)
	_, pub := writeTestKeys(t)

	unsignedRef := host + "/llm/serve-cfg:v1"
	home := t.TempDir()
	palan(t, home, "pack", fx.ggufPath, "-t", unsignedRef)
	palan(t, home, "push", unsignedRef)

	base := startServe(t, home, "--config", writeVerifyConfig(t, pub))
	if code, body := chatStatus(t, base, unsignedRef); code != http.StatusForbidden {
		t.Errorf("config-driven policy ignored: got %d, want 403\n%s", code, body)
	}
}

// TestRunRefusesBeforeFetching: run pulled models itself without consulting
// the policy, so an unsigned model was downloaded and served. The refusal has
// to happen before the download, which is why the store is what this asserts
// on rather than the exit status alone.
func TestRunRefusesBeforeFetching(t *testing.T) {
	t.Setenv("COSIGN_PASSWORD", testKeyPassword)
	host := registryHost(t)
	fx := writeFixtures(t, 64<<10)
	_, pub := writeTestKeys(t)

	unsignedRef := host + "/llm/run-unsigned:v1"
	seed := t.TempDir()
	palan(t, seed, "pack", fx.ggufPath, "-t", unsignedRef)
	palan(t, seed, "push", unsignedRef)

	// A store that has never seen the model: run would otherwise fetch it.
	fresh := t.TempDir()
	out, err := palanRun(fresh, "--config", writeVerifyConfig(t, pub),
		"run", unsignedRef, "--prompt", "hi")
	if err == nil {
		t.Errorf("run must refuse an unsigned model under verify.required:\n%s", out)
	}
	if !strings.Contains(out, "no signature") {
		t.Errorf("refusal should name the missing signature:\n%s", out)
	}
	if listed := palan(t, fresh, "ls"); strings.Contains(listed, "run-unsigned") {
		t.Errorf("nothing should have been fetched:\n%s", listed)
	}
	blobs := filepath.Join(fresh, "blobs", "sha256")
	if entries, err := os.ReadDir(blobs); err == nil && len(entries) > 0 {
		t.Errorf("refused run left %d blob(s) on disk", len(entries))
	}
}
