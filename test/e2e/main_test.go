// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

// Package e2e exercises the real palan binary against a real zot registry
// (docker), plus oras and modctl binaries for the interop contract (G2).
//
// Requirements: docker (unless E2E_REGISTRY points at a running registry);
// oras and modctl in PATH for the interop tests (skipped otherwise).
package e2e

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// zotImage pins the e2e registry (ADR-0002; keep in sync with ci.yml).
const zotImage = "ghcr.io/project-zot/zot-minimal-linux-amd64:v2.1.18"

var (
	palanBin    string
	runtimeDir  string // holds a fake llama-server, prepended to the subprocess PATH
	regOnce     sync.Once
	regHostVal  string
	regSkipWhy  string
	regCleanup  func()
	digestRegex = regexp.MustCompile(`Digest: (sha256:[0-9a-f]{64})`)
)

func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "palan-e2e-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e: tempdir:", err)
		os.Exit(1)
	}
	palanBin = filepath.Join(tmp, "palan")
	build := exec.Command("go", "build", "-o", palanBin, "github.com/aimd54/palan/cmd/palan")
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "e2e: building palan: %v\n%s", err, out)
		os.Exit(1)
	}

	// serve and run need a llama-server on PATH. The fake one speaks enough
	// of the HTTP surface for the router, so these tests can exercise the
	// serving path without a real llama.cpp build.
	runtimeDir = filepath.Join(tmp, "runtime")
	if err := os.MkdirAll(runtimeDir, 0o750); err != nil {
		fmt.Fprintln(os.Stderr, "e2e: runtime dir:", err)
		os.Exit(1)
	}
	fake := exec.Command("go", "build", "-o", filepath.Join(runtimeDir, "llama-server"),
		"github.com/aimd54/palan/internal/fakellama")
	if out, err := fake.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "e2e: building fakellama: %v\n%s", err, out)
		os.Exit(1)
	}

	code := m.Run()
	if regCleanup != nil {
		regCleanup()
	}
	// A supervised llama-server that outlives the test that started it leaves
	// nothing failing: the suite passes, the process keeps running, and it is
	// found days later by accident. Fail here instead.
	if leaked := survivingChildren(runtimeDir); len(leaked) > 0 {
		fmt.Fprintf(os.Stderr,
			"e2e: %d supervised child process(es) outlived the suite: %v\n"+
				"serve is expected to stop them on shutdown, so a survivor means a test\n"+
				"killed it in a way that skipped that shutdown.\n", len(leaked), leaked)
		code = 1
	}
	_ = os.RemoveAll(tmp)
	os.Exit(code)
}

// survivingChildren returns the pids of processes still running from dir.
// Reading /proc is Linux-only; elsewhere it reports nothing rather than
// pretending to have checked.
func survivingChildren(dir string) []int {
	if runtime.GOOS != "linux" || dir == "" {
		return nil
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var pids []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		cmdline, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if err != nil {
			continue // exited between the listing and the read
		}
		if strings.Contains(string(cmdline), dir) {
			pids = append(pids, pid)
		}
	}
	return pids
}

// registryHost returns a ready registry host:port, starting a zot container
// on first use unless E2E_REGISTRY is set.
func registryHost(t *testing.T) string {
	t.Helper()
	regOnce.Do(func() {
		if h := os.Getenv("E2E_REGISTRY"); h != "" {
			regHostVal = h
			waitReady(&regSkipWhy, regHostVal)
			return
		}
		if _, err := exec.LookPath("docker"); err != nil {
			regSkipWhy = "docker not available and E2E_REGISTRY not set"
			return
		}
		port, err := freePort()
		if err != nil {
			regSkipWhy = "no free port: " + err.Error()
			return
		}
		out, err := exec.Command("docker", "run", "-d", "--rm",
			"-p", fmt.Sprintf("127.0.0.1:%d:5000", port), zotImage).Output()
		if err != nil {
			regSkipWhy = "starting zot container: " + err.Error()
			return
		}
		id := strings.TrimSpace(string(out))
		regCleanup = func() { _ = exec.Command("docker", "rm", "-f", id).Run() }
		regHostVal = fmt.Sprintf("127.0.0.1:%d", port)
		waitReady(&regSkipWhy, regHostVal)
	})
	if regSkipWhy != "" {
		t.Skip("e2e registry unavailable: " + regSkipWhy)
	}
	return regHostVal
}

func waitReady(skipWhy *string, host string) {
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + host + "/v2/")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	*skipWhy = "registry at " + host + " never became ready"
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// palan runs the built binary with an isolated store and plain-HTTP
// registries, failing the test on error.
func palan(t *testing.T, home string, args ...string) string {
	t.Helper()
	out, err := palanRun(home, args...)
	if err != nil {
		t.Fatalf("palan %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

func palanRun(home string, args ...string) (string, error) {
	full := append([]string{"--plain-http", "--quiet"}, args...)
	cmd := exec.Command(palanBin, full...)
	cmd.Env = append(os.Environ(), "PALAN_HOME="+home, "PATH="+runtimeDir+":"+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// run executes an external tool (oras, modctl) with HOME isolated.
func run(t *testing.T, bin string, args ...string) string {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", bin, strings.Join(args, " "), err, out)
	}
	return string(out)
}

// firstDigest extracts the first "Digest: sha256:..." line from CLI output.
func firstDigest(t *testing.T, out string) string {
	t.Helper()
	m := digestRegex.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no digest in output:\n%s", out)
	}
	return m[1]
}
