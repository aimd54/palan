// Copyright The moci Authors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/aimd54/moci/internal/store"
)

var fakellamaBin string

func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "moci-runtime-test-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fakellamaBin = filepath.Join(tmp, "fakellama")
	build := exec.Command("go", "build", "-o", fakellamaBin, "github.com/aimd54/moci/internal/fakellama")
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "building fakellama: %v\n%s", err, out)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(tmp)
	os.Exit(code)
}

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSupervisorStartServeStop(t *testing.T) {
	ctx := context.Background()
	s, err := Start(ctx, Spec{
		Bin:          fakellamaBin,
		ModelPath:    "/fake/model.gguf",
		Alias:        "registry.example/llm/tiny:q4",
		CtxSize:      2048,
		NGL:          99,
		LogDir:       t.TempDir(),
		StartTimeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer func() { _ = s.Stop(ctx) }()

	resp, err := http.Get(s.BaseURL() + "/v1/models")
	if err != nil {
		t.Fatalf("child not serving: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(body), "model.gguf") {
		t.Errorf("unexpected /v1/models body: %s", body)
	}

	if err := s.Stop(ctx); err != nil {
		t.Fatalf("stop: %v", err)
	}
	// After Stop, the port must be released.
	if _, err := http.Get(s.BaseURL() + "/health"); err == nil {
		t.Error("child still serving after Stop")
	}
}

func TestSupervisorStartupTimeout(t *testing.T) {
	t.Setenv("FAKELLAMA_STARTUP_DELAY", "30s")
	_, err := Start(context.Background(), Spec{
		Bin:          fakellamaBin,
		ModelPath:    "/fake/model.gguf",
		Alias:        "slow",
		LogDir:       t.TempDir(),
		StartTimeout: 700 * time.Millisecond,
	})
	if err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("expected startup timeout, got %v", err)
	}
}

func TestSupervisorDetectsCrash(t *testing.T) {
	t.Setenv("FAKELLAMA_EXIT_AFTER", "500ms")
	ctx := context.Background()
	s, err := Start(ctx, Spec{
		Bin:          fakellamaBin,
		ModelPath:    "/fake/model.gguf",
		Alias:        "crashy",
		LogDir:       t.TempDir(),
		StartTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	select {
	case <-s.Done():
		if s.ExitErr() == nil {
			t.Error("crash should surface a non-nil exit error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("crash never reported on Done()")
	}
	// Stop after exit must return immediately (idempotency regression guard).
	stopped := make(chan struct{})
	go func() { _ = s.Stop(context.Background()); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop hangs on an already-exited process")
	}
}

func TestPackEnsureRoundTrip(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)

	lib := filepath.Join(t.TempDir(), "libggml.so")
	if err := os.WriteFile(lib, []byte("fake-lib"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		Name: "llama-server", Build: "b0000", OS: runtime.GOOS, Arch: runtime.GOARCH,
		Flavor: "cpu", Entrypoint: "llama-server",
	}
	ref := "registry.example/runtimes/llama-server:b0000-cpu"
	if _, err := Pack(ctx, st, []PackFile{
		{Path: fakellamaBin, Name: "llama-server"},
		{Path: lib},
	}, cfg, ref); err != nil {
		t.Fatalf("pack: %v", err)
	}

	entry, err := Ensure(ctx, st, ref)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	fi, err := os.Stat(entry)
	if err != nil {
		t.Fatalf("entrypoint missing: %v", err)
	}
	if fi.Mode()&0o100 == 0 {
		t.Error("entrypoint not executable")
	}
	libInfo, err := os.Stat(filepath.Join(filepath.Dir(entry), "libggml.so"))
	if err != nil {
		t.Fatalf("companion file missing: %v", err)
	}
	if libInfo.Mode()&0o100 != 0 {
		t.Error("companion file should not be executable")
	}

	// Idempotent second Ensure, and the materialized binary actually runs
	// under the supervisor.
	entry2, err := Ensure(ctx, st, ref)
	if err != nil || entry2 != entry {
		t.Fatalf("second ensure: %s (%v)", entry2, err)
	}
	s, err := Start(ctx, Spec{Bin: entry, ModelPath: "/fake/m.gguf", Alias: "mat", LogDir: t.TempDir(), StartTimeout: 30 * time.Second})
	if err != nil {
		t.Fatalf("start materialized runtime: %v", err)
	}
	_ = s.Stop(ctx)
}

func TestEnsureRejectsWrongPlatform(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	cfg := Config{Name: "llama-server", Build: "b1", OS: "plan9", Arch: "mips", Flavor: "cpu", Entrypoint: "llama-server"}
	ref := "registry.example/runtimes/llama-server:b1-plan9"
	if _, err := Pack(ctx, st, []PackFile{{Path: fakellamaBin, Name: "llama-server"}}, cfg, ref); err != nil {
		t.Fatal(err)
	}
	if _, err := Ensure(ctx, st, ref); err == nil || !strings.Contains(err.Error(), "plan9") {
		t.Errorf("expected platform mismatch error, got %v", err)
	}
}

func TestPackRequiresEntrypoint(t *testing.T) {
	st := openTestStore(t)
	cfg := Config{Name: "x", Build: "b1", OS: runtime.GOOS, Arch: runtime.GOARCH, Flavor: "cpu", Entrypoint: "missing"}
	if _, err := Pack(context.Background(), st, []PackFile{{Path: fakellamaBin}}, cfg, "r.example/x:y"); err == nil {
		t.Error("pack must reject an entrypoint that is not among the files")
	}
}

func TestListFiltersRuntimes(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	cfg := Config{Name: "llama-server", Build: "b2", OS: runtime.GOOS, Arch: runtime.GOARCH, Flavor: "cpu", Entrypoint: "llama-server"}
	if _, err := Pack(ctx, st, []PackFile{{Path: fakellamaBin, Name: "llama-server"}}, cfg, "r.example/runtimes/l:b2-cpu"); err != nil {
		t.Fatal(err)
	}
	entries, err := List(ctx, st)
	if err != nil || len(entries) != 1 {
		t.Errorf("list: %v entries, err %v", len(entries), err)
	}
}

func TestResolveFallsBackToPath(t *testing.T) {
	st := openTestStore(t)
	dir := t.TempDir()
	fake := filepath.Join(dir, DefaultBinaryName)
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil { // #nosec G306
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	p, err := Resolve(context.Background(), st, "")
	if err != nil || p != fake {
		t.Errorf("resolve: %q (%v)", p, err)
	}

	t.Setenv("PATH", t.TempDir())
	if _, err := Resolve(context.Background(), st, ""); err == nil {
		t.Error("resolve must fail with no runtime anywhere")
	}
}
