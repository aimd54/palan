// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
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

	"github.com/aimd54/palan/internal/store"
)

var fakellamaBin string

func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "palan-runtime-test-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fakellamaBin = filepath.Join(tmp, "fakellama")
	build := exec.Command("go", "build", "-o", fakellamaBin, "github.com/aimd54/palan/internal/fakellama")
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

// writeLib drops a plausibly-named shared library into dir.
func writeLib(t *testing.T, dir, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("fake-lib"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// envValue returns the value of key in a process environment slice.
func envValue(env []string, key string) (string, bool) {
	for _, kv := range env {
		if rest, ok := strings.CutPrefix(kv, key+"="); ok {
			return rest, true
		}
	}
	return "", false
}

func TestRuntimeEnvExposesPackedLibraries(t *testing.T) {
	key := libraryPathVar()
	for _, name := range []string{"libggml.so", "libggml.so.0", "libggml.dylib"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeLib(t, dir, name)

			env := runtimeEnv([]string{"PATH=/usr/bin"}, dir)
			got, ok := envValue(env, key)
			if !ok || got != dir {
				t.Errorf("%s = %q (present %v), want %q", key, got, ok, dir)
			}
			if v, ok := envValue(env, "PATH"); !ok || v != "/usr/bin" {
				t.Errorf("unrelated variables must survive; PATH = %q (present %v)", v, ok)
			}
		})
	}
}

func TestRuntimeEnvPrependsToExistingSearchPath(t *testing.T) {
	key := libraryPathVar()
	dir := t.TempDir()
	writeLib(t, dir, "libggml.so.0")

	env := runtimeEnv([]string{key + "=/opt/libs", "PATH=/usr/bin"}, dir)
	want := dir + string(os.PathListSeparator) + "/opt/libs"
	if got, _ := envValue(env, key); got != want {
		t.Errorf("%s = %q, want %q", key, got, want)
	}
	// The variable must not be duplicated, or the loader reads only the first.
	var n int
	for _, kv := range env {
		if strings.HasPrefix(kv, key+"=") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%s appears %d times, want 1", key, n)
	}
}

func TestRuntimeEnvLeavesLibraryFreeDirsAlone(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README"), []byte("no libs here"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := []string{"PATH=/usr/bin"}
	for _, binDir := range []string{dir, "", ".", filepath.Join(dir, "missing")} {
		if got := runtimeEnv(base, binDir); len(got) != 1 || got[0] != "PATH=/usr/bin" {
			t.Errorf("binDir %q: environment changed to %v", binDir, got)
		}
	}
}

// TestSupervisorPointsLoaderAtPackedRuntime covers the air-gap case end to
// end: a runtime unpacked from an artifact carries its libraries beside the
// executable, and the child process must be told to look there.
func TestSupervisorPointsLoaderAtPackedRuntime(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "llama-server")
	src, err := os.ReadFile(fakellamaBin)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, src, 0o700); err != nil { // #nosec G306
		t.Fatal(err)
	}
	writeLib(t, dir, "libggml.so.0")

	srv, err := Start(context.Background(), Spec{
		Bin:          bin,
		ModelPath:    "/fake/model.gguf",
		Alias:        "registry.example/llm/tiny:q4",
		LogDir:       t.TempDir(),
		StartTimeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Stop(context.Background()) }()

	key := libraryPathVar()
	got, ok := envValue(srv.cmd.Env, key)
	if !ok || got != dir {
		t.Errorf("child %s = %q (present %v), want %q", key, got, ok, dir)
	}
}

// packRuntime seeds a runtime artifact holding the fake llama-server plus a
// companion library, and returns its reference.
func packRuntime(t *testing.T, st *store.Store) string {
	t.Helper()
	lib := filepath.Join(t.TempDir(), "libggml.so")
	if err := os.WriteFile(lib, []byte("a library the loader picks up"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		Name: "llama-server", Build: "b9", OS: runtime.GOOS, Arch: runtime.GOARCH,
		Flavor: "cpu", Entrypoint: "llama-server",
	}
	ref := "registry.example/runtimes/llama-server:b9-cpu"
	if _, err := Pack(context.Background(), st, []PackFile{
		{Path: fakellamaBin, Name: "llama-server"},
		{Path: lib},
	}, cfg, ref); err != nil {
		t.Fatalf("pack: %v", err)
	}
	return ref
}

// TestEnsureReplacesAnUnpackedEngineThatWasTamperedWith is the gap between
// verifying an artifact and executing a file. The store's blobs are
// content-addressed and checked; the unpacked tree is a plain copy that the
// supervisor execs, so its presence proves nothing about its bytes.
func TestEnsureReplacesAnUnpackedEngineThatWasTamperedWith(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	ref := packRuntime(t, st)

	entry, err := Ensure(ctx, st, ref)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	genuine, err := os.ReadFile(entry) // #nosec G304 -- test fixture under a temp dir
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(entry, []byte("#!/bin/sh\nexit 7\n"), 0o755); err != nil { // #nosec G306 -- deliberately executable
		t.Fatal(err)
	}

	again, err := Ensure(ctx, st, ref)
	if err != nil {
		t.Fatalf("ensure after tampering: %v", err)
	}
	if again != entry {
		t.Fatalf("ensure moved the entrypoint to %s, want %s", again, entry)
	}
	// Positive state: the bytes at the path the supervisor will exec are
	// the packed ones again, not merely different from the substitute.
	back, err := os.ReadFile(entry) // #nosec G304 -- test fixture under a temp dir
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, genuine) {
		t.Fatalf("the engine about to be spawned holds %d bytes that are not the packed ones", len(back))
	}
	fi, err := os.Stat(entry)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&0o100 == 0 {
		t.Error("the replaced entrypoint is not executable")
	}
}

// TestEnsureReplacesAnUnpackedTreeThatGainedAFile covers the quieter half:
// palan points the dynamic loader at this directory, so a library added
// beside the binary is loaded by it without any packed file being touched.
func TestEnsureReplacesAnUnpackedTreeThatGainedAFile(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	ref := packRuntime(t, st)

	entry, err := Ensure(ctx, st, ref)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	planted := filepath.Join(filepath.Dir(entry), "libevil.so")
	if err := os.WriteFile(planted, []byte("loaded from the runtime directory"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Ensure(ctx, st, ref); err != nil {
		t.Fatalf("ensure after a file was planted: %v", err)
	}
	if _, err := os.Stat(planted); !os.IsNotExist(err) {
		t.Fatalf("the planted library is still in the directory the loader searches (stat: %v)", err)
	}
	// The packed files are still there: the repair must not empty the tree.
	for _, name := range []string{"llama-server", "libggml.so"} {
		if _, err := os.Stat(filepath.Join(filepath.Dir(entry), name)); err != nil {
			t.Errorf("packed file %s is gone after the repair: %v", name, err)
		}
	}
}
