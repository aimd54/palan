// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

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

// seedHostileRuntime pushes a runtime artifact directly, bypassing Pack's
// validation, so a test can present Ensure with a config a publisher could
// write but Pack would refuse to produce. What reaches a host is whatever a
// registry served, not whatever this repository's own packer would emit.
func seedHostileRuntime(t *testing.T, st *store.Store, cfg Config, files map[string][]byte, ref string) {
	t.Helper()
	ctx := context.Background()
	push := func(mediaType string, data []byte, ann map[string]string) ocispec.Descriptor {
		desc := ocispec.Descriptor{
			MediaType:   mediaType,
			Digest:      digest.FromBytes(data),
			Size:        int64(len(data)),
			Annotations: ann,
		}
		if err := st.OCI().Push(ctx, desc, bytes.NewReader(data)); err != nil && !isAlreadyExists(err) {
			t.Fatalf("push %s: %v", mediaType, err)
		}
		return desc
	}
	cfgBytes, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	layers := make([]ocispec.Descriptor, 0, len(files))
	for _, n := range names {
		layers = append(layers, push(MediaTypeRuntimeFile, files[n], map[string]string{ocispec.AnnotationTitle: n}))
	}
	manifest := ocispec.Manifest{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: ArtifactTypeRuntime,
		Config:       push(MediaTypeRuntimeConfig, cfgBytes, nil),
		Layers:       layers,
	}
	manifest.SchemaVersion = 2
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	desc := push(ocispec.MediaTypeImageManifest, raw, nil)
	if err := st.Tag(ctx, desc, ref); err != nil {
		t.Fatalf("tag: %v", err)
	}
}

// TestEnsureRefusesAConfigWhoseNameEscapesTheStore: name, build and flavor
// come out of the artifact's own config blob and are joined into a path
// that Ensure removes and rewrites, so a traversal there is an unlink of a
// directory the publisher chose. filepath.Join cleans a traversal into a
// real path instead of refusing it, which is what makes this reachable.
func TestEnsureRefusesAConfigWhoseNameEscapesTheStore(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	victim := filepath.Join(root, "victim")
	if err := os.MkdirAll(victim, 0o750); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(victim, "keep.txt")
	if err := os.WriteFile(keep, []byte("a directory that has nothing to do with palan"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(ctx, filepath.Join(root, "home"))
	if err != nil {
		t.Fatal(err)
	}

	ref := "registry.example/runtimes/evil:1"
	seedHostileRuntime(t, st, Config{
		Name: "../..", Build: "", Flavor: "./../victim",
		OS: runtime.GOOS, Arch: runtime.GOARCH, Entrypoint: "llama-server",
	}, map[string][]byte{"llama-server": []byte("an engine unpacked over somebody else's directory")}, ref)

	if _, err := Ensure(ctx, st, ref); err == nil {
		t.Fatal("a config naming a path outside the store was accepted")
	} else if !strings.Contains(err.Error(), "single path component") {
		t.Errorf("the refusal does not say what is wrong with the config: %v", err)
	}
	// Positive state: the directory the config aimed at is still there,
	// with its contents. An error alone would not say whether the removal
	// happened before it.
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("the unrelated directory was deleted despite the refusal: %v", err)
	}
}

func TestEnsureRefusesAnEntrypointTheArtifactDoesNotCarry(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	ref := "registry.example/runtimes/odd:1"
	seedHostileRuntime(t, st, Config{
		Name: "llama-server", Build: "b1", Flavor: "cpu",
		OS: runtime.GOOS, Arch: runtime.GOARCH, Entrypoint: "not-packed",
	}, map[string][]byte{"llama-server": []byte("the only file this artifact carries")}, ref)

	if _, err := Ensure(ctx, st, ref); err == nil {
		t.Fatal("an entrypoint the artifact does not carry was accepted")
	} else if !strings.Contains(err.Error(), "not-packed") {
		t.Errorf("the refusal does not name the entrypoint: %v", err)
	}
}

// TestEnsureRefusesAStoreBlobThatWasRewritten covers the path that creates
// the unpacked tree rather than the one that finds it. A store blob is
// addressed by its file name and by nothing else, so reading one back is a
// plain file open and a blob altered in place is handed over without
// complaint.
func TestEnsureRefusesAStoreBlobThatWasRewritten(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	ref := packRuntime(t, st)

	entry, err := Ensure(ctx, st, ref)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	// Take the unpacked tree away, so the next Ensure has to build one.
	if err := os.RemoveAll(filepath.Dir(entry)); err != nil {
		t.Fatal(err)
	}

	manifest, err := store.FetchManifest(ctx, st.OCI(), mustResolve(t, st, ref))
	if err != nil {
		t.Fatal(err)
	}
	var engine ocispec.Descriptor
	for _, l := range manifest.Layers {
		if l.Annotations[ocispec.AnnotationTitle] == "llama-server" {
			engine = l
		}
	}
	blob, err := st.BlobPath(engine.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(blob, 0o600); err != nil {
		t.Fatal(err)
	}
	tampered := make([]byte, engine.Size)
	copy(tampered, "#!/bin/sh\nexit 7\n")
	if err := os.WriteFile(blob, tampered, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Ensure(ctx, st, ref); err == nil {
		t.Fatal("an engine was unpacked from a store blob that does not hash to its manifest")
	} else if !strings.Contains(err.Error(), engine.Digest.String()) {
		t.Errorf("the refusal does not name the blob: %v", err)
	}
	if _, err := os.Stat(entry); err == nil {
		t.Fatal("the refusal left an engine at the path the supervisor would execute")
	}
}

// TestEnsureRefusesASymlinkedEngine: a symlink pointing at a file that
// holds the right bytes passes a check that follows it, and is still a
// symlink afterwards, so whoever owns the target decides what runs from
// then on without palan ever looking again.
func TestEnsureRefusesASymlinkedEngine(t *testing.T) {
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
	shadow := filepath.Join(t.TempDir(), "shadow")
	if err := os.WriteFile(shadow, genuine, 0o755); err != nil { // #nosec G306 -- deliberately executable
		t.Fatal(err)
	}
	if err := os.Remove(entry); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(shadow, entry); err != nil {
		t.Fatal(err)
	}

	if _, err := Ensure(ctx, st, ref); err != nil {
		t.Fatalf("ensure over a symlinked engine: %v", err)
	}
	fi, err := os.Lstat(entry)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.Mode().IsRegular() {
		t.Fatalf("the engine is still a %s, so its bytes are somebody else's to change", fi.Mode().Type())
	}
	// Positive state: rewriting what the link aimed at no longer changes
	// anything about the file that would be executed.
	if err := os.WriteFile(shadow, []byte("#!/bin/sh\nexit 7\n"), 0o755); err != nil { // #nosec G306 -- deliberately executable
		t.Fatal(err)
	}
	back, err := os.ReadFile(entry) // #nosec G304 -- test fixture under a temp dir
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, genuine) {
		t.Fatal("the engine's bytes still track a file outside the store")
	}
}

// TestEnsureKeepsTheOldEngineWhenTheUnpackCannotFinish: removing the tree
// before building its replacement leaves a host with no engine at all when
// the unpack fails, which is a worse position than the mismatching tree it
// started with.
func TestEnsureKeepsTheOldEngineWhenTheUnpackCannotFinish(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	ref := packRuntime(t, st)

	entry, err := Ensure(ctx, st, ref)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	// A tree that no longer matches, so Ensure will try to rebuild it.
	planted := filepath.Join(filepath.Dir(entry), "libevil.so")
	if err := os.WriteFile(planted, []byte("planted"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A store that can no longer supply the replacement.
	manifest, err := store.FetchManifest(ctx, st.OCI(), mustResolve(t, st, ref))
	if err != nil {
		t.Fatal(err)
	}
	blob, err := st.BlobPath(manifest.Layers[0].Digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(blob, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(blob, []byte("too short to be what the manifest records"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Ensure(ctx, st, ref); err == nil {
		t.Fatal("the unpack reported success from a store that cannot supply the files")
	}
	if _, err := os.Stat(entry); err != nil {
		t.Fatalf("a failed unpack left the host with no engine where it had one: %v", err)
	}
}

func mustResolve(t *testing.T, st *store.Store, ref string) ocispec.Descriptor {
	t.Helper()
	desc, err := st.Resolve(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	return desc
}

// TestEnsureRefusesADigestItCannotCompute: building a verifier for an
// algorithm the binary does not link panics rather than returning an error,
// so a manifest naming one would take down run, serve and runtime pull with
// a stack trace instead of a refusal.
func TestEnsureRefusesADigestItCannotCompute(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	ref := packRuntime(t, st)

	// A second artifact sharing the materialization directory, so the
	// tree the first one unpacked is already there to be compared against.
	hostile := "registry.example/runtimes/llama-server:b9-cpu-alt"
	seedHostileRuntime(t, st, Config{
		Name: "llama-server", Build: "b9", Flavor: "cpu",
		OS: runtime.GOOS, Arch: runtime.GOARCH, Entrypoint: "llama-server",
	}, map[string][]byte{"llama-server": []byte("an engine digested with an algorithm palan does not link")}, hostile)
	if _, err := Ensure(ctx, st, ref); err != nil {
		t.Fatalf("unpacking the genuine runtime: %v", err)
	}
	retagWithDigestAlgorithm(t, st, hostile, "md5:900150983cd24fb0d6963f7d28e17f72")

	// The refusal is the assertion: reaching this line at all means no
	// panic, and the message has to name the algorithm rather than blame
	// the file on disk.
	_, err := Ensure(ctx, st, hostile)
	if err == nil {
		t.Fatal("a manifest digested with an unavailable algorithm was accepted")
	}
	// Asserted on the refusal's own words. The reference must not carry the
	// algorithm's name either, or this passes on the wrapper rather than on
	// the check.
	if !strings.Contains(err.Error(), "cannot use") {
		t.Errorf("the refusal does not read as one about the digest: %v", err)
	}
	if !strings.Contains(err.Error(), "md5") {
		t.Errorf("the refusal does not name the algorithm: %v", err)
	}
	if !strings.Contains(err.Error(), "llama-server") {
		t.Errorf("the refusal does not name the layer: %v", err)
	}
}

// retagWithDigestAlgorithm rewrites ref's manifest so its layers carry the
// given digest string, which is what a hostile or malformed registry would
// serve.
func retagWithDigestAlgorithm(t *testing.T, st *store.Store, ref, layerDigest string) {
	t.Helper()
	ctx := context.Background()
	manifest, err := store.FetchManifest(ctx, st.OCI(), mustResolve(t, st, ref))
	if err != nil {
		t.Fatal(err)
	}
	for i := range manifest.Layers {
		manifest.Layers[i].Digest = digest.Digest(layerDigest)
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	desc := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageManifest,
		Digest:    digest.FromBytes(raw),
		Size:      int64(len(raw)),
	}
	if err := st.OCI().Push(ctx, desc, bytes.NewReader(raw)); err != nil && !isAlreadyExists(err) {
		t.Fatal(err)
	}
	if err := st.Tag(ctx, desc, ref); err != nil {
		t.Fatal(err)
	}
}

// TestEnsureKeepsRuntimesWhoseFlavourLooksLikeAStagingDirectory: a flavour
// ending in the staging suffix used to resolve to exactly another
// runtime's staging path, so unpacking either deleted the other's engine.
func TestEnsureKeepsRuntimesWhoseFlavourLooksLikeAStagingDirectory(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	engine := []byte("an engine")
	plain := "registry.example/runtimes/llama-server:b1-cpu"
	colliding := "registry.example/runtimes/llama-server:b1-cpu-tmp"
	seedHostileRuntime(t, st, Config{
		Name: "llama-server", Build: "b1", Flavor: "cpu",
		OS: runtime.GOOS, Arch: runtime.GOARCH, Entrypoint: "llama-server",
	}, map[string][]byte{"llama-server": engine}, plain)
	seedHostileRuntime(t, st, Config{
		Name: "llama-server", Build: "b1", Flavor: "cpu.tmp",
		OS: runtime.GOOS, Arch: runtime.GOARCH, Entrypoint: "llama-server",
	}, map[string][]byte{"llama-server": engine}, colliding)

	first, err := Ensure(ctx, st, colliding)
	if err != nil {
		t.Fatalf("unpacking the runtime whose flavour ends in the staging suffix: %v", err)
	}
	if _, err := Ensure(ctx, st, plain); err != nil {
		t.Fatalf("unpacking the plain runtime: %v", err)
	}
	// Positive state: the first engine is still where it was put.
	if _, err := os.Stat(first); err != nil {
		t.Fatalf("unpacking one runtime deleted another's engine: %v", err)
	}
}

func TestEnsureRefusesAConfigNamingTheStoreRoot(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	ref := "registry.example/runtimes/dots:1"
	seedHostileRuntime(t, st, Config{
		Name: "..", Build: "b1", Flavor: "cpu",
		OS: runtime.GOOS, Arch: runtime.GOARCH, Entrypoint: "llama-server",
	}, map[string][]byte{"llama-server": []byte("an engine unpacked a level too high")}, ref)

	if _, err := Ensure(ctx, st, ref); err == nil {
		t.Fatal(`a config naming ".." was accepted, so its directory and its removal sit above the runtimes tree`)
	} else if !strings.Contains(err.Error(), "single path component") {
		t.Errorf("the refusal does not say what is wrong with the config: %v", err)
	}
}

func TestEnsureRefusesALayerNamedDotDot(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	ref := "registry.example/runtimes/dotlayer:1"
	seedHostileRuntime(t, st, Config{
		Name: "llama-server", Build: "b1", Flavor: "cpu",
		OS: runtime.GOOS, Arch: runtime.GOARCH, Entrypoint: "llama-server",
	}, map[string][]byte{"llama-server": []byte("an engine"), "..": []byte("a layer naming a directory")}, ref)

	if _, err := Ensure(ctx, st, ref); err == nil {
		t.Fatal("a layer named \"..\" was accepted")
	} else if !strings.Contains(err.Error(), "invalid file name") {
		t.Errorf("the refusal comes from somewhere other than the name check: %v", err)
	}
}

func TestPackRefusesAConfigThatCannotBeUnpacked(t *testing.T) {
	st := openTestStore(t)
	cfg := Config{
		Name: "../../evil", Build: "b1", Flavor: "cpu",
		OS: runtime.GOOS, Arch: runtime.GOARCH, Entrypoint: "llama-server",
	}
	_, err := Pack(context.Background(), st, []PackFile{{Path: fakellamaBin, Name: "llama-server"}}, cfg, "r.example/x:y")
	if err == nil {
		t.Fatal("pack published a config every consumer will refuse")
	}
	if !strings.Contains(err.Error(), "single path component") {
		t.Errorf("the refusal does not say what is wrong with the config: %v", err)
	}
}
