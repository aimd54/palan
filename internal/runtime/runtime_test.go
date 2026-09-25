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

	"github.com/gofrs/flock"
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

	entry, err := ensureTag(ctx, st, ref)
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
	entry2, err := ensureTag(ctx, st, ref)
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
	if _, err := ensureTag(ctx, st, ref); err == nil || !strings.Contains(err.Error(), "plan9") {
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
	p, err := Resolve(context.Background(), st, "", ocispec.Descriptor{})
	if err != nil || p != fake {
		t.Errorf("resolve: %q (%v)", p, err)
	}

	t.Setenv("PATH", t.TempDir())
	if _, err := Resolve(context.Background(), st, "", ocispec.Descriptor{}); err == nil {
		t.Error("resolve must fail with no runtime anywhere")
	}
}

// ensureTag resolves a tag in the store and materializes what it names,
// which is the two steps the commands take. Ensure itself is given a
// descriptor so that the artifact a caller checked is the artifact that
// gets unpacked, and these tests are not checking anything.
func ensureTag(ctx context.Context, st *store.Store, ref string) (string, error) {
	desc, err := st.Resolve(ctx, ref)
	if err != nil {
		return "", err
	}
	return Ensure(ctx, st, ref, desc)
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

	entry, err := ensureTag(ctx, st, ref)
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

	again, err := ensureTag(ctx, st, ref)
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

	entry, err := ensureTag(ctx, st, ref)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	planted := filepath.Join(filepath.Dir(entry), "libevil.so")
	if err := os.WriteFile(planted, []byte("loaded from the runtime directory"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := ensureTag(ctx, st, ref); err != nil {
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

	if _, err := ensureTag(ctx, st, ref); err == nil {
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

	if _, err := ensureTag(ctx, st, ref); err == nil {
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

	entry, err := ensureTag(ctx, st, ref)
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

	if _, err := ensureTag(ctx, st, ref); err == nil {
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

	entry, err := ensureTag(ctx, st, ref)
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

	if _, err := ensureTag(ctx, st, ref); err != nil {
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

	entry, err := ensureTag(ctx, st, ref)
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

	if _, err := ensureTag(ctx, st, ref); err == nil {
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
	hostile := "registry.example/runtimes/llama-server:b9-cpu-alt"
	cfg := Config{
		Name: "llama-server", Build: "b9", Flavor: "cpu",
		OS: runtime.GOOS, Arch: runtime.GOARCH, Entrypoint: "llama-server",
	}
	seedHostileRuntime(t, st, cfg, map[string][]byte{"llama-server": []byte("an engine digested with an algorithm palan does not link")}, hostile)
	retagWithDigestAlgorithm(t, st, hostile, "md5:900150983cd24fb0d6963f7d28e17f72")

	// A tree already where this artifact unpacks, so there is a file on
	// disk to be compared against the digest.
	tree := filepath.Join(st.Root(), "runtimes", cfg.Name, cfg.dirName()+"-"+mustResolve(t, st, hostile).Digest.Encoded())
	if err := os.MkdirAll(tree, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree, "llama-server"), []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}

	// The refusal is the assertion: reaching this line at all means no
	// panic, and the message has to name the algorithm rather than blame
	// the file on disk.
	_, err := ensureTag(ctx, st, hostile)
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

func TestEnsureRefusesAConfigNamingTheStoreRoot(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	ref := "registry.example/runtimes/dots:1"
	seedHostileRuntime(t, st, Config{
		Name: "..", Build: "b1", Flavor: "cpu",
		OS: runtime.GOOS, Arch: runtime.GOARCH, Entrypoint: "llama-server",
	}, map[string][]byte{"llama-server": []byte("an engine unpacked a level too high")}, ref)

	if _, err := ensureTag(ctx, st, ref); err == nil {
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

	if _, err := ensureTag(ctx, st, ref); err == nil {
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

func TestEnsureRefusesTwoLayersClaimingOneFileName(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	ref := "registry.example/runtimes/clash:1"
	// seedHostileRuntime keys its files by name, so the manifest is built
	// here to carry the same title twice.
	seedHostileRuntime(t, st, Config{
		Name: "llama-server", Build: "b1", Flavor: "cpu",
		OS: runtime.GOOS, Arch: runtime.GOARCH, Entrypoint: "llama-server",
	}, map[string][]byte{"llama-server": []byte("the engine")}, ref)
	duplicateFirstLayer(t, st, ref)

	if _, err := ensureTag(ctx, st, ref); err == nil {
		t.Fatal("two layers claiming one file name were unpacked, so one silently replaced the other")
	} else if !strings.Contains(err.Error(), "llama-server") {
		t.Errorf("the refusal does not name the file both layers claim: %v", err)
	}
}

// duplicateFirstLayer re-tags ref with a manifest carrying its first layer
// twice, which is what a registry could serve and Pack will not produce.
func duplicateFirstLayer(t *testing.T, st *store.Store, ref string) {
	t.Helper()
	ctx := context.Background()
	manifest, err := store.FetchManifest(ctx, st.OCI(), mustResolve(t, st, ref))
	if err != nil {
		t.Fatal(err)
	}
	manifest.Layers = append(manifest.Layers, manifest.Layers[0])
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

func TestPackRefusesTwoFilesWithOneName(t *testing.T) {
	st := openTestStore(t)
	other := filepath.Join(t.TempDir(), "llama-server")
	if err := os.WriteFile(other, []byte("a different build of the same name"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		Name: "llama-server", Build: "b1", Flavor: "cpu",
		OS: runtime.GOOS, Arch: runtime.GOARCH, Entrypoint: "llama-server",
	}
	_, err := Pack(context.Background(), st, []PackFile{
		{Path: fakellamaBin, Name: "llama-server"},
		{Path: other, Name: "llama-server"},
	}, cfg, "r.example/x:y")
	if err == nil {
		t.Fatal("pack published an artifact whose two files claim one name")
	}
	if !strings.Contains(err.Error(), "llama-server") {
		t.Errorf("the refusal does not name the file: %v", err)
	}
}

// TestEnsureMaterializesTheArtifactItWasGiven: a tag is mutable and the
// store answers each question on its own, so resolving it to check an
// engine and resolving it again to unpack one asks twice and acts on the
// second answer. Between those two moments anything that can write to the
// store can move the tag, and what gets unpacked and executed is then not
// what was admitted.
//
// Both artifacts here declare the same name, build and flavour, so the only
// thing separating them is which descriptor Ensure was handed.
func TestEnsureMaterializesTheArtifactItWasGiven(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	const ref = "registry.example/runtimes/llama-server:b9-cpu"
	cfg := Config{
		Name: "llama-server", Build: "b9", OS: runtime.GOOS, Arch: runtime.GOARCH,
		Flavor: "cpu", Entrypoint: "llama-server",
	}

	admitted := []byte("#!/bin/sh\n# the engine that was checked\nexit 0\n")
	seedHostileRuntime(t, st, cfg, map[string][]byte{"llama-server": admitted}, ref)
	checked, err := st.Resolve(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}

	// The tag moves to a different engine, exactly as a concurrent pull of
	// another artifact under the same name would move it.
	substitute := []byte("#!/bin/sh\n# an engine nothing admitted\nexit 0\n")
	seedHostileRuntime(t, st, cfg, map[string][]byte{"llama-server": substitute}, ref)
	moved, err := st.Resolve(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	if moved.Digest == checked.Digest {
		t.Fatal("the fixture did not move the tag, so this test proves nothing")
	}

	entry, err := Ensure(ctx, st, ref, checked)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	got, err := os.ReadFile(entry) // #nosec G304 -- path returned by the code under test
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(admitted) {
		t.Fatalf("the engine on disk is not the one that was checked, it holds %q", got)
	}
}

// TestEnsureRefusesAnUnpackDirectoryThatIsALink: reading a directory
// follows a link at its name, so a tree somebody else owns can be checked
// file by file and found perfect, and the entrypoint handed back resolves
// through the link.
//
// The link holds byte-identical copies, which is the whole point. Files
// that differ are caught by the per-file check and repaired, so they
// survive nothing. Identical ones pass every check there is, the repair
// never runs, and the owner of the target can rewrite the binary
// afterwards for every load from then on.
func TestEnsureRefusesAnUnpackDirectoryThatIsALink(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	const ref = "registry.example/runtimes/llama-server:b9-cpu"
	cfg := Config{
		Name: "llama-server", Build: "b9", OS: runtime.GOOS, Arch: runtime.GOARCH,
		Flavor: "cpu", Entrypoint: "llama-server",
	}
	packed := []byte("#!/bin/sh\n# the engine the manifest records\nexit 0\n")
	seedHostileRuntime(t, st, cfg, map[string][]byte{"llama-server": packed}, ref)
	desc, err := st.Resolve(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := Ensure(ctx, st, ref, desc)
	if err != nil {
		t.Fatalf("first unpack: %v", err)
	}
	destDir := filepath.Dir(entry)

	// A tree the attacker owns, carrying byte-identical copies of every
	// file the manifest names, with the real directory replaced by a link
	// to it.
	shadow := filepath.Join(t.TempDir(), "shadow")
	if err := os.MkdirAll(shadow, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(shadow, "llama-server"), packed, 0o700); err != nil { // #nosec G306
		t.Fatal(err)
	}
	if err := os.RemoveAll(destDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(shadow, destDir); err != nil {
		t.Skipf("this filesystem does not support symlinks: %v", err)
	}

	entry2, err := Ensure(ctx, st, ref, desc)
	if err != nil {
		t.Fatalf("a linked unpack directory must be repaired, not refused outright: %v", err)
	}
	fi, err := os.Lstat(destDir)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("the unpack directory is still a link, so every later load checks somebody else's tree")
	}

	// What that buys, stated as the outcome rather than as the mechanism:
	// the owner of the linked tree rewrites the binary once the check has
	// passed, and the path palan hands to the supervisor must not follow
	// them there.
	substitute := []byte("#!/bin/sh\n# an engine nothing packed\nexit 7\n")
	if err := os.WriteFile(filepath.Join(shadow, "llama-server"), substitute, 0o700); err != nil { // #nosec G306
		t.Fatal(err)
	}
	got, err := os.ReadFile(entry2) // #nosec G304 -- path returned by the code under test
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(packed) {
		t.Fatalf("the engine palan would execute holds %q", got)
	}
}

// TestEnsureRefusesALinkAboveTheUnpackDirectory: Lstat refuses a link only
// at the last component of a path. Every component above the unpack
// directory is still resolved by whatever opens it, so a link at
// runtimes/<name> hands the whole tree, staging directory included, to
// whoever owns the target, and the check one level down reads that tree
// and finds it perfect.
func TestEnsureRefusesALinkAboveTheUnpackDirectory(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	const ref = "registry.example/runtimes/llama-server:b9-cpu"
	cfg := Config{
		Name: "llama-server", Build: "b9", OS: runtime.GOOS, Arch: runtime.GOARCH,
		Flavor: "cpu", Entrypoint: "llama-server",
	}
	packed := []byte("#!/bin/sh\n# the engine the manifest records\nexit 0\n")
	seedHostileRuntime(t, st, cfg, map[string][]byte{"llama-server": packed}, ref)
	desc, err := st.Resolve(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}

	// A tree the attacker owns, laid out exactly as the store's would be
	// and carrying byte-identical copies, with the name above the unpack
	// directory replaced by a link to it.
	shadow := filepath.Join(t.TempDir(), "shadow")
	unpackDir := cfg.dirName() + "-" + desc.Digest.Encoded()
	if err := os.MkdirAll(filepath.Join(shadow, unpackDir), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(shadow, unpackDir, "llama-server"), packed, 0o700); err != nil { // #nosec G306
		t.Fatal(err)
	}
	parent := filepath.Join(st.Root(), "runtimes", "llama-server")
	if err := os.MkdirAll(filepath.Dir(parent), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(parent); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(shadow, parent); err != nil {
		t.Skipf("this filesystem does not support symlinks: %v", err)
	}

	entry, err := Ensure(ctx, st, ref, desc)
	if err != nil {
		// Refused, which is the outcome this is about, and for the link.
		if !strings.Contains(err.Error(), parent) {
			t.Fatalf("refused, but not for the link at %s: %v", parent, err)
		}
		return
	}
	// Accepted. That is only sound if what it accepted is not the linked
	// tree, so the owner of that tree must not be able to change what runs.
	substitute := []byte("#!/bin/sh\n# an engine nothing packed\nexit 7\n")
	if err := os.WriteFile(filepath.Join(shadow, unpackDir, "llama-server"), substitute, 0o700); err != nil { // #nosec G306
		t.Fatal(err)
	}
	got, err := os.ReadFile(entry) // #nosec G304 -- path returned by the code under test
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(packed) {
		t.Fatalf("a link above the unpack directory decides what palan executes; it now holds %q", got)
	}
}

// TestEnsureWaitsForAnotherUnpack: deciding a tree needs replacing and
// replacing it happen under one lock across processes.
func TestEnsureWaitsForAnotherUnpack(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	ref := packRuntime(t, st)

	runtimes := filepath.Join(st.Root(), "runtimes")
	if err := os.MkdirAll(runtimes, 0o750); err != nil {
		t.Fatal(err)
	}
	other := flock.New(filepath.Join(runtimes, unpackLockName))
	if ok, err := other.TryLock(); err != nil || !ok {
		t.Fatalf("taking the unpack lock as another process would: ok=%v err=%v", ok, err)
	}

	type ensured struct {
		entry string
		err   error
	}
	got := make(chan ensured, 1)
	go func() {
		entry, err := ensureTag(ctx, st, ref)
		got <- ensured{entry, err}
	}()
	select {
	case e := <-got:
		_ = other.Unlock()
		t.Fatalf("ensure went ahead while another unpack held the lock (%q, %v)", e.entry, e.err)
	case <-time.After(500 * time.Millisecond):
	}
	if err := other.Unlock(); err != nil {
		t.Fatal(err)
	}

	var e ensured
	select {
	case e = <-got:
	case <-time.After(10 * time.Second):
		t.Fatal("ensure did not proceed once the other unpack finished")
	}
	if e.err != nil {
		t.Fatalf("ensure: %v", e.err)
	}
	packed, err := os.ReadFile(fakellamaBin)
	if err != nil {
		t.Fatal(err)
	}
	unpacked, err := os.ReadFile(e.entry) // #nosec G304 -- test fixture under a temp dir
	if err != nil {
		t.Fatalf("the engine ensure reported is not there: %v", err)
	}
	if !bytes.Equal(packed, unpacked) {
		t.Fatal("the engine ensure reported does not hold the packed bytes")
	}
}

// TestEnsureNeverReplacesAnotherArtifactsTree: two builds published under one
// name, build and flavour are different artifacts, and unpacking the second
// must leave the first where an engine already started from it.
func TestEnsureNeverReplacesAnotherArtifactsTree(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	cfg := Config{
		Name: "llama-server", Build: "b9", OS: runtime.GOOS, Arch: runtime.GOARCH,
		Flavor: "cpu", Entrypoint: "llama-server",
	}
	packed := map[string][]byte{}
	entries := map[string]string{}
	for _, ref := range []string{"registry.example/runtimes/llama-server:first", "registry.example/runtimes/llama-server:second"} {
		bin := filepath.Join(t.TempDir(), "llama-server")
		body := []byte("#!/bin/sh\n# " + ref + "\n")
		if err := os.WriteFile(bin, body, 0o755); err != nil { // #nosec G306 -- an executable fixture
			t.Fatal(err)
		}
		if _, err := Pack(ctx, st, []PackFile{{Path: bin, Name: "llama-server"}}, cfg, ref); err != nil {
			t.Fatalf("pack %s: %v", ref, err)
		}
		entry, err := ensureTag(ctx, st, ref)
		if err != nil {
			t.Fatalf("ensure %s: %v", ref, err)
		}
		packed[ref], entries[ref] = body, entry
	}
	if entries["registry.example/runtimes/llama-server:first"] == entries["registry.example/runtimes/llama-server:second"] {
		t.Fatalf("two artifacts unpacked to one path: %s", entries["registry.example/runtimes/llama-server:first"])
	}
	for ref, entry := range entries {
		got, err := os.ReadFile(entry) // #nosec G304 -- test fixture under a temp dir
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, packed[ref]) {
			t.Errorf("the engine unpacked for %s no longer holds its own bytes", ref)
		}
	}
}

// TestEnsureHoldsTheUnpackLockUntilTheTreeIsInPlace: removing the old tree
// and renaming the new one in are the steps the lock exists for, since two
// unpacks interleaving there each remove the tree the other has placed.
func TestEnsureHoldsTheUnpackLockUntilTheTreeIsInPlace(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	ref := packRuntime(t, st)
	var reached, held bool
	afterRemove = func() {
		reached = true
		rival := flock.New(filepath.Join(st.Root(), "runtimes", unpackLockName))
		ok, err := rival.TryLock()
		if ok {
			_ = rival.Unlock()
		}
		held = err == nil && !ok
	}
	defer func() { afterRemove = nil }()

	if _, err := ensureTag(ctx, st, ref); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if !reached {
		t.Fatal("the unpack never came between removing a tree and renaming one in")
	}
	if !held {
		t.Fatal("another unpack could take the lock between the old tree's removal and the new one's arrival")
	}
}

// TestEnsureRefusesALinkAtItsLockFile: the lock file is opened without
// following a link, so a link planted at its name creates nothing elsewhere.
func TestEnsureRefusesALinkAtItsLockFile(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	ref := packRuntime(t, st)
	runtimes := filepath.Join(st.Root(), "runtimes")
	if err := os.MkdirAll(runtimes, 0o750); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "created-through-the-link")
	if err := os.Symlink(target, filepath.Join(runtimes, unpackLockName)); err != nil {
		t.Skipf("this filesystem does not support symlinks: %v", err)
	}
	if _, err := ensureTag(ctx, st, ref); err == nil {
		t.Fatal("ensure took a lock through a link at the lock file's name")
	}
	if _, err := os.Lstat(target); err == nil {
		t.Fatal("opening the lock file created the link's target")
	}
}

// TestEnsureChecksItsDirectoriesAgainOnceLocked: the directories above the
// unpack directory are checked before the wait for the lock and again after
// it, since the wait can last as long as another unpack does.
func TestEnsureChecksItsDirectoriesAgainOnceLocked(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	ref := packRuntime(t, st)
	runtimes := filepath.Join(st.Root(), "runtimes")
	if err := os.MkdirAll(runtimes, 0o750); err != nil {
		t.Fatal(err)
	}
	other := flock.New(filepath.Join(runtimes, unpackLockName))
	if ok, err := other.TryLock(); err != nil || !ok {
		t.Fatalf("taking the unpack lock: ok=%v err=%v", ok, err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := ensureTag(ctx, st, ref)
		done <- err
	}()
	parent := filepath.Join(runtimes, "llama-server")
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(parent); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = other.Unlock()
			t.Fatal("ensure never reached the lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// While it waits, the directory it checked becomes a link elsewhere.
	shadow := t.TempDir()
	if err := os.Remove(parent); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(shadow, parent); err != nil {
		_ = other.Unlock()
		t.Skipf("this filesystem does not support symlinks: %v", err)
	}
	_ = other.Unlock()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("ensure unpacked through a link that appeared while it waited for the lock")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ensure did not return once the lock was free")
	}
	entries, err := os.ReadDir(shadow)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("ensure wrote %d entries through the link", len(entries))
	}
}

// TestEnsureRefusesANameBeginningWithADot: runtimes/ holds the store's own
// files beside each runtime's directory, the unpack lock among them.
func TestEnsureRefusesANameBeginningWithADot(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	const ref = "registry.example/runtimes/dotted:b1-cpu"
	cfg := Config{
		Name: unpackLockName, Build: "b1", OS: runtime.GOOS, Arch: runtime.GOARCH,
		Flavor: "cpu", Entrypoint: "llama-server",
	}
	seedHostileRuntime(t, st, cfg, map[string][]byte{"llama-server": []byte("#!/bin/sh\n")}, ref)
	_, err := ensureTag(ctx, st, ref)
	if err == nil || !strings.Contains(err.Error(), "begins with a dot") {
		t.Fatalf("a runtime named %q: %v, want it refused for the dot", unpackLockName, err)
	}
	// Nothing was made under that name, so the next unpack takes its lock.
	if fi, err := os.Lstat(filepath.Join(st.Root(), "runtimes", unpackLockName)); err == nil && fi.IsDir() {
		t.Fatalf("the refusal left a directory where the unpack lock lives")
	}
	if _, err := ensureTag(ctx, st, packRuntime(t, st)); err != nil {
		t.Fatalf("unpacking a runtime after the refusal: %v", err)
	}
}

// TestEnsureRefusesALinkAtTheRuntimesDirectory: runtimes/ itself is a path
// component the unpack creates, locks and renames beneath.
func TestEnsureRefusesALinkAtTheRuntimesDirectory(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	ref := packRuntime(t, st)
	shadow := t.TempDir()
	runtimes := filepath.Join(st.Root(), "runtimes")
	if err := os.RemoveAll(runtimes); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(shadow, runtimes); err != nil {
		t.Skipf("this filesystem does not support symlinks: %v", err)
	}
	_, err := ensureTag(ctx, st, ref)
	if err == nil || !strings.Contains(err.Error(), runtimes+" is a link") {
		t.Fatalf("a link at %s: %v, want it refused for the link", runtimes, err)
	}
	entries, err := os.ReadDir(shadow)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("ensure wrote %d entries through the link", len(entries))
	}
}
