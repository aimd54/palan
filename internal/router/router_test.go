// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aimd54/palan/internal/runtime"
)

var fakellamaBin string

func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "palan-router-test-*")
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

// fakeBackend serves a fixed set of models via fakellama, with per-model
// memory estimates.
type fakeBackend struct {
	models map[string]int64 // ref → estimated memory
}

func (b *fakeBackend) List(context.Context) ([]string, error) {
	out := make([]string, 0, len(b.models))
	for ref := range b.models {
		out = append(out, ref)
	}
	return out, nil
}

func (b *fakeBackend) Spec(_ context.Context, ref string) (runtime.Spec, int64, error) {
	mem, ok := b.models[ref]
	if !ok {
		return runtime.Spec{}, 0, fmt.Errorf("unknown model")
	}
	return runtime.Spec{
		Bin:          fakellamaBin,
		ModelPath:    "/fake/" + strings.NewReplacer("/", "_", ":", "_").Replace(ref) + ".gguf",
		Alias:        ref,
		StartTimeout: 30 * time.Second,
	}, mem, nil
}

func newTestRouter(t *testing.T, opts Options) (*Router, *httptest.Server) {
	t.Helper()
	if opts.Backend == nil {
		opts.Backend = &fakeBackend{models: map[string]int64{"llm/a:1": 100, "llm/b:1": 100}}
	}
	if opts.SweepInterval <= 0 {
		opts.SweepInterval = 50 * time.Millisecond
	}
	rt, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(rt)
	t.Cleanup(func() {
		srv.Close()
		rt.Shutdown(context.Background())
	})
	return rt, srv
}

// chat posts a chat completion and returns status + body.
func chat(t *testing.T, url, model, prompt string, stream bool, header http.Header) (int, string) {
	t.Helper()
	body := fmt.Sprintf(`{"model":%q,"stream":%v,"messages":[{"role":"user","content":%q}]}`, model, stream, prompt)
	req, err := http.NewRequest(http.MethodPost, url+"/v1/chat/completions", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	maps.Copy(req.Header, header)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func loadedCount(rt *Router) int {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return len(rt.loaded)
}

func TestLazyLoadAndRouteTwoModels(t *testing.T) {
	rt, srv := newTestRouter(t, Options{MemoryBudget: 1000, IdleTimeout: time.Hour})

	code, body := chat(t, srv.URL, "llm/a:1", "hello", false, nil)
	if code != 200 || !strings.Contains(body, "llm_a_1.gguf") {
		t.Fatalf("model a: %d %s", code, body)
	}
	code, body = chat(t, srv.URL, "llm/b:1", "hello", false, nil)
	if code != 200 || !strings.Contains(body, "llm_b_1.gguf") {
		t.Fatalf("model b: %d %s", code, body)
	}
	if n := loadedCount(rt); n != 2 {
		t.Errorf("expected 2 loaded instances, got %d", n)
	}
	// Same model again: no additional load (still 2).
	code, _ = chat(t, srv.URL, "llm/a:1", "again", false, nil)
	if code != 200 || loadedCount(rt) != 2 {
		t.Errorf("re-request changed instance count: %d", loadedCount(rt))
	}
}

func TestUnknownModelIs404(t *testing.T) {
	_, srv := newTestRouter(t, Options{MemoryBudget: 1000, IdleTimeout: time.Hour})
	code, body := chat(t, srv.URL, "llm/none:1", "x", false, nil)
	if code != http.StatusNotFound || !strings.Contains(body, "not servable") {
		t.Errorf("unknown model: %d %s", code, body)
	}
}

func TestMissingModelFieldIs400(t *testing.T) {
	_, srv := newTestRouter(t, Options{MemoryBudget: 1000, IdleTimeout: time.Hour})
	resp, err := http.Post(srv.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{"messages":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("missing model: %d", resp.StatusCode)
	}
}

func TestStreamingPassesThrough(t *testing.T) {
	_, srv := newTestRouter(t, Options{MemoryBudget: 1000, IdleTimeout: time.Hour})
	code, body := chat(t, srv.URL, "llm/a:1", "stream me", true, nil)
	if code != 200 {
		t.Fatalf("stream: %d %s", code, body)
	}
	if !strings.Contains(body, "data: ") || !strings.Contains(body, "[DONE]") {
		t.Errorf("SSE stream mangled:\n%s", body)
	}
}

func TestMemoryBudgetEvictsLRU(t *testing.T) {
	rt, srv := newTestRouter(t, Options{
		Backend:      &fakeBackend{models: map[string]int64{"llm/a:1": 600, "llm/b:1": 600}},
		MemoryBudget: 1000, // fits exactly one model
		IdleTimeout:  time.Hour,
	})

	if code, _ := chat(t, srv.URL, "llm/a:1", "x", false, nil); code != 200 {
		t.Fatal("load a failed")
	}
	if code, _ := chat(t, srv.URL, "llm/b:1", "x", false, nil); code != 200 {
		t.Fatal("load b failed (eviction did not happen?)")
	}
	rt.mu.Lock()
	_, aLoaded := rt.loaded["llm/a:1"]
	_, bLoaded := rt.loaded["llm/b:1"]
	rt.mu.Unlock()
	if aLoaded || !bLoaded {
		t.Errorf("expected a evicted and b loaded; a=%v b=%v", aLoaded, bLoaded)
	}
}

func TestOverBudgetModelRejected(t *testing.T) {
	_, srv := newTestRouter(t, Options{
		Backend:      &fakeBackend{models: map[string]int64{"llm/huge:1": 5000}},
		MemoryBudget: 1000,
		IdleTimeout:  time.Hour,
	})
	code, body := chat(t, srv.URL, "llm/huge:1", "x", false, nil)
	if code != http.StatusInsufficientStorage {
		t.Errorf("over-budget model: %d %s", code, body)
	}
}

func TestBusyInstanceNotEvicted(t *testing.T) {
	t.Setenv("FAKELLAMA_RESPONSE_DELAY", "2s")
	_, srv := newTestRouter(t, Options{
		Backend:      &fakeBackend{models: map[string]int64{"llm/a:1": 600, "llm/b:1": 600}},
		MemoryBudget: 1000,
		IdleTimeout:  time.Hour,
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Long-running request holds model a busy.
		code, _ := chat(t, srv.URL, "llm/a:1", "slow", false, nil)
		if code != 200 {
			t.Errorf("slow request on a: %d", code)
		}
	}()
	// Give the slow request time to load a and enter the delay.
	time.Sleep(1 * time.Second)

	code, body := chat(t, srv.URL, "llm/b:1", "x", false, nil)
	if code != http.StatusServiceUnavailable {
		t.Errorf("b while a busy: expected 503, got %d %s", code, body)
	}
	<-done
}

func TestIdleUnload(t *testing.T) {
	rt, srv := newTestRouter(t, Options{
		MemoryBudget:  1000,
		IdleTimeout:   200 * time.Millisecond,
		SweepInterval: 50 * time.Millisecond,
	})
	if code, _ := chat(t, srv.URL, "llm/a:1", "x", false, nil); code != 200 {
		t.Fatal("load failed")
	}
	deadline := time.Now().Add(5 * time.Second)
	for loadedCount(rt) != 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if n := loadedCount(rt); n != 0 {
		t.Errorf("instance not idle-unloaded (still %d loaded)", n)
	}
}

func TestKeepLoadedSurvivesIdleSweep(t *testing.T) {
	rt, srv := newTestRouter(t, Options{
		MemoryBudget:  1000,
		IdleTimeout:   100 * time.Millisecond,
		SweepInterval: 30 * time.Millisecond,
		KeepLoaded:    []string{"llm/a:1"},
	})
	if code, _ := chat(t, srv.URL, "llm/a:1", "x", false, nil); code != 200 {
		t.Fatal("load failed")
	}
	time.Sleep(500 * time.Millisecond)
	if n := loadedCount(rt); n != 1 {
		t.Errorf("keep-loaded model was unloaded (loaded=%d)", n)
	}
}

func TestCrashedInstanceRespawnsOnNextRequest(t *testing.T) {
	t.Setenv("FAKELLAMA_EXIT_AFTER", "300ms")
	rt, srv := newTestRouter(t, Options{MemoryBudget: 1000, IdleTimeout: time.Hour})

	if code, _ := chat(t, srv.URL, "llm/a:1", "x", false, nil); code != 200 {
		t.Fatal("initial load failed")
	}
	// Wait for the crash reaper to remove the instance.
	deadline := time.Now().Add(5 * time.Second)
	for loadedCount(rt) != 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if loadedCount(rt) != 0 {
		t.Fatal("crashed instance never reaped")
	}
	// Next request spawns a fresh child (which will also crash later, but
	// answers first).
	if code, body := chat(t, srv.URL, "llm/a:1", "again", false, nil); code != 200 {
		t.Errorf("respawn failed: %d %s", code, body)
	}
}

func TestBearerAuth(t *testing.T) {
	_, srv := newTestRouter(t, Options{MemoryBudget: 1000, IdleTimeout: time.Hour, BearerToken: "s3cret"})

	code, _ := chat(t, srv.URL, "llm/a:1", "x", false, nil)
	if code != http.StatusUnauthorized {
		t.Errorf("no token: %d", code)
	}
	h := http.Header{}
	h.Set("Authorization", "Bearer s3cret")
	if code, _ := chat(t, srv.URL, "llm/a:1", "x", false, h); code != 200 {
		t.Errorf("valid token rejected: %d", code)
	}

	resp, err := http.Get(srv.URL + "/v1/models")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("models without token: %d", resp.StatusCode)
	}
}

func TestModelsEndpoint(t *testing.T) {
	_, srv := newTestRouter(t, Options{MemoryBudget: 1000, IdleTimeout: time.Hour})
	resp, err := http.Get(srv.URL + "/v1/models")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Data) != 2 {
		t.Errorf("expected 2 models, got %+v", out.Data)
	}
}

func TestParseBudget(t *testing.T) {
	cases := map[string]int64{
		"1024":   1024,
		"8GiB":   8 << 30,
		"8G":     8 << 30,
		"512MiB": 512 << 20,
		"1.5GiB": 3 << 29,
	}
	for in, want := range cases {
		got, err := ParseBudget(in)
		if err != nil || got != want {
			t.Errorf("ParseBudget(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "abc", "-1G"} {
		if _, err := ParseBudget(bad); err == nil {
			t.Errorf("ParseBudget(%q) should fail", bad)
		}
	}
}
