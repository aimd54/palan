// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package hf

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeHub serves the two API endpoints and file downloads that palan uses,
// so the whole path is exercised without touching the network.
type fakeHub struct {
	files map[string][]byte // path in repo → contents
	// inline names files paths-info reports with no LFS digest, matching how
	// the real API serves small files stored inline rather than in LFS.
	inline map[string]bool
	// status, when non-zero, is returned for every request.
	status int
	// ignoreRange serves the whole body even when a Range is asked for,
	// which some CDNs do.
	ignoreRange bool
	// truncateAt, when > 0, serves only that many bytes and drops.
	truncateAt int
	// corrupt serves bytes that do not match the advertised digest.
	corrupt bool
	srv     *httptest.Server
	ranges  []string
}

func newFakeHub(t *testing.T, files map[string][]byte) *fakeHub {
	t.Helper()
	h := &fakeHub{files: files}
	h.srv = httptest.NewServer(h)
	t.Cleanup(h.srv.Close)
	return h
}

func (h *fakeHub) URL() string { return h.srv.URL }

func (h *fakeHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.status != 0 {
		w.WriteHeader(h.status)
		return
	}
	switch {
	case strings.HasSuffix(r.URL.Path, "/paths-info/main"):
		var req struct {
			Paths []string `json:"paths"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		type lfs struct {
			OID string `json:"oid"`
		}
		var out []map[string]any
		for _, p := range req.Paths {
			b, ok := h.files[p]
			if !ok {
				continue
			}
			if h.inline[p] {
				out = append(out, map[string]any{"path": p, "size": len(b)})
				continue
			}
			sum := sha256.Sum256(b)
			out = append(out, map[string]any{
				"path": p, "size": len(b),
				"lfs": lfs{OID: hex.EncodeToString(sum[:])},
			})
		}
		_ = json.NewEncoder(w).Encode(out)

	case strings.Contains(r.URL.Path, "/api/models/"):
		type sib struct {
			Filename string `json:"rfilename"`
		}
		var sibs []sib
		for p := range h.files {
			sibs = append(sibs, sib{Filename: p})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"siblings": sibs})

	case strings.Contains(r.URL.Path, "/resolve/main/"):
		i := strings.Index(r.URL.Path, "/resolve/main/")
		name := r.URL.Path[i+len("/resolve/main/"):]
		b, ok := h.files[name]
		if !ok {
			http.Error(w, "no such file", http.StatusNotFound)
			return
		}
		if h.corrupt {
			b = append([]byte("x"), b[1:]...)
		}
		rng := r.Header.Get("Range")
		h.ranges = append(h.ranges, rng)
		start := 0
		if rng != "" && !h.ignoreRange {
			_, _ = fmt.Sscanf(rng, "bytes=%d-", &start)
			if start > len(b) {
				http.Error(w, "bad range", http.StatusRequestedRangeNotSatisfiable)
				return
			}
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, len(b)-1, len(b)))
			w.WriteHeader(http.StatusPartialContent)
		}
		body := b[start:]
		if h.truncateAt > 0 && len(body) > h.truncateAt {
			body = body[:h.truncateAt]
		}
		_, _ = w.Write(body)

	default:
		http.Error(w, "unexpected "+r.URL.Path, http.StatusNotFound)
	}
}

func testClient(h *fakeHub) *Client {
	return &Client{HTTP: h.srv.Client(), Endpoint: h.URL()}
}

func TestParseRef(t *testing.T) {
	ok := []struct {
		in   string
		repo string
		path string
	}{
		{"hf://Qwen/Qwen3-8B-GGUF/Q4.gguf", "Qwen/Qwen3-8B-GGUF", "Q4.gguf"},
		{"hf://org/repo/nested/dir/file.gguf", "org/repo", "nested/dir/file.gguf"},
		{"hf://org/repo", "org/repo", ""},
		{"hf://org/repo/", "org/repo", ""},
		{"hf://org/repo/file.gguf?download=true", "org/repo", "file.gguf"},
	}
	for _, tc := range ok {
		got, err := ParseRef(tc.in)
		if err != nil {
			t.Errorf("ParseRef(%q): %v", tc.in, err)
			continue
		}
		if got.Repo != tc.repo || got.Path != tc.path {
			t.Errorf("ParseRef(%q) = %+v, want repo %q path %q", tc.in, got, tc.repo, tc.path)
		}
	}
	bad := []string{
		"hf://", "hf://org", "hf:///repo", "hf://org/",
		"hf://org/repo/../../etc/passwd",
		"/local/path.gguf", "https://example/x.gguf",
	}
	for _, in := range bad {
		if _, err := ParseRef(in); err == nil {
			t.Errorf("ParseRef(%q) should have failed", in)
		}
	}
}

func TestResolveRejectsBareRepoAndNamesTheOptions(t *testing.T) {
	h := newFakeHub(t, map[string][]byte{
		"Q4_K_M.gguf": []byte("weights-a"),
		"Q8_0.gguf":   []byte("weights-b"),
		"README.md":   []byte("hi"),
	})
	_, err := testClient(h).Resolve(context.Background(), Ref{Repo: "org/repo"})
	if !errors.Is(err, ErrNoFile) {
		t.Fatalf("a bare repository should ask which file, got %v", err)
	}
	// Guessing a quantisation would be worse than saying what exists.
	for _, want := range []string{"Q4_K_M.gguf", "Q8_0.gguf"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error should list %s: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "README.md") {
		t.Errorf("only .gguf files are useful suggestions: %v", err)
	}
}

func TestResolveCarriesUpstreamDigestAndLicense(t *testing.T) {
	weights := []byte("the weights")
	h := newFakeHub(t, map[string][]byte{
		"model.gguf": weights,
		"LICENSE":    []byte("apache"),
		"README.md":  []byte("hi"),
	})
	files, err := testClient(h).Resolve(context.Background(), Ref{Repo: "org/repo", Path: "model.gguf"})
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string]File{}
	for _, f := range files {
		byPath[f.Path] = f
	}
	if _, ok := byPath["LICENSE"]; !ok {
		t.Error("a licence in the repository should travel with the weights")
	}
	if _, ok := byPath["README.md"]; ok {
		t.Error("unrelated files should not be pulled in")
	}
	sum := sha256.Sum256(weights)
	if got := byPath["model.gguf"].SHA256; got != hex.EncodeToString(sum[:]) {
		t.Errorf("upstream digest = %q, want the repository's own", got)
	}
}

// TestResolveFetchesEverySplitPart: naming one part of a split GGUF must not
// produce an artifact holding only that part, which would look complete and
// fail to load.
func TestResolveFetchesEverySplitPart(t *testing.T) {
	h := newFakeHub(t, map[string][]byte{
		"m-00001-of-00003.gguf":     []byte("a"),
		"m-00002-of-00003.gguf":     []byte("b"),
		"m-00003-of-00003.gguf":     []byte("c"),
		"other-00001-of-00002.gguf": []byte("z"),
	})
	files, err := testClient(h).Resolve(context.Background(), Ref{Repo: "org/repo", Path: "m-00001-of-00003.gguf"})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, f := range files {
		got[f.Path] = true
	}
	for i := 1; i <= 3; i++ {
		want := fmt.Sprintf("m-%05d-of-00003.gguf", i)
		if !got[want] {
			t.Errorf("missing part %s from %v", want, got)
		}
	}
	if got["other-00001-of-00002.gguf"] {
		t.Error("a different split set must not be pulled in")
	}
}

func TestDownloadVerifiesAgainstUpstreamDigest(t *testing.T) {
	h := newFakeHub(t, map[string][]byte{"model.gguf": []byte("genuine weights")})
	c := testClient(h)
	ref := Ref{Repo: "org/repo", Path: "model.gguf"}
	files, err := c.Resolve(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	path, err := c.Download(context.Background(), ref, files[0], dir, Events{})
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if b, _ := os.ReadFile(path); string(b) != "genuine weights" {
		t.Errorf("content = %q", b)
	}

	// Now serve different bytes for the same advertised digest.
	h.corrupt = true
	dir2 := t.TempDir()
	if _, err := c.Download(context.Background(), ref, files[0], dir2, Events{}); err == nil {
		t.Error("bytes that do not match the published digest must be refused")
	} else if !strings.Contains(err.Error(), "refusing") {
		t.Errorf("the refusal should say what happened: %v", err)
	}
	// Nothing usable may be left behind for a later step to pick up.
	if entries, _ := os.ReadDir(dir2); len(entries) != 0 {
		t.Errorf("a refused download left %d file(s) behind", len(entries))
	}
}

// TestDownloadResumesAfterDroppedConnections: a server that cuts every
// response short must still produce a complete, correct file, because each
// attempt keeps what arrived and continues from there. Deleting the partial on
// a short read would make every dropped connection start over.
func TestDownloadResumesAfterDroppedConnections(t *testing.T) {
	body := []byte(strings.Repeat("weights", 500)) // 3500 bytes
	h := newFakeHub(t, map[string][]byte{"model.gguf": body})
	h.truncateAt = 1000 // each attempt delivers at most 1000 bytes
	c := testClient(h)
	ref := Ref{Repo: "org/repo", Path: "model.gguf"}
	files, err := c.Resolve(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	path, err := c.Download(context.Background(), ref, files[0], dir, Events{})
	if err != nil {
		t.Fatalf("repeated short reads should still complete: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != string(body) {
		t.Fatalf("file is %d bytes, want %d", len(got), len(body))
	}
	// Progress must have accumulated rather than restarted each time.
	var resumed int
	for _, r := range h.ranges {
		if r != "" && !strings.HasPrefix(r, "bytes=0-") {
			resumed++
		}
	}
	if resumed == 0 {
		t.Errorf("no attempt resumed from an offset; ranges seen: %v", h.ranges)
	}
	if _, err := os.Stat(path + ".partial"); !os.IsNotExist(err) {
		t.Error("the partial file should be gone once the download completes")
	}
}

// TestDownloadRangeResumeContinues checks the resume path directly: a partial
// file already on disk must produce a ranged request rather than starting over.
func TestDownloadRangeResumeContinues(t *testing.T) {
	body := []byte(strings.Repeat("weights", 500))
	h := newFakeHub(t, map[string][]byte{"model.gguf": body})
	c := testClient(h)
	ref := Ref{Repo: "org/repo", Path: "model.gguf"}
	files, err := c.Resolve(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	// Plant a valid prefix, as an interrupted transfer would leave.
	if err := os.WriteFile(filepath.Join(dir, "model.gguf.partial"), body[:1000], 0o600); err != nil {
		t.Fatal(err)
	}
	path, err := c.Download(context.Background(), ref, files[0], dir, Events{})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != string(body) {
		t.Errorf("resumed file is %d bytes, want %d", len(got), len(body))
	}
	var ranged bool
	for _, r := range h.ranges {
		if strings.HasPrefix(r, "bytes=1000-") {
			ranged = true
		}
	}
	if !ranged {
		t.Errorf("resume should have asked for the remainder, ranges seen: %v", h.ranges)
	}
}

// TestDownloadRestartsWhenRangeIgnored: a server that ignores Range must not
// leave the file with the prefix written twice.
func TestDownloadRestartsWhenRangeIgnored(t *testing.T) {
	body := []byte(strings.Repeat("weights", 500))
	h := newFakeHub(t, map[string][]byte{"model.gguf": body})
	h.ignoreRange = true
	c := testClient(h)
	ref := Ref{Repo: "org/repo", Path: "model.gguf"}
	files, err := c.Resolve(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "model.gguf.partial"), body[:1000], 0o600); err != nil {
		t.Fatal(err)
	}
	path, err := c.Download(context.Background(), ref, files[0], dir, Events{})
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != string(body) {
		t.Errorf("file is %d bytes, want %d: a restart must truncate, not append", len(got), len(body))
	}
}

func TestGatedRepositoryExplainsItself(t *testing.T) {
	h := newFakeHub(t, nil)
	h.status = http.StatusForbidden
	_, err := testClient(h).Resolve(context.Background(), Ref{Repo: "meta/gated", Path: "m.gguf"})
	if err == nil {
		t.Fatal("a gated repository must fail")
	}
	for _, want := range []string{"gated", "HF_TOKEN", "meta/gated"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error should mention %q: %v", want, err)
		}
	}
}

func TestResolveWholeRepositoryTakesTheShardsTheIndexNames(t *testing.T) {
	hub := newFakeHub(t, map[string][]byte{
		"model.safetensors.index.json":     []byte(`{"metadata":{"total_size":8},"weight_map":{"a":"model-00001-of-00002.safetensors","b":"model-00002-of-00002.safetensors"}}`),
		"model-00001-of-00002.safetensors": []byte("shard-one"),
		"model-00002-of-00002.safetensors": []byte("shard-two"),
		"config.json":                      []byte(`{"architectures":["Qwen3ForCausalLM"]}`),
		"tokenizer.json":                   []byte("{}"),
		"LICENSE":                          []byte("Apache-2.0"),
		// Published beside the model and not part of it: a second
		// quantisation the index does not name.
		"model-q4.safetensors": []byte("other-model"),
	})
	files, err := testClient(hub).Resolve(t.Context(), Ref{Repo: "org/repo"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	got := map[string]bool{}
	for _, f := range files {
		got[f.Path] = true
		if f.SHA256 == "" {
			t.Errorf("%s resolved without the digest the repository publishes", f.Path)
		}
	}
	for _, want := range []string{
		"model.safetensors.index.json", "model-00001-of-00002.safetensors",
		"model-00002-of-00002.safetensors", "config.json", "tokenizer.json", "LICENSE",
	} {
		if !got[want] {
			t.Errorf("Resolve did not select %q", want)
		}
	}
	if got["model-q4.safetensors"] {
		t.Error("Resolve selected a weight file the index does not name")
	}
}

func TestResolveWholeRepositoryTakesASingleShardModel(t *testing.T) {
	hub := newFakeHub(t, map[string][]byte{
		"model.safetensors": []byte("weights"),
		"config.json":       []byte(`{"architectures":["Qwen3ForCausalLM"]}`),
	})
	files, err := testClient(hub).Resolve(t.Context(), Ref{Repo: "org/repo"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("resolved %d files, want the weights and the config", len(files))
	}
}

func TestResolveRefusesARepositoryMissingAShardItsIndexNames(t *testing.T) {
	hub := newFakeHub(t, map[string][]byte{
		"model.safetensors.index.json":     []byte(`{"metadata":{"total_size":8},"weight_map":{"a":"model-00001-of-00002.safetensors","b":"model-00002-of-00002.safetensors"}}`),
		"model-00001-of-00002.safetensors": []byte("shard-one"),
		"config.json":                      []byte(`{}`),
	})
	_, err := testClient(hub).Resolve(t.Context(), Ref{Repo: "org/repo"})
	if err == nil {
		t.Fatal("resolved a model whose second shard the repository does not publish")
	}
	if !strings.Contains(err.Error(), "model-00002-of-00002.safetensors") {
		t.Errorf("the refusal does not name the missing shard: %v", err)
	}
}

func TestResolveStillAsksWhichFileForAGGUFRepository(t *testing.T) {
	hub := newFakeHub(t, map[string][]byte{
		"qwen3-8b-q4_k_m.gguf": []byte("gguf-bytes"),
	})
	_, err := testClient(hub).Resolve(t.Context(), Ref{Repo: "org/repo"})
	if !errors.Is(err, ErrNoFile) {
		t.Fatalf("err = %v, want ErrNoFile so the caller is asked which quantisation", err)
	}
}

// TestResolveWholeRepositoryLeavesInlineFilesWithoutADigest: the API reports
// an LFS digest only for files stored in LFS. A small file such as
// config.json is served inline with none, and resolving the repository must
// carry that file through with an empty SHA256 rather than inventing one or
// refusing the file.
func TestResolveWholeRepositoryLeavesInlineFilesWithoutADigest(t *testing.T) {
	hub := newFakeHub(t, map[string][]byte{
		"model.safetensors": []byte("weights"),
		"config.json":       []byte(`{"architectures":["Qwen3ForCausalLM"]}`),
	})
	hub.inline = map[string]bool{"config.json": true}
	files, err := testClient(hub).Resolve(t.Context(), Ref{Repo: "org/repo"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	byPath := map[string]File{}
	for _, f := range files {
		byPath[f.Path] = f
	}
	cfg, ok := byPath["config.json"]
	if !ok {
		t.Fatal("Resolve did not select config.json")
	}
	if cfg.SHA256 != "" {
		t.Errorf("config.json SHA256 = %q, want empty: the repository serves it inline with no digest", cfg.SHA256)
	}
	if got := byPath["model.safetensors"].SHA256; got == "" {
		t.Error("model.safetensors resolved without the digest the repository publishes")
	}
}

// FuzzParseRef: hf:// strings come from the command line and end up shaping
// URLs, so parsing must never panic and must never yield a traversal segment.
func FuzzParseRef(f *testing.F) {
	for _, s := range []string{
		"hf://org/repo/file.gguf", "hf://", "hf://a/b/../c",
		"hf://a/b/c?x=1#y", "hf:////", "hf://a/b/" + strings.Repeat("x/", 50),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		ref, err := ParseRef(s)
		if err != nil {
			return
		}
		if strings.Count(ref.Repo, "/") != 1 {
			t.Fatalf("repo %q must be exactly org/name", ref.Repo)
		}
		for _, seg := range strings.Split(ref.Path, "/") {
			if seg == ".." || seg == "." {
				t.Fatalf("path %q kept a traversal segment", ref.Path)
			}
		}
	})
}
