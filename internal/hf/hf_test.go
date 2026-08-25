// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package hf

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aimd54/palan/internal/hf/hftest"
)

// testRevision is a well-formed commit sha, set as the default on every hub
// newFakeHub builds, so that every test exercising Resolve or Download
// through it runs against the pinned-revision path rather than the main
// fallback: a test that needs the fallback itself sets Revision to "" on the
// hub it builds directly with hftest.New.
const testRevision = "0123456789abcdef0123456789abcdef01234567"

func newFakeHub(t *testing.T, files map[string][]byte) *hftest.Hub {
	h := hftest.New(t, files)
	h.Revision = testRevision
	return h
}

func testClient(h *hftest.Hub) *Client { return &Client{HTTP: h.Client(), Endpoint: h.URL()} }

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
	res, err := testClient(h).Resolve(context.Background(), Ref{Repo: "org/repo", Path: "model.gguf"})
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string]File{}
	for _, f := range res.Files {
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
	res, err := testClient(h).Resolve(context.Background(), Ref{Repo: "org/repo", Path: "m-00001-of-00003.gguf"})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, f := range res.Files {
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
	res, err := c.Resolve(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	path, err := c.Download(context.Background(), ref, res.Revision, res.Files[0], dir, Events{})
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if b, _ := os.ReadFile(path); string(b) != "genuine weights" {
		t.Errorf("content = %q", b)
	}

	// Now serve different bytes for the same advertised digest.
	h.Corrupt = true
	dir2 := t.TempDir()
	if _, err := c.Download(context.Background(), ref, res.Revision, res.Files[0], dir2, Events{}); err == nil {
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
	h.TruncateAt = 1000 // each attempt delivers at most 1000 bytes
	c := testClient(h)
	ref := Ref{Repo: "org/repo", Path: "model.gguf"}
	res, err := c.Resolve(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	path, err := c.Download(context.Background(), ref, res.Revision, res.Files[0], dir, Events{})
	if err != nil {
		t.Fatalf("repeated short reads should still complete: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != string(body) {
		t.Fatalf("file is %d bytes, want %d", len(got), len(body))
	}
	// Progress must have accumulated rather than restarted each time.
	var resumed int
	for _, r := range h.Ranges {
		if r != "" && !strings.HasPrefix(r, "bytes=0-") {
			resumed++
		}
	}
	if resumed == 0 {
		t.Errorf("no attempt resumed from an offset; ranges seen: %v", h.Ranges)
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
	res, err := c.Resolve(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	// Plant a valid prefix, as an interrupted transfer would leave.
	if err := os.WriteFile(filepath.Join(dir, "model.gguf.partial"), body[:1000], 0o600); err != nil {
		t.Fatal(err)
	}
	path, err := c.Download(context.Background(), ref, res.Revision, res.Files[0], dir, Events{})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != string(body) {
		t.Errorf("resumed file is %d bytes, want %d", len(got), len(body))
	}
	var ranged bool
	for _, r := range h.Ranges {
		if strings.HasPrefix(r, "bytes=1000-") {
			ranged = true
		}
	}
	if !ranged {
		t.Errorf("resume should have asked for the remainder, ranges seen: %v", h.Ranges)
	}
}

// TestDownloadRestartsWhenRangeIgnored: a server that ignores Range must not
// leave the file with the prefix written twice.
func TestDownloadRestartsWhenRangeIgnored(t *testing.T) {
	body := []byte(strings.Repeat("weights", 500))
	h := newFakeHub(t, map[string][]byte{"model.gguf": body})
	h.IgnoreRange = true
	c := testClient(h)
	ref := Ref{Repo: "org/repo", Path: "model.gguf"}
	res, err := c.Resolve(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "model.gguf.partial"), body[:1000], 0o600); err != nil {
		t.Fatal(err)
	}
	path, err := c.Download(context.Background(), ref, res.Revision, res.Files[0], dir, Events{})
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
	h.Status = http.StatusForbidden
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

// TestFetchSmallDistinguishesAnUnpublishedFileFromOtherFailures proves the
// one status FetchSmall may read as "the repository does not publish this
// file" is a 404, so a caller can tell that apart from a fetch failure that
// says nothing about whether the file exists.
func TestFetchSmallDistinguishesAnUnpublishedFileFromOtherFailures(t *testing.T) {
	h := newFakeHub(t, map[string][]byte{"config.json": []byte("{}")})
	_, err := testClient(h).FetchSmall(context.Background(), Ref{Repo: "org/repo"}, "", "model.sig")
	if err == nil {
		t.Fatal("fetched a file the repository does not publish")
	}
	if !errors.Is(err, ErrFileNotFound) {
		t.Errorf("error = %v, want it to wrap ErrFileNotFound so a caller can tell an absent file from any other fetch failure", err)
	}
}

// TestFetchSmallDoesNotClaimAGatedFileIsUnpublished proves a gated
// repository is reported as gated, with the HF_TOKEN guidance intact, rather
// than folded into the same "file not found" case a 404 gets.
func TestFetchSmallDoesNotClaimAGatedFileIsUnpublished(t *testing.T) {
	h := newFakeHub(t, nil)
	h.Status = http.StatusForbidden
	_, err := testClient(h).FetchSmall(context.Background(), Ref{Repo: "meta/gated"}, "", "model.sig")
	if err == nil {
		t.Fatal("a gated repository must fail")
	}
	if errors.Is(err, ErrFileNotFound) {
		t.Error("a gated repository was reported the same way as one that never published the file")
	}
	for _, want := range []string{"gated", "HF_TOKEN"} {
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
	res, err := testClient(hub).Resolve(t.Context(), Ref{Repo: "org/repo"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	got := map[string]bool{}
	for _, f := range res.Files {
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
	res, err := testClient(hub).Resolve(t.Context(), Ref{Repo: "org/repo"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(res.Files) != 2 {
		t.Fatalf("resolved %d files, want the weights and the config", len(res.Files))
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
	hub.Inline = map[string]bool{"config.json": true}
	res, err := testClient(hub).Resolve(t.Context(), Ref{Repo: "org/repo"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	byPath := map[string]File{}
	for _, f := range res.Files {
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

func TestResolveReportsTheCommitTheListingCameFrom(t *testing.T) {
	hub := hftest.New(t, map[string][]byte{
		"model.safetensors": []byte("weights"),
		"config.json":       []byte(`{"architectures":["Qwen3ForCausalLM"]}`),
	})
	hub.Revision = "e4f2c1d0000000000000000000000000000000aa"

	res, err := testClient(hub).Resolve(t.Context(), Ref{Repo: "org/repo"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Revision != hub.Revision {
		t.Errorf("Revision = %q, want the commit the API reported", res.Revision)
	}
	if len(res.Files) != 2 {
		t.Fatalf("resolved %d files, want the weights and the config", len(res.Files))
	}
}

func TestResolveLeavesTheRevisionEmptyWhenTheApiOmitsIt(t *testing.T) {
	hub := hftest.New(t, map[string][]byte{
		"model.safetensors": []byte("weights"),
		"config.json":       []byte(`{}`),
	})
	hub.Revision = "" // the API reported no sha

	res, err := testClient(hub).Resolve(t.Context(), Ref{Repo: "org/repo"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Revision != "" {
		t.Errorf("Revision = %q, want empty: the repository stated none", res.Revision)
	}
}

func TestDownloadFetchesFromTheResolvedCommit(t *testing.T) {
	hub := hftest.New(t, map[string][]byte{"model.safetensors": []byte("weights")})
	hub.Revision = "e4f2c1d0000000000000000000000000000000aa"

	res, err := testClient(hub).Resolve(t.Context(), Ref{Repo: "org/repo"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, err := testClient(hub).Download(t.Context(), Ref{Repo: "org/repo"}, res.Revision, res.Files[0], t.TempDir(), Events{}); err != nil {
		t.Fatalf("Download: %v", err)
	}
	for _, got := range hub.Fetched {
		if got != hub.Revision {
			t.Errorf("downloaded from revision %q, want %q: a branch can move between listing and download",
				got, hub.Revision)
		}
	}
	if len(hub.Fetched) == 0 {
		t.Fatal("no download reached the hub")
	}
}

// TestResolveTreatsATraversalShapedRevisionAsNoRevision proves a sha the
// repository reports never reaches the download URL unless it is the exact
// shape of a git SHA-1 object id. A repository is untrusted text: this one
// reports a value shaped to walk the request into a different repository's
// path, and the only safe outcome is the same one a repository that reports
// no sha at all gets, the main fallback, never the malformed text itself.
func TestResolveTreatsATraversalShapedRevisionAsNoRevision(t *testing.T) {
	hub := hftest.New(t, map[string][]byte{"model.safetensors": []byte("weights")})
	hub.Revision = "../../other-org/other-repo/resolve/main"

	res, err := testClient(hub).Resolve(t.Context(), Ref{Repo: "org/repo"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Revision != "" {
		t.Errorf("Revision = %q, want empty: a value that is not a commit sha must not be used as one", res.Revision)
	}

	if _, err := testClient(hub).Download(t.Context(), Ref{Repo: "org/repo"}, res.Revision, res.Files[0], t.TempDir(), Events{}); err != nil {
		t.Fatalf("Download: %v", err)
	}
	if len(hub.Fetched) == 0 {
		t.Fatal("no download reached the hub")
	}
	for _, got := range hub.Fetched {
		if strings.Contains(got, "..") {
			t.Fatalf("the traversal-shaped revision reached the download URL: %q", got)
		}
		if got != "main" {
			t.Errorf("downloaded from %q, want the main fallback since the reported revision was unusable", got)
		}
	}
}

// TestDownloadFallsBackToMainWhenNoRevisionWasResolved proves the main
// fallback in Download's rev handling is load bearing: a resolution that
// carries no revision, exactly what a repository reporting no sha produces,
// must still be able to download. Deleting the fallback keeps every other
// test in this package green, since they all resolve a revision; this is
// the one test that a repository with no sha at all needs.
func TestDownloadFallsBackToMainWhenNoRevisionWasResolved(t *testing.T) {
	hub := hftest.New(t, map[string][]byte{"model.safetensors": []byte("weights")})

	res, err := testClient(hub).Resolve(t.Context(), Ref{Repo: "org/repo"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Revision != "" {
		t.Fatalf("Revision = %q, want empty for this test to exercise the fallback", res.Revision)
	}

	if _, err := testClient(hub).Download(t.Context(), Ref{Repo: "org/repo"}, res.Revision, res.Files[0], t.TempDir(), Events{}); err != nil {
		t.Fatalf("Download: %v", err)
	}
	if len(hub.Fetched) == 0 {
		t.Fatal("no download reached the hub")
	}
	for _, got := range hub.Fetched {
		if got != "main" {
			t.Errorf("downloaded from revision %q, want main: an empty revision must fall back to it", got)
		}
	}
}

// TestResolveRefusesAPathTheCallerNeverRequested: the path in a paths-info
// response names the file whose bytes are packed, becomes a URL segment on
// the way to fetching them, and is written into a signed annotation. A
// response substituting a different path would put another file's bytes,
// under another file's name, into the artifact and into the statement that
// vouches for it, so the response is held to the set that was asked for.
func TestResolveRefusesAPathTheCallerNeverRequested(t *testing.T) {
	hub := newFakeHub(t, map[string][]byte{"model.gguf": []byte("weights")})
	// A hostile or compromised endpoint: everything is served by the real
	// hub except the paths-info answer, which names a file of its choosing.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/paths-info/") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `[{"path":"hidden/other-org-weights.gguf","size":7}]`)
			return
		}
		hub.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	// Built directly rather than with NewClient, which reads HF_TOKEN from
	// the environment and would put a real credential in an Authorization
	// header aimed at this local server.
	c := &Client{HTTP: srv.Client(), Endpoint: srv.URL}
	_, err := c.Resolve(context.Background(), Ref{Repo: "org/repo", Path: "model.gguf"})
	if err == nil {
		t.Fatal("a substituted path was accepted, so the artifact would record a file that was never requested")
	}
	if !strings.Contains(err.Error(), "hidden/other-org-weights.gguf") {
		t.Errorf("the refusal must name the path it rejected, got: %v", err)
	}
}

// TestResolveRefusesADuplicatedPath: two files are requested and one of
// them comes back twice. The count matches, so the existing "metadata for
// N of M" check is satisfied, while the response covers only one of the two
// files. Nothing else would notice, and the licence would be packed with
// the weights' metadata under its own name.
func TestResolveRefusesADuplicatedPath(t *testing.T) {
	hub := newFakeHub(t, map[string][]byte{
		"model.gguf": []byte("weights"),
		"LICENSE":    []byte("Apache License, Version 2.0"),
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/paths-info/") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `[{"path":"model.gguf","size":7},{"path":"model.gguf","size":7}]`)
			return
		}
		hub.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	c := &Client{HTTP: srv.Client(), Endpoint: srv.URL}
	_, err := c.Resolve(context.Background(), Ref{Repo: "org/repo", Path: "model.gguf"})
	if err == nil {
		t.Fatal("a duplicated path was accepted, so a count check was satisfied by fewer files than were requested")
	}
	if !strings.Contains(err.Error(), "more than once") {
		t.Errorf("the refusal must say the response repeated a path, got: %v", err)
	}
}

// TestListingDropsAPathOutsideTheRepository: a listing entry is
// third-party text, and every later check treats it as legitimate because
// the repository itself reported it. A shard index naming such an entry
// would otherwise be admitted (the entry is "present"), fetched from a URL
// that a normalising server resolves to another repository's file, and
// written into the signed statement as this model's source.
func TestListingDropsAPathOutsideTheRepository(t *testing.T) {
	hub := newFakeHub(t, map[string][]byte{"model.safetensors": []byte("weights")})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/models/") && !strings.Contains(r.URL.Path, "paths-info") {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"sha":%q,"siblings":[{"rfilename":"model.safetensors"},{"rfilename":"../../victim/secret.safetensors"},{"rfilename":"/etc/passwd"}]}`, testRevision)
			return
		}
		hub.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	c := &Client{HTTP: srv.Client(), Endpoint: srv.URL}
	listing, _, err := c.listFiles(context.Background(), Ref{Repo: "org/repo"})
	if err != nil {
		t.Fatalf("listFiles: %v", err)
	}
	// The legitimate file survives, so this is not passing by rejecting
	// everything.
	if len(listing) != 1 || listing[0] != "model.safetensors" {
		t.Fatalf("listing = %q, want only the file inside the repository", listing)
	}
}

// TestResolveRefusesAPathOutsideTheRepositoryInPathsInfo covers the other
// decode point: the value that actually reaches the annotation is read
// here, so it is checked here too rather than trusted because the listing
// was filtered.
func TestResolveRefusesAPathOutsideTheRepositoryInPathsInfo(t *testing.T) {
	hub := newFakeHub(t, map[string][]byte{"model.gguf": []byte("weights")})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/paths-info/") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `[{"path":"../../victim/secret.safetensors","size":7}]`)
			return
		}
		hub.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	c := &Client{HTTP: srv.Client(), Endpoint: srv.URL}
	_, err := c.Resolve(context.Background(), Ref{Repo: "org/repo", Path: "model.gguf"})
	if err == nil {
		t.Fatal("a path outside the repository was accepted and would reach the signed statement")
	}
	if !strings.Contains(err.Error(), "not a path inside the repository") {
		t.Errorf("the refusal must say why, got: %v", err)
	}
}

// TestResolveAsksForTheLicenceOnce: the named file can also be the licence,
// so both ways a file enters the request name the same one. Asking twice
// gets two answers from a server behaving correctly, which the repeated
// path check would then blame the server for.
func TestResolveAsksForTheLicenceOnce(t *testing.T) {
	hub := newFakeHub(t, map[string][]byte{
		"LICENSE":    []byte("Apache License, Version 2.0"),
		"model.gguf": []byte("weights"),
	})
	c := testClient(hub)
	res, err := c.Resolve(context.Background(), Ref{Repo: "org/repo", Path: "LICENSE"})
	if err != nil {
		t.Fatalf("naming the licence directly must resolve: %v", err)
	}
	if len(res.Files) != 1 || res.Files[0].Path != "LICENSE" {
		t.Errorf("resolved %d files (%+v), want the licence exactly once", len(res.Files), res.Files)
	}
}
