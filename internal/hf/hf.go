// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

// Package hf fetches model files from Hugging Face so they can be packed
// without a separate download step.
//
// This is a connected-side convenience: it seeds a registry that an offline
// site then mirrors from. It is compiled in rather than hidden behind a build
// tag (ADR-0009), because it costs one HTTP client and an air-gapped operator
// simply never names an hf:// source.
//
// The API reports each file's upstream SHA-256, which is checked as the
// download streams and recorded as io.palan.origin.sha256. A file that does
// not match what the repository published is refused rather than packed.
package hf

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/aimd54/palan/internal/safetensors"
	"github.com/aimd54/palan/internal/transfer"
)

// Scheme prefixes a Hugging Face source: hf://<org>/<repo>/<path in repo>.
const Scheme = "hf://"

// endpoint is the API host; HF_ENDPOINT overrides it for mirrors and tests.
const defaultEndpoint = "https://huggingface.co"

// ErrNoFile marks a reference that names a repository but not a file.
var ErrNoFile = errors.New("no file named in the reference")

// splitPart matches llama.cpp's multi-part naming, model-00001-of-00003.gguf.
// Packing only the part that was named would produce an artifact that looks
// complete and cannot load, so every sibling is fetched.
var splitPart = regexp.MustCompile(`^(.*)-(\d{5})-of-(\d{5})(\.gguf)$`)

// Ref is a parsed hf:// reference.
type Ref struct {
	Repo string // "org/name"
	Path string // path within the repository; empty means none was given
}

// File is one downloadable file with the digest the repository published.
type File struct {
	Path string // path within the repository
	Size int64
	// SHA256 is the upstream digest, empty when the file is not stored in
	// LFS (small files such as LICENSE are served inline).
	SHA256 string
}

// URL returns the repository's web page, used as the packed artifact's source
// annotation.
func (r Ref) URL() string { return defaultEndpoint + "/" + r.Repo }

// IsRef reports whether an argument is a Hugging Face source rather than a
// local path.
func IsRef(s string) bool { return strings.HasPrefix(s, Scheme) }

// ParseRef splits hf://org/repo/path/within/repo. Both the organisation and
// the repository name are required; the file path may be absent, which callers
// treat as "say which file" rather than guessing a quantisation.
func ParseRef(s string) (Ref, error) {
	if !IsRef(s) {
		return Ref{}, fmt.Errorf("not a Hugging Face reference: %q", s)
	}
	rest := strings.TrimPrefix(s, Scheme)
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	rest = strings.Trim(rest, "/")
	parts := strings.Split(rest, "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return Ref{}, fmt.Errorf("%q must look like hf://<org>/<repo>/<file>", s)
	}
	for _, p := range parts {
		if p == "." || p == ".." {
			return Ref{}, fmt.Errorf("%q must not contain path traversal", s)
		}
	}
	ref := Ref{Repo: parts[0] + "/" + parts[1]}
	if len(parts) > 2 {
		ref.Path = strings.Join(parts[2:], "/")
	}
	return ref, nil
}

// Client talks to the Hugging Face API.
type Client struct {
	HTTP     *http.Client
	Endpoint string
	// Token authenticates against gated repositories; empty uses HF_TOKEN.
	Token string
}

// NewClient returns a client configured from the environment.
func NewClient() *Client {
	ep := defaultEndpoint
	if v := os.Getenv("HF_ENDPOINT"); v != "" {
		ep = strings.TrimRight(v, "/")
	}
	return &Client{
		HTTP:     &http.Client{}, // no timeout: model downloads run for minutes
		Endpoint: ep,
		Token:    os.Getenv("HF_TOKEN"),
	}
}

func (c *Client) endpoint() string {
	if c.Endpoint != "" {
		return c.Endpoint
	}
	return defaultEndpoint
}

func (c *Client) do(req *http.Request) (*http.Response, error) {
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	req.Header.Set("User-Agent", "palan")
	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	return client.Do(req)
}

// gatedError explains a refusal in terms of what to do about it, since a bare
// 401 or 403 from a gated repository looks like a palan problem.
func (c *Client) gatedError(ref Ref, status int) error {
	// Hugging Face answers 401 for a repository that does not exist as well
	// as for one you cannot see, so as not to reveal which. Say so, rather
	// than sending someone to hunt for a token when they mistyped a name.
	hint := "if it exists and is gated, accept its terms and set HF_TOKEN"
	if c.Token != "" {
		hint = "if it exists, the configured HF_TOKEN may lack access or its terms may need accepting"
	}
	return fmt.Errorf("hugging face refused %s (%d): the repository is missing, private, or gated, and it does not say which; check the name at %s, and %s",
		ref.Repo, status, c.endpoint()+"/"+ref.Repo, hint)
}

// listFiles returns every file path in the repository.
func (c *Client) listFiles(ctx context.Context, ref Ref) ([]string, error) {
	url := c.endpoint() + "/api/models/" + ref.Repo
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, c.gatedError(ref, resp.StatusCode)
	case http.StatusNotFound:
		return nil, fmt.Errorf("hugging face has no repository %s", ref.Repo)
	default:
		return nil, fmt.Errorf("listing %s: unexpected status %q", ref.Repo, resp.Status)
	}
	var body struct {
		Siblings []struct {
			Filename string `json:"rfilename"`
		} `json:"siblings"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decoding the file list for %s: %w", ref.Repo, err)
	}
	out := make([]string, 0, len(body.Siblings))
	for _, s := range body.Siblings {
		out = append(out, s.Filename)
	}
	sort.Strings(out)
	return out, nil
}

// pathsInfo asks for size and upstream digest for specific paths.
func (c *Client) pathsInfo(ctx context.Context, ref Ref, paths []string) ([]File, error) {
	body, err := json.Marshal(map[string]any{"paths": paths})
	if err != nil {
		return nil, err
	}
	url := c.endpoint() + "/api/models/" + ref.Repo + "/paths-info/main"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, c.gatedError(ref, resp.StatusCode)
	default:
		return nil, fmt.Errorf("querying %s: unexpected status %q", ref.Repo, resp.Status)
	}
	var infos []struct {
		Path string `json:"path"`
		Size int64  `json:"size"`
		LFS  *struct {
			OID string `json:"oid"`
		} `json:"lfs"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&infos); err != nil {
		return nil, fmt.Errorf("decoding file metadata for %s: %w", ref.Repo, err)
	}
	out := make([]File, 0, len(infos))
	for _, i := range infos {
		f := File{Path: i.Path, Size: i.Size}
		if i.LFS != nil {
			f.SHA256 = i.LFS.OID
		}
		out = append(out, f)
	}
	return out, nil
}

// Resolve turns a reference into the set of files to fetch: the named file,
// every sibling part when it is one of a split set, and the repository's
// licence when it has one.
func (c *Client) Resolve(ctx context.Context, ref Ref) ([]File, error) {
	if ref.Path == "" {
		return c.resolveRepo(ctx, ref)
	}
	listing, err := c.listFiles(ctx, ref)
	if err != nil {
		return nil, err
	}
	known := make(map[string]bool, len(listing))
	for _, p := range listing {
		known[p] = true
	}
	if !known[ref.Path] {
		return nil, fmt.Errorf("%s has no file %q", ref.Repo, ref.Path)
	}

	want := []string{ref.Path}
	want = append(want, siblingParts(ref.Path, listing)...)
	if lic := licenseFile(listing); lic != "" {
		want = append(want, lic)
	}

	files, err := c.pathsInfo(ctx, ref, want)
	if err != nil {
		return nil, err
	}
	if len(files) != len(want) {
		return nil, fmt.Errorf("%s returned metadata for %d of %d requested files", ref.Repo, len(files), len(want))
	}
	return files, nil
}

// resolveRepo selects the files a whole published model consists of. A
// safetensors model is published as a directory, so the repository is the
// name a reader has for it.
//
// The shard index states which weight files the model is made of, so weights
// it does not name are a different model published beside this one: an
// adapter, or a second quantisation. Selecting those would put another
// model's bytes in the artifact.
func (c *Client) resolveRepo(ctx context.Context, ref Ref) ([]File, error) {
	listing, err := c.listFiles(ctx, ref)
	if err != nil {
		return nil, err
	}
	present := make(map[string]bool, len(listing))
	for _, p := range listing {
		present[p] = true
	}

	var want []string
	switch {
	case present[safetensors.IndexName]:
		data, err := c.fetchSmall(ctx, ref, safetensors.IndexName)
		if err != nil {
			return nil, err
		}
		ix, err := safetensors.ParseIndex(data)
		if err != nil {
			return nil, fmt.Errorf("%s of %s: %w", safetensors.IndexName, ref.Repo, err)
		}
		want = append(want, safetensors.IndexName)
		for _, shard := range ix.Shards() {
			if !present[shard] {
				return nil, fmt.Errorf(
					"%s names the shard %s and %s does not publish it; the model would pack incomplete",
					safetensors.IndexName, shard, ref.Repo)
			}
			want = append(want, shard)
		}
	case present["model.safetensors"]:
		want = append(want, "model.safetensors")
	default:
		return nil, c.suggestFiles(ctx, ref)
	}

	for _, name := range append([]string{safetensors.ConfigName}, safetensors.CompanionNames...) {
		if present[name] {
			want = append(want, name)
		}
	}
	for _, name := range safetensors.DocNames {
		if present[name] {
			want = append(want, name)
		}
	}

	files, err := c.pathsInfo(ctx, ref, want)
	if err != nil {
		return nil, err
	}
	if len(files) != len(want) {
		return nil, fmt.Errorf("%s returned metadata for %d of %d requested files", ref.Repo, len(files), len(want))
	}
	return files, nil
}

// fetchSmall reads a small file whole. It is for the index and the signature,
// never for weights, which stream through Download so an interrupted transfer
// resumes.
func (c *Client) fetchSmall(ctx context.Context, ref Ref, name string) ([]byte, error) {
	url := c.endpoint() + "/" + ref.Repo + "/resolve/main/" + name
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", name, err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, c.gatedError(ref, resp.StatusCode)
	default:
		return nil, fmt.Errorf("fetching %s: unexpected status %q", name, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}

// suggestFiles turns "which quantisation did you mean" into an answer rather
// than a guess.
func (c *Client) suggestFiles(ctx context.Context, ref Ref) error {
	listing, err := c.listFiles(ctx, ref)
	if err != nil {
		return err
	}
	var ggufs []string
	for _, p := range listing {
		if strings.HasSuffix(p, ".gguf") {
			ggufs = append(ggufs, p)
		}
	}
	if len(ggufs) == 0 {
		return fmt.Errorf("%w: %s publishes no .gguf files, so it needs converting first", ErrNoFile, ref.Repo)
	}
	return fmt.Errorf("%w: name one of %s's files, for example hf://%s/%s\navailable: %s",
		ErrNoFile, ref.Repo, ref.Repo, ggufs[0], strings.Join(ggufs, ", "))
}

// siblingParts returns the other parts of a split GGUF, so naming one part
// fetches the whole set.
func siblingParts(name string, listing []string) []string {
	m := splitPart.FindStringSubmatch(path.Base(name))
	if m == nil {
		return nil
	}
	dir := path.Dir(name)
	prefix, total, ext := m[1], m[3], m[4]
	var out []string
	for _, candidate := range listing {
		if path.Dir(candidate) != dir {
			continue
		}
		cm := splitPart.FindStringSubmatch(path.Base(candidate))
		if cm == nil || cm[1] != prefix || cm[3] != total || cm[4] != ext {
			continue
		}
		if candidate != name {
			out = append(out, candidate)
		}
	}
	return out
}

// licenseFile finds a licence at the repository root, matching what the
// hand-written Ollama recipe packs.
func licenseFile(listing []string) string {
	for _, p := range listing {
		if strings.ContainsRune(p, '/') {
			continue
		}
		switch strings.ToUpper(p) {
		case "LICENSE", "LICENSE.TXT", "LICENSE.MD", "LICENCE", "COPYING":
			return p
		}
	}
	return ""
}

// Events reports download progress; every field may be nil.
type Events struct {
	OnStart func(f File, resumeOffset int64) func(delta int64)
}

// downloadAttempts bounds resume retries, mirroring the registry path.
const downloadAttempts = 4

// Download fetches f into destDir and returns the local path.
//
// An interrupted transfer keeps its partial file and resumes on the next
// attempt, so a dropped connection costs the remainder rather than the whole
// download. Completed bytes are checked against the digest the repository
// published: a file that does not match is removed rather than handed on to be
// packed and signed as genuine.
func (c *Client) Download(ctx context.Context, ref Ref, f File, destDir string, ev Events) (string, error) {
	dest := filepath.Join(destDir, filepath.Base(f.Path)) // #nosec G304 -- caller owns destDir
	partial := dest + ".partial"

	var lastErr error
	for attempt := range downloadAttempts {
		hasher, complete, err := c.attempt(ctx, ref, f, partial, ev)
		switch {
		case err != nil:
			lastErr = err
		case !complete:
			// The body ended early. The partial is deliberately kept: the
			// next attempt continues from where this one stopped.
			lastErr = fmt.Errorf("%s: transfer ended before the file was complete", f.Path)
		default:
			if f.SHA256 != "" {
				if got := hex.EncodeToString(hasher.Sum(nil)); got != f.SHA256 {
					_ = os.Remove(partial)
					return "", fmt.Errorf(
						"%s: downloaded bytes hash to %s but the repository publishes %s; refusing the file",
						f.Path, got, f.SHA256)
				}
			}
			if err := os.Rename(partial, dest); err != nil {
				return "", err
			}
			return dest, nil
		}
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(time.Duration(attempt+1) * 200 * time.Millisecond):
		}
	}
	return "", fmt.Errorf("fetching %s after %d attempts: %w", f.Path, downloadAttempts, lastErr)
}

// attempt resumes the partial and reports whether the file is now complete.
func (c *Client) attempt(ctx context.Context, ref Ref, f File, partial string, ev Events) (hash.Hash, bool, error) {
	offset, hasher, err := transfer.RehashPartial(partial, f.Size)
	if err != nil {
		return nil, false, err
	}
	if offset >= f.Size && f.Size > 0 {
		return hasher, true, nil // a previous attempt finished the bytes
	}
	if err := c.stream(ctx, ref, f, partial, &offset, &hasher, ev); err != nil {
		return nil, false, err
	}
	return hasher, offset >= f.Size, nil
}

// stream performs the ranged GET, appending to the partial file.
func (c *Client) stream(ctx context.Context, ref Ref, f File, partial string, offset *int64, hasher *hash.Hash, ev Events) (retErr error) {
	url := c.endpoint() + "/" + ref.Repo + "/resolve/main/" + f.Path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if *offset > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", *offset))
	}
	resp, err := c.do(req)
	if err != nil {
		return fmt.Errorf("fetching %s: %w", f.Path, err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && retErr == nil {
			retErr = cerr
		}
	}()

	appendMode := false
	switch resp.StatusCode {
	case http.StatusOK:
		// The range was ignored, so start over rather than corrupt the file.
		*offset = 0
		*hasher = sha256.New()
	case http.StatusPartialContent:
		appendMode = true
	case http.StatusUnauthorized, http.StatusForbidden:
		return c.gatedError(ref, resp.StatusCode)
	default:
		return fmt.Errorf("fetching %s: unexpected status %q", f.Path, resp.Status)
	}

	flags := os.O_CREATE | os.O_WRONLY
	if appendMode {
		flags |= os.O_APPEND
	} else {
		flags |= os.O_TRUNC
	}
	out, err := os.OpenFile(partial, flags, 0o600) // #nosec G304 -- caller-owned temp dir
	if err != nil {
		return err
	}
	defer func() {
		if cerr := out.Close(); cerr != nil && retErr == nil {
			retErr = cerr
		}
	}()

	var tick func(int64)
	if ev.OnStart != nil {
		tick = ev.OnStart(f, *offset)
	}
	w := io.MultiWriter(out, *hasher)
	if tick != nil {
		w = io.MultiWriter(out, *hasher, progressWriter(tick))
	}
	n, err := io.Copy(w, resp.Body)
	if err != nil {
		return fmt.Errorf("fetching %s: %w", f.Path, err)
	}
	*offset += n
	return nil
}

type progressWriter func(int64)

func (p progressWriter) Write(b []byte) (int, error) {
	p(int64(len(b)))
	return len(b), nil
}
