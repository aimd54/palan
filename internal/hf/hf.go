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
// The API reports each file's upstream SHA-256 when the file is stored in
// LFS; a file served inline, such as a small config or license file, carries
// none. Where a digest is published it is checked as the download streams
// and recorded as io.palan.origin.sha256, and a file that does not match it
// is refused rather than packed; where none is published, none is checked
// and none is invented.
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
	"net/url"
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

// ErrFileNotFound marks a file the repository does not publish, as distinct
// from ErrNoFile (no file was named at all) and from any other fetch
// failure: a timeout, a 5xx, or a gated repository all refuse too, but for a
// reason a caller should surface, not fold into "this file does not exist".
var ErrFileNotFound = errors.New("file not found in the repository")

// splitPart matches llama.cpp's multi-part naming, model-00001-of-00003.gguf.
// Packing only the part that was named would produce an artifact that looks
// complete and cannot load, so every sibling is fetched.
var splitPart = regexp.MustCompile(`^(.*)-(\d{5})-of-(\d{5})(\.gguf)$`)

// commitSHA matches the shape of a git SHA-1 object id, which is what
// Hugging Face reports as a repository's `sha`. The value becomes a URL path
// segment and is later written into a signed annotation, so it is validated
// at the point it is decoded: anything present but not this exact shape is
// the repository stating something palan cannot use as a revision, and is
// treated the same as no revision at all rather than failing the resolve.
var commitSHA = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

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

// listFiles returns every file path in the repository, and the commit the
// repository reported for the listing, empty when it stated none.
func (c *Client) listFiles(ctx context.Context, ref Ref) ([]string, string, error) {
	url := c.endpoint() + "/api/models/" + ref.Repo
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := c.do(req)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, "", c.gatedError(ref, resp.StatusCode)
	case http.StatusNotFound:
		return nil, "", fmt.Errorf("hugging face has no repository %s", ref.Repo)
	default:
		return nil, "", fmt.Errorf("listing %s: unexpected status %q", ref.Repo, resp.Status)
	}
	var body struct {
		Siblings []struct {
			Filename string `json:"rfilename"`
		} `json:"siblings"`
		SHA string `json:"sha"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, "", fmt.Errorf("decoding the file list for %s: %w", ref.Repo, err)
	}
	// A listing entry names a file that may be fetched, packed and attested
	// to. One that is not a plain path inside the repository is dropped
	// rather than carried: it cannot name a file this repository publishes,
	// and every later check that would see it treats it as legitimate
	// because the repository itself reported it.
	out := make([]string, 0, len(body.Siblings))
	for _, s := range body.Siblings {
		if !safeRepoPath(s.Filename) {
			continue
		}
		out = append(out, s.Filename)
	}
	sort.Strings(out)
	rev := body.SHA
	if rev != "" && !commitSHA.MatchString(rev) {
		rev = ""
	}
	return out, rev, nil
}

// revOrMain is the URL segment naming which revision to request: rev when a
// listing resolved one, main otherwise, which is what a caller with no
// resolution has.
// safeRepoPath reports whether p is a path a repository may legitimately
// publish: a clean, relative, forward-slash path that stays inside the
// repository. A published path is third-party text that reaches a URL
// segment and is written into a signed annotation, so it is checked where
// it is decoded, exactly as a reported commit is.
//
// filepath.Base already keeps a hostile path from escaping the download
// directory, so this is not what stops a file being written somewhere
// unexpected. What it stops is subtler and not otherwise caught: a path
// that walks out of the repository resolves, on a normalising server, to
// another repository's file, and palan would then pack those bytes and
// sign a statement naming a path the caller never asked for.
func safeRepoPath(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") || strings.Contains(p, "\\") {
		return false
	}
	// A percent sign is refused outright rather than decoded and
	// re-inspected. %2e%2e/%2e%2e/ passes every check made on literal
	// segments below, and a server that decodes before it normalises
	// resolves it exactly as the plain form would, so inspecting only what
	// is written leaves the guard reading a different path from the one the
	// server will act on. No file this client fetches needs one.
	if strings.ContainsRune(p, '%') {
		return false
	}
	// Control bytes never appear in a published filename, and this path is
	// printed to a terminal before anything parses it.
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	if path.Clean(p) != p {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// resolveURL builds a file's download URL with the path escaped by the URL
// encoder rather than pasted in. Concatenating leaves whatever the
// repository wrote in the request line verbatim, so a path this client
// accepted as literal text could still reach the server as something else
// once decoded.
func resolveURL(endpoint, repo, rev, file string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("parsing the endpoint %q: %w", endpoint, err)
	}
	// Assigning Path and leaving RawPath unset makes String escape each
	// segment once, from the decoded form.
	u.Path = strings.TrimSuffix(u.Path, "/") + "/" + repo + "/resolve/" + rev + "/" + file
	u.RawPath = ""
	return u.String(), nil
}

func revOrMain(rev string) string {
	if rev == "" {
		return "main"
	}
	return rev
}

// pathsInfo asks for size and upstream digest for specific paths, pinned to
// rev so the digests it returns describe the same commit Download fetches
// from rather than whatever main happens to hold when the two calls land on
// either side of a push.
func (c *Client) pathsInfo(ctx context.Context, ref Ref, rev string, paths []string) ([]File, error) {
	body, err := json.Marshal(map[string]any{"paths": paths})
	if err != nil {
		return nil, err
	}
	url := c.endpoint() + "/api/models/" + ref.Repo + "/paths-info/" + revOrMain(rev)
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
	// A returned path is third-party text that names the file whose bytes
	// are packed, reaches a URL path segment, and is written into a signed
	// annotation, so it is held to the set that was asked for rather than
	// trusted, the same way a reported commit is validated where it is
	// decoded. A response naming a file the caller never requested would
	// otherwise put another path's bytes, under another path's name, into
	// the artifact and into the statement that vouches for it.
	requested := make(map[string]bool, len(paths))
	for _, p := range paths {
		requested[p] = true
	}
	out := make([]File, 0, len(infos))
	seen := make(map[string]bool, len(infos))
	for _, i := range infos {
		if !safeRepoPath(i.Path) {
			return nil, fmt.Errorf("%s returned metadata for %q, which is not a path inside the repository", ref.Repo, i.Path)
		}
		if !requested[i.Path] {
			return nil, fmt.Errorf("%s returned metadata for %q, which was not among the files requested", ref.Repo, i.Path)
		}
		if seen[i.Path] {
			return nil, fmt.Errorf("%s returned metadata for %q more than once", ref.Repo, i.Path)
		}
		seen[i.Path] = true
		f := File{Path: i.Path, Size: i.Size}
		if i.LFS != nil {
			f.SHA256 = i.LFS.OID
		}
		out = append(out, f)
	}
	return out, nil
}

// Resolution is the outcome of resolving a reference: the files to fetch, and
// the commit the repository reported for the listing they came from.
type Resolution struct {
	Files []File
	// Revision is the commit the listing resolved to, empty when the
	// repository states none. A caller records it only when it is set: a
	// revision that was never reported is not a fact about the model.
	Revision string
}

// Resolve turns a reference into the set of files to fetch: the named file,
// every sibling part when it is one of a split set, and the repository's
// licence when it has one. The commit the listing was taken at travels with
// the result, so Download can fetch from that same state rather than from a
// branch that may have moved since.
func (c *Client) Resolve(ctx context.Context, ref Ref) (Resolution, error) {
	if ref.Path == "" {
		return c.resolveRepo(ctx, ref)
	}
	listing, rev, err := c.listFiles(ctx, ref)
	if err != nil {
		return Resolution{}, err
	}
	known := make(map[string]bool, len(listing))
	for _, p := range listing {
		known[p] = true
	}
	if !known[ref.Path] {
		return Resolution{}, fmt.Errorf("%s has no file %q", ref.Repo, ref.Path)
	}

	want := []string{ref.Path}
	want = append(want, siblingParts(ref.Path, listing)...)
	if lic := licenseFile(listing); lic != "" {
		want = append(want, lic)
	}
	want = dedupe(want)

	files, err := c.pathsInfo(ctx, ref, rev, want)
	if err != nil {
		return Resolution{}, err
	}
	if len(files) != len(want) {
		return Resolution{}, fmt.Errorf("%s returned metadata for %d of %d requested files", ref.Repo, len(files), len(want))
	}
	return Resolution{Files: files, Revision: rev}, nil
}

// dedupe returns names with repeats removed, keeping first appearance
// order. The named file can also be the licence, so the two ways a file
// enters the request can name the same one; asking for it twice would be
// answered twice by a server behaving correctly, and refused as a repeated
// path.
func dedupe(names []string) []string {
	seen := make(map[string]bool, len(names))
	out := make([]string, 0, len(names))
	for _, n := range names {
		if seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

// resolveRepo selects the files a whole published model consists of. A
// safetensors model is published as a directory, so the repository is the
// name a reader has for it.
//
// The shard index states which weight files the model is made of, so weights
// it does not name are a different model published beside this one: an
// adapter, or a second quantisation. Selecting those would put another
// model's bytes in the artifact.
func (c *Client) resolveRepo(ctx context.Context, ref Ref) (Resolution, error) {
	listing, rev, err := c.listFiles(ctx, ref)
	if err != nil {
		return Resolution{}, err
	}
	present := make(map[string]bool, len(listing))
	for _, p := range listing {
		present[p] = true
	}

	var want []string
	switch {
	case present[safetensors.IndexName]:
		data, err := c.FetchSmall(ctx, ref, rev, safetensors.IndexName)
		if err != nil {
			return Resolution{}, err
		}
		ix, err := safetensors.ParseIndex(data)
		if err != nil {
			return Resolution{}, fmt.Errorf("%s of %s: %w", safetensors.IndexName, ref.Repo, err)
		}
		want = append(want, safetensors.IndexName)
		for _, shard := range ix.Shards() {
			if !present[shard] {
				return Resolution{}, fmt.Errorf(
					"%s names the shard %s and %s does not publish it; the model would pack incomplete",
					safetensors.IndexName, shard, ref.Repo)
			}
			want = append(want, shard)
		}
	case present["model.safetensors"]:
		want = append(want, "model.safetensors")
	default:
		return Resolution{}, c.suggestFiles(ctx, ref)
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

	want = dedupe(want)
	files, err := c.pathsInfo(ctx, ref, rev, want)
	if err != nil {
		return Resolution{}, err
	}
	if len(files) != len(want) {
		return Resolution{}, fmt.Errorf("%s returned metadata for %d of %d requested files", ref.Repo, len(files), len(want))
	}
	return Resolution{Files: files, Revision: rev}, nil
}

// FetchSmall reads a small file whole. It is for the index and the signature,
// never for weights, which stream through Download so an interrupted transfer
// resumes.
//
// rev pins the commit to read from, exactly as Download's rev does, so an
// index or signature read this way describes the same commit the weights
// come from rather than whatever main holds when the two calls land on
// either side of a push. An empty rev reads from main.
func (c *Client) FetchSmall(ctx context.Context, ref Ref, rev, name string) ([]byte, error) {
	target, err := resolveURL(c.endpoint(), ref.Repo, revOrMain(rev), name)
	if err != nil {
		return nil, err
	}
	url := target
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
	case http.StatusNotFound:
		return nil, fmt.Errorf("%w: %s in %s", ErrFileNotFound, name, ref.Repo)
	default:
		return nil, fmt.Errorf("fetching %s: unexpected status %q", name, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}

// suggestFiles turns "which quantisation did you mean" into an answer rather
// than a guess.
func (c *Client) suggestFiles(ctx context.Context, ref Ref) error {
	listing, _, err := c.listFiles(ctx, ref)
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
// rev pins the commit to fetch from. A repository's branch can move between
// the listing that produced f and this request, which would otherwise yield
// an artifact whose files came from two states of the same repository with
// nothing reporting it. An empty rev fetches from main, which is what a
// caller with no resolution has.
//
// An interrupted transfer keeps its partial file and resumes on the next
// attempt, so a dropped connection costs the remainder rather than the whole
// download. Completed bytes are checked against the digest the repository
// published, when it published one for f: f.SHA256 is empty for a file
// served inline rather than stored in LFS, and then nothing is checked here.
// Where a digest was published, a file that does not match it is removed
// rather than handed on to be packed and signed as genuine.
func (c *Client) Download(ctx context.Context, ref Ref, rev string, f File, destDir string, ev Events) (string, error) {
	dest := filepath.Join(destDir, filepath.Base(f.Path)) // #nosec G304 -- caller owns destDir
	partial := dest + ".partial"

	var lastErr error
	for attempt := range downloadAttempts {
		hasher, complete, err := c.attempt(ctx, ref, rev, f, partial, ev)
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
func (c *Client) attempt(ctx context.Context, ref Ref, rev string, f File, partial string, ev Events) (hash.Hash, bool, error) {
	offset, hasher, err := transfer.RehashPartial(partial, f.Size)
	if err != nil {
		return nil, false, err
	}
	if offset >= f.Size && f.Size > 0 {
		return hasher, true, nil // a previous attempt finished the bytes
	}
	if err := c.stream(ctx, ref, rev, f, partial, &offset, &hasher, ev); err != nil {
		return nil, false, err
	}
	return hasher, offset >= f.Size, nil
}

// stream performs the ranged GET, appending to the partial file.
func (c *Client) stream(ctx context.Context, ref Ref, rev string, f File, partial string, offset *int64, hasher *hash.Hash, ev Events) (retErr error) {
	target, err := resolveURL(c.endpoint(), ref.Repo, revOrMain(rev), f.Path)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
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
