// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

// Package hftest serves a Hugging Face API against files held in memory, so
// the import path can be exercised without the network.
package hftest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Hub is a fake Hugging Face API.
type Hub struct {
	// Files is the repository content, keyed by path within the repository.
	// Every repository the client asks about resolves to this same set,
	// which is enough for a test that only ever names one repository.
	Files map[string][]byte
	// Repos holds distinct content per repository ("org/name"), for a test
	// that packs more than one repository in the same run and needs their
	// files to actually differ. A repository named here is served from its
	// own entry instead of Files.
	Repos map[string]map[string][]byte
	// Inline names files paths-info reports with no LFS digest, matching how
	// the real API serves small files stored inline rather than in LFS.
	Inline map[string]bool
	// Status, when non-zero, is returned for every request.
	Status int
	// IgnoreRange serves the whole body even when a Range is asked for,
	// which some content delivery networks do.
	IgnoreRange bool
	// TruncateAt, when > 0, serves only that many bytes and drops.
	TruncateAt int
	// Corrupt serves bytes that do not match the advertised digest.
	Corrupt bool
	// Ranges records the Range header of every download request.
	Ranges []string
	// Revision is the commit the model API reports as `sha`. Empty serves a
	// response with no sha at all, which is how a repository that states
	// none behaves.
	Revision string
	// Fetched records the revision segment of every download request, so a
	// test can prove the bytes came from the commit that was resolved
	// rather than from a branch that may have moved since.
	Fetched []string

	srv *httptest.Server
}

// New starts a hub serving files, stopped when the test ends.
func New(t *testing.T, files map[string][]byte) *Hub {
	t.Helper()
	h := &Hub{Files: files}
	h.srv = httptest.NewServer(h)
	t.Cleanup(h.srv.Close)
	return h
}

// URL is the endpoint to point HF_ENDPOINT or Client.Endpoint at.
func (h *Hub) URL() string { return h.srv.URL }

// Client returns an HTTP client that reaches this hub.
func (h *Hub) Client() *http.Client { return h.srv.Client() }

// filesFor returns the file set to serve for repo: its own entry in Repos
// when it has one, otherwise the single flat Files every repository shares.
func (h *Hub) filesFor(repo string) map[string][]byte {
	if f, ok := h.Repos[repo]; ok {
		return f
	}
	return h.Files
}

func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.Status != 0 {
		w.WriteHeader(h.Status)
		return
	}
	switch {
	case strings.Contains(r.URL.Path, "/paths-info/"):
		i := strings.Index(r.URL.Path, "/paths-info/")
		repo := strings.TrimPrefix(r.URL.Path[:i], "/api/models/")
		rev := r.URL.Path[i+len("/paths-info/"):]
		if rev == "" {
			http.Error(w, "no revision in path", http.StatusNotFound)
			return
		}
		files := h.filesFor(repo)
		var req struct {
			Paths []string `json:"paths"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		type lfs struct {
			OID string `json:"oid"`
		}
		var out []map[string]any
		for _, p := range req.Paths {
			b, ok := files[p]
			if !ok {
				continue
			}
			if h.Inline[p] {
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
		repo := strings.TrimPrefix(r.URL.Path, "/api/models/")
		files := h.filesFor(repo)
		type sib struct {
			Filename string `json:"rfilename"`
		}
		var sibs []sib
		for p := range files {
			sibs = append(sibs, sib{Filename: p})
		}
		body := map[string]any{"siblings": sibs}
		if h.Revision != "" {
			body["sha"] = h.Revision
		}
		_ = json.NewEncoder(w).Encode(body)

	case strings.Contains(r.URL.Path, "/resolve/"):
		i := strings.Index(r.URL.Path, "/resolve/")
		repo := strings.TrimPrefix(r.URL.Path[:i], "/")
		rest := r.URL.Path[i+len("/resolve/"):]
		rev, name, cut := strings.Cut(rest, "/")
		if !cut || rev == "" {
			// Real Hugging Face 404s a revision segment that is not there;
			// an empty rev must never be silently treated as a match, since
			// that would hide Download falling back to main when it should
			// not have.
			http.Error(w, "no revision in path", http.StatusNotFound)
			return
		}
		h.Fetched = append(h.Fetched, rev)
		files := h.filesFor(repo)
		b, found := files[name]
		if !found {
			http.Error(w, "no such file", http.StatusNotFound)
			return
		}
		if h.Corrupt {
			b = append([]byte("x"), b[1:]...)
		}
		rng := r.Header.Get("Range")
		h.Ranges = append(h.Ranges, rng)
		start := 0
		if rng != "" && !h.IgnoreRange {
			_, _ = fmt.Sscanf(rng, "bytes=%d-", &start)
			if start > len(b) {
				http.Error(w, "bad range", http.StatusRequestedRangeNotSatisfiable)
				return
			}
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, len(b)-1, len(b)))
			w.WriteHeader(http.StatusPartialContent)
		}
		body := b[start:]
		if h.TruncateAt > 0 && len(body) > h.TruncateAt {
			body = body[:h.TruncateAt]
		}
		_, _ = w.Write(body)

	default:
		http.Error(w, "unexpected "+r.URL.Path, http.StatusNotFound)
	}
}
