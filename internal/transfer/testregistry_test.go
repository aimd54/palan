// Copyright The moci Authors
// SPDX-License-Identifier: Apache-2.0

package transfer

// A minimal in-process OCI Distribution registry for hermetic tests:
// manifests, blobs with HTTP Range support (via http.ServeContent),
// monolithic POST+PUT uploads, cross-repo mounts, request logging, and
// mid-stream connection-failure injection for resume tests.

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
)

type manifestEntry struct {
	mediaType string
	data      []byte
}

type reqRecord struct {
	Method string
	Path   string
	Range  string
}

type testRegistry struct {
	t *testing.T

	mu        sync.Mutex
	blobs     map[string]map[digest.Digest][]byte // repo → digest → content
	manifests map[string]map[string]manifestEntry // repo → tag|digest → entry
	uploads   map[string]string                   // upload id → repo
	nextID    int
	requests  []reqRecord

	// failBlobReads[d] > 0 makes the next GET of blob d serve only
	// failAfterBytes bytes and then drop the connection.
	failBlobReads  map[digest.Digest]int
	failAfterBytes int64
	// ignoreRange makes blob GETs disregard Range headers (always 200).
	ignoreRange bool
	// corruptBlob serves flipped bytes for this digest (content ≠ digest).
	corruptBlob digest.Digest

	srv *httptest.Server
}

func newTestRegistry(t *testing.T) *testRegistry {
	t.Helper()
	r := &testRegistry{
		t:             t,
		blobs:         map[string]map[digest.Digest][]byte{},
		manifests:     map[string]map[string]manifestEntry{},
		uploads:       map[string]string{},
		failBlobReads: map[digest.Digest]int{},
	}
	r.srv = httptest.NewServer(r)
	t.Cleanup(r.srv.Close)
	return r
}

// host returns the registry host:port (no scheme).
func (r *testRegistry) host() string {
	return strings.TrimPrefix(r.srv.URL, "http://")
}

func (r *testRegistry) putBlob(repo string, content []byte) digest.Digest {
	d := digest.FromBytes(content)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.blobs[repo] == nil {
		r.blobs[repo] = map[digest.Digest][]byte{}
	}
	r.blobs[repo][d] = content
	return d
}

func (r *testRegistry) putManifest(repo, ref, mediaType string, data []byte) digest.Digest {
	d := digest.FromBytes(data)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.manifests[repo] == nil {
		r.manifests[repo] = map[string]manifestEntry{}
	}
	e := manifestEntry{mediaType: mediaType, data: data}
	r.manifests[repo][ref] = e
	r.manifests[repo][d.String()] = e
	return d
}

func (r *testRegistry) hasBlob(repo string, d digest.Digest) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.blobs[repo][d]
	return ok
}

// countRequests returns how many logged requests match method and a path
// substring.
func (r *testRegistry) countRequests(method, pathPart string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, rec := range r.requests {
		if rec.Method == method && strings.Contains(rec.Path, pathPart) {
			n++
		}
	}
	return n
}

// rangeRequests returns the Range header values seen on GETs of the blob.
func (r *testRegistry) rangeRequests(d digest.Digest) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, rec := range r.requests {
		if rec.Method == http.MethodGet && strings.HasSuffix(rec.Path, d.String()) && rec.Range != "" {
			out = append(out, rec.Range)
		}
	}
	return out
}

var (
	reUploadPost = regexp.MustCompile(`^/v2/(.+)/blobs/uploads/$`)
	reUploadPut  = regexp.MustCompile(`^/v2/(.+)/blobs/uploads/([^/?]+)$`)
	reBlob       = regexp.MustCompile(`^/v2/(.+)/blobs/([^/]+)$`)
	reManifest   = regexp.MustCompile(`^/v2/(.+)/manifests/([^/]+)$`)
)

func (r *testRegistry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	r.requests = append(r.requests, reqRecord{Method: req.Method, Path: req.URL.Path, Range: req.Header.Get("Range")})
	r.mu.Unlock()

	path := req.URL.Path
	switch {
	case path == "/v2/":
		w.WriteHeader(http.StatusOK)

	case reUploadPost.MatchString(path) && req.Method == http.MethodPost:
		r.handleUploadStart(w, req, reUploadPost.FindStringSubmatch(path)[1])

	case reUploadPut.MatchString(path) && req.Method == http.MethodPut:
		m := reUploadPut.FindStringSubmatch(path)
		r.handleUploadPut(w, req, m[1])

	case reManifest.MatchString(path):
		m := reManifest.FindStringSubmatch(path)
		r.handleManifest(w, req, m[1], m[2])

	case reBlob.MatchString(path):
		m := reBlob.FindStringSubmatch(path)
		r.handleBlob(w, req, m[1], m[2])

	default:
		http.Error(w, "not found: "+path, http.StatusNotFound)
	}
}

func (r *testRegistry) handleUploadStart(w http.ResponseWriter, req *http.Request, repo string) {
	q := req.URL.Query()
	if mount, from := q.Get("mount"), q.Get("from"); mount != "" && from != "" {
		d, err := digest.Parse(mount)
		if err == nil {
			r.mu.Lock()
			content, ok := r.blobs[from][d]
			if ok {
				if r.blobs[repo] == nil {
					r.blobs[repo] = map[digest.Digest][]byte{}
				}
				r.blobs[repo][d] = content
			}
			r.mu.Unlock()
			if ok {
				w.Header().Set("Location", "/v2/"+repo+"/blobs/"+d.String())
				w.WriteHeader(http.StatusCreated)
				return
			}
		}
	}
	r.mu.Lock()
	r.nextID++
	id := fmt.Sprintf("upload-%d", r.nextID)
	r.uploads[id] = repo
	r.mu.Unlock()
	w.Header().Set("Location", "/v2/"+repo+"/blobs/uploads/"+id)
	w.WriteHeader(http.StatusAccepted)
}

func (r *testRegistry) handleUploadPut(w http.ResponseWriter, req *http.Request, repo string) {
	dq := req.URL.Query().Get("digest")
	want, err := digest.Parse(dq)
	if err != nil {
		http.Error(w, "bad digest", http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(req.Body)
	if err != nil || digest.FromBytes(body) != want {
		http.Error(w, "digest mismatch", http.StatusBadRequest)
		return
	}
	r.mu.Lock()
	if r.blobs[repo] == nil {
		r.blobs[repo] = map[digest.Digest][]byte{}
	}
	r.blobs[repo][want] = body
	r.mu.Unlock()
	w.Header().Set("Docker-Content-Digest", want.String())
	w.WriteHeader(http.StatusCreated)
}

func (r *testRegistry) handleManifest(w http.ResponseWriter, req *http.Request, repo, ref string) {
	switch req.Method {
	case http.MethodPut:
		body, err := io.ReadAll(req.Body)
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		d := r.putManifest(repo, ref, req.Header.Get("Content-Type"), body)
		w.Header().Set("Docker-Content-Digest", d.String())
		w.WriteHeader(http.StatusCreated)

	case http.MethodGet, http.MethodHead:
		r.mu.Lock()
		e, ok := r.manifests[repo][ref]
		r.mu.Unlock()
		if !ok {
			http.Error(w, "manifest unknown", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", e.mediaType)
		w.Header().Set("Docker-Content-Digest", digest.FromBytes(e.data).String())
		w.Header().Set("Content-Length", strconv.Itoa(len(e.data)))
		if req.Method == http.MethodGet {
			_, _ = w.Write(e.data)
		}

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (r *testRegistry) handleBlob(w http.ResponseWriter, req *http.Request, repo, dg string) {
	d, err := digest.Parse(dg)
	if err != nil {
		http.Error(w, "bad digest", http.StatusBadRequest)
		return
	}
	r.mu.Lock()
	content, ok := r.blobs[repo][d]
	failReads := r.failBlobReads[d]
	if failReads > 0 && req.Method == http.MethodGet {
		r.failBlobReads[d] = failReads - 1
	}
	corrupt := r.corruptBlob == d
	ignoreRange := r.ignoreRange
	failAfter := r.failAfterBytes
	r.mu.Unlock()

	if !ok {
		http.Error(w, "blob unknown", http.StatusNotFound)
		return
	}

	switch req.Method {
	case http.MethodHead:
		w.Header().Set("Content-Length", strconv.Itoa(len(content)))
		w.Header().Set("Docker-Content-Digest", d.String())
		w.WriteHeader(http.StatusOK)

	case http.MethodGet:
		if corrupt {
			flipped := bytes.Clone(content)
			for i := range flipped {
				flipped[i] ^= 0xFF
			}
			content = flipped
		}
		if failReads > 0 {
			// Serve the response header plus a truncated body, then drop
			// the connection: the client sees an unexpected EOF mid-stream.
			hj, ok := w.(http.Hijacker)
			if !ok {
				r.t.Fatal("test server does not support hijacking")
			}
			conn, buf, err := hj.Hijack()
			if err != nil {
				r.t.Fatalf("hijack: %v", err)
			}
			_, _ = fmt.Fprintf(buf, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\n\r\n", len(content))
			_, _ = buf.Write(content[:failAfter])
			_ = buf.Flush()
			_ = conn.Close()
			return
		}
		if ignoreRange {
			req.Header.Del("Range")
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Docker-Content-Digest", d.String())
		http.ServeContent(w, req, "", time.Time{}, bytes.NewReader(content))

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
