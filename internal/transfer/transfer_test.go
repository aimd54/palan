// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package transfer

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/aimd54/palan/internal/refname"
	"github.com/aimd54/palan/internal/registrytest"
	"github.com/aimd54/palan/internal/store"
	"github.com/aimd54/palan/pkg/modelspec"
)

const testConfigJSON = `{"descriptor":{"name":"tiny"},"modelfs":{"type":"layers","diffIds":[]},"config":{"format":"gguf"}}`

func newTestClient(t *testing.T) *Client {
	t.Helper()
	c, err := New(Options{
		PlainHTTP:  true,
		Credential: auth.StaticCredential("", auth.EmptyCredential),
		UserAgent:  "palan-test",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	return c
}

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	return s
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}

// buildModelManifest returns manifest bytes plus descriptors for a minimal
// ModelPack artifact (config + one raw weight layer).
func buildModelManifest(t *testing.T, weights []byte) (manifest []byte, mDesc, cfgDesc, wDesc ocispec.Descriptor) {
	t.Helper()
	cfgDesc = content.NewDescriptorFromBytes(modelspec.MediaTypeModelConfig, []byte(testConfigJSON))
	wDesc = content.NewDescriptorFromBytes(modelspec.MediaTypeModelWeightRaw, weights)
	wDesc.Annotations = map[string]string{modelspec.AnnotationFilepath: "tiny.gguf"}
	m := ocispec.Manifest{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: modelspec.ArtifactTypeModelManifest,
		Config:       cfgDesc,
		Layers:       []ocispec.Descriptor{wDesc},
	}
	m.SchemaVersion = 2
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	mDesc = content.NewDescriptorFromBytes(ocispec.MediaTypeImageManifest, raw)
	mDesc.ArtifactType = modelspec.ArtifactTypeModelManifest
	return raw, mDesc, cfgDesc, wDesc
}

// seedRegistryModel stores a model artifact directly in the test registry.
func seedRegistryModel(t *testing.T, reg *registrytest.Registry, repo, tag string, weights []byte) (mDesc, wDesc ocispec.Descriptor) {
	t.Helper()
	manifest, mDesc, _, wDesc := buildModelManifest(t, weights)
	reg.PutBlob(repo, []byte(testConfigJSON))
	reg.PutBlob(repo, weights)
	reg.PutManifest(repo, tag, ocispec.MediaTypeImageManifest, manifest)
	return mDesc, wDesc
}

// seedStoreModel stores a model artifact in the local store under ref.
func seedStoreModel(t *testing.T, st *store.Store, ref string, weights []byte) (mDesc, wDesc ocispec.Descriptor) {
	t.Helper()
	ctx := context.Background()
	manifest, mDesc, cfgDesc, wDesc := buildModelManifest(t, weights)
	push := func(desc ocispec.Descriptor, data []byte) {
		if err := st.OCI().Push(ctx, desc, bytes.NewReader(data)); err != nil && !errors.Is(err, errdef.ErrAlreadyExists) {
			t.Fatalf("seed push %s: %v", desc.MediaType, err)
		}
	}
	push(cfgDesc, []byte(testConfigJSON))
	push(wDesc, weights)
	push(mDesc, manifest)
	if err := st.Tag(ctx, mDesc, ref); err != nil {
		t.Fatalf("seed tag: %v", err)
	}
	return mDesc, wDesc
}

func mustParse(t *testing.T, raw string) registry.Reference {
	t.Helper()
	ref, err := refname.Parse(raw, "")
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return ref
}

func TestPullRoundTrip(t *testing.T) {
	reg := registrytest.New(t)
	weights := randomBytes(t, 2<<20)
	mDesc, wDesc := seedRegistryModel(t, reg, "llm/tiny", "q4", weights)

	st := openTestStore(t)
	c := newTestClient(t)
	ref := mustParse(t, reg.Host()+"/llm/tiny:q4")

	got, err := c.Pull(context.Background(), st, ref, Events{})
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if got.Digest != mDesc.Digest {
		t.Errorf("pulled root %s, want %s", got.Digest, mDesc.Digest)
	}

	// The ref resolves locally and the weight blob is byte-identical.
	if _, err := st.Resolve(context.Background(), ref.String()); err != nil {
		t.Fatalf("local resolve: %v", err)
	}
	p, err := st.BlobPath(wDesc.Digest)
	if err != nil {
		t.Fatalf("blob path: %v", err)
	}
	onDisk, err := os.ReadFile(p)
	if err != nil || !bytes.Equal(onDisk, weights) {
		t.Errorf("weight blob mismatch on disk (%v)", err)
	}

	// Ingest dir must be clean after a successful pull.
	ingest, _ := st.IngestDir()
	if entries, _ := os.ReadDir(ingest); len(entries) != 0 {
		t.Errorf("ingest dir not clean: %d leftover files", len(entries))
	}

	// Second pull: weights must not be re-downloaded.
	before := reg.CountRequests("GET", wDesc.Digest.String())
	var skips atomic.Int32
	_, err = c.Pull(context.Background(), st, ref, Events{
		OnBlobSkip: func(ocispec.Descriptor) { skips.Add(1) },
	})
	if err != nil {
		t.Fatalf("second pull: %v", err)
	}
	if after := reg.CountRequests("GET", wDesc.Digest.String()); after != before {
		t.Errorf("weights re-downloaded on second pull (%d → %d GETs)", before, after)
	}
	if skips.Load() == 0 {
		t.Error("expected skip events on second pull")
	}
}

// TestPullResumesAfterConnectionDrop: the registry drops the connection
// mid-blob once; the retry must resume with a Range request instead of
// restarting from zero.
func TestPullResumesAfterConnectionDrop(t *testing.T) {
	reg := registrytest.New(t)
	weights := randomBytes(t, 2<<20)
	_, wDesc := seedRegistryModel(t, reg, "llm/tiny", "q4", weights)
	reg.SetFailBlobReads(wDesc.Digest, 1, 300*1024)

	st := openTestStore(t)
	c := newTestClient(t)
	ref := mustParse(t, reg.Host()+"/llm/tiny:q4")

	var resumedFrom atomic.Int64
	_, err := c.Pull(context.Background(), st, ref, Events{
		OnBlobStart: func(d ocispec.Descriptor, offset int64) func(int64) {
			if offset > 0 {
				resumedFrom.Store(offset)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("pull with drop: %v", err)
	}

	ranges := reg.RangeRequests(wDesc.Digest)
	if len(ranges) == 0 {
		t.Fatal("no Range request seen: resume did not happen")
	}
	if resumedFrom.Load() == 0 {
		t.Error("OnBlobStart never reported a resume offset")
	}
	if _, err := st.BlobPath(wDesc.Digest); err != nil {
		t.Fatalf("blob missing after resumed pull: %v", err)
	}
}

// TestPullResumesAcrossProcessRestart: a canceled pull leaves a partial;
// a fresh pull resumes it via Range (cold-restart resume, M1 acceptance).
func TestPullResumesAcrossProcessRestart(t *testing.T) {
	reg := registrytest.New(t)
	weights := randomBytes(t, 4<<20)
	_, wDesc := seedRegistryModel(t, reg, "llm/tiny", "q4", weights)

	st := openTestStore(t)
	c := newTestClient(t)
	ref := mustParse(t, reg.Host()+"/llm/tiny:q4")

	// First pull cancels itself after ~512 KiB.
	ctx, cancel := context.WithCancel(context.Background())
	var seen atomic.Int64
	_, err := c.Pull(ctx, st, ref, Events{
		OnBlobStart: func(d ocispec.Descriptor, offset int64) func(int64) {
			return func(n int64) {
				if seen.Add(n) > 512*1024 {
					cancel()
				}
			}
		},
	})
	if err == nil {
		t.Fatal("expected canceled pull to fail")
	}

	ingest, _ := st.IngestDir()
	partials, _ := filepath.Glob(filepath.Join(ingest, "*"))
	if len(partials) == 0 {
		t.Fatal("no partial retained after canceled pull")
	}

	// Fresh pull (simulating a new process) must resume, not restart.
	if _, err := c.Pull(context.Background(), st, ref, Events{}); err != nil {
		t.Fatalf("resumed pull: %v", err)
	}
	if len(reg.RangeRequests(wDesc.Digest)) == 0 {
		t.Fatal("no Range request on restart: expected cold-restart resume")
	}
	p, err := st.BlobPath(wDesc.Digest)
	if err != nil {
		t.Fatalf("blob missing after resume: %v", err)
	}
	onDisk, _ := os.ReadFile(p)
	if digest.FromBytes(onDisk) != wDesc.Digest {
		t.Error("resumed blob content corrupt")
	}
}

// TestPullRestartsWhenRangeIgnored: a registry that ignores Range must not
// corrupt the download — the client restarts hashing from zero.
func TestPullRestartsWhenRangeIgnored(t *testing.T) {
	reg := registrytest.New(t)
	weights := randomBytes(t, 1<<20)
	_, wDesc := seedRegistryModel(t, reg, "llm/tiny", "q4", weights)
	reg.SetIgnoreRange(true)

	st := openTestStore(t)
	// Plant a stale partial so the pull attempts a resume.
	ingest, _ := st.IngestDir()
	partial := filepath.Join(ingest, wDesc.Digest.Algorithm().String()+"-"+wDesc.Digest.Encoded())
	if err := os.WriteFile(partial, weights[:100*1024], 0o600); err != nil {
		t.Fatal(err)
	}

	c := newTestClient(t)
	ref := mustParse(t, reg.Host()+"/llm/tiny:q4")
	if _, err := c.Pull(context.Background(), st, ref, Events{}); err != nil {
		t.Fatalf("pull: %v", err)
	}
	p, _ := st.BlobPath(wDesc.Digest)
	onDisk, _ := os.ReadFile(p)
	if digest.FromBytes(onDisk) != wDesc.Digest {
		t.Error("blob corrupt after Range-ignoring registry")
	}
}

// TestPullRejectsCorruptBlob: content that does not match its descriptor
// digest must fail the pull and leave no partial behind.
func TestPullRejectsCorruptBlob(t *testing.T) {
	reg := registrytest.New(t)
	weights := randomBytes(t, 256*1024)
	_, wDesc := seedRegistryModel(t, reg, "llm/tiny", "q4", weights)
	reg.SetCorruptBlob(wDesc.Digest)

	st := openTestStore(t)
	c := newTestClient(t)
	ref := mustParse(t, reg.Host()+"/llm/tiny:q4")

	_, err := c.Pull(context.Background(), st, ref, Events{})
	if err == nil {
		t.Fatal("corrupt blob must fail the pull")
	}
	if !strings.Contains(err.Error(), "digest mismatch") {
		t.Errorf("error should mention digest mismatch, got: %v", err)
	}
	ingest, _ := st.IngestDir()
	if entries, _ := os.ReadDir(ingest); len(entries) != 0 {
		t.Error("corrupt partial must be discarded")
	}
	if _, err := st.BlobPath(wDesc.Digest); err == nil {
		t.Error("corrupt blob must not be installed")
	}
}

func TestPushRoundTrip(t *testing.T) {
	reg := registrytest.New(t)
	st := openTestStore(t)
	c := newTestClient(t)

	weights := randomBytes(t, 1<<20)
	ref := mustParse(t, reg.Host()+"/llm/tiny:q4")
	mDesc, wDesc := seedStoreModel(t, st, ref.String(), weights)

	got, err := c.Push(context.Background(), st, ref, Events{})
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if got.Digest != mDesc.Digest {
		t.Errorf("pushed root %s, want %s", got.Digest, mDesc.Digest)
	}
	if !reg.HasBlob("llm/tiny", wDesc.Digest) {
		t.Error("weights did not arrive in the registry")
	}
	if !reg.HasManifest("llm/tiny", "q4") {
		t.Error("manifest did not arrive in the registry")
	}

	// Second push: the root manifest already exists, so oras.Copy
	// short-circuits the whole DAG (re-tagging the root server-side) and no
	// blob may be re-uploaded. Note: oras-go deliberately does not fire
	// OnCopySkipped for a skipped root against a registry, so no skip
	// events are expected here.
	uploads := reg.CountRequests("PUT", "/blobs/uploads/")
	if _, err := c.Push(context.Background(), st, ref, Events{}); err != nil {
		t.Fatalf("second push: %v", err)
	}
	if again := reg.CountRequests("PUT", "/blobs/uploads/"); again != uploads {
		t.Errorf("blobs re-uploaded on second push (%d → %d)", uploads, again)
	}
}

// TestPushMountsAcrossRepos: pushing a second repository that shares blobs
// with an already-pushed sibling must mount server-side, not re-upload.
func TestPushMountsAcrossRepos(t *testing.T) {
	reg := registrytest.New(t)
	st := openTestStore(t)
	c := newTestClient(t)

	weights := randomBytes(t, 1<<20)
	refA := mustParse(t, reg.Host()+"/llm/model-a:v1")
	_, wDesc := seedStoreModel(t, st, refA.String(), weights)
	if _, err := c.Push(context.Background(), st, refA, Events{}); err != nil {
		t.Fatalf("push a: %v", err)
	}

	refB := mustParse(t, reg.Host()+"/llm/model-b:v1")
	seedStoreModel(t, st, refB.String(), weights)
	if _, err := c.Push(context.Background(), st, refB, Events{}); err != nil {
		t.Fatalf("push b: %v", err)
	}

	if !reg.HasBlob("llm/model-b", wDesc.Digest) {
		t.Fatal("weights absent from model-b after push")
	}
	// The weight blob must have arrived in model-b via mount (POST with
	// mount=), not via an upload PUT.
	var mountPosts, uploadPuts int
	for _, rec := range reg.Requests() {
		if strings.Contains(rec.Path, "model-b/blobs/uploads") {
			switch rec.Method {
			case http.MethodPost:
				mountPosts++
			case http.MethodPut:
				uploadPuts++
			}
		}
	}
	if mountPosts == 0 {
		t.Error("no upload POST recorded for model-b")
	}
	if uploadPuts > 1 { // config blob may still upload; weights must not
		t.Errorf("expected at most 1 upload PUT for model-b (config), got %d", uploadPuts)
	}
}
