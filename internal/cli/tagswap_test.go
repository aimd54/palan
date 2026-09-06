// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/viper"

	"github.com/aimd54/palan/internal/registrytest"
	"github.com/aimd54/palan/internal/store"
)

// swappingRegistry proxies to a real registry but answers one tag with a
// different repository path once it has been asked the first time.
//
// A tag is mutable and a registry answers each request on its own, so a
// command that resolves a tag to check it and resolves the tag again to
// fetch it has checked one artifact and downloaded another. Nothing about
// that needs a hostile registry: an ordinary tag move landing between the
// two requests does it.
func swappingRegistry(t *testing.T, upstream, tagPath, swapTo string, after int32) (host string, arm func()) {
	t.Helper()
	target, err := url.Parse("http://" + upstream)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	var armed atomic.Bool
	var seen atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Armed after the fixture is signed, so the signature is made
		// against this host and its identity matches. From then on the
		// first ask answers honestly and every later one does not, which
		// is the whole point: one resolve to check, another to fetch.
		if armed.Load() && r.URL.Path == tagPath && seen.Add(1) > after {
			r.URL.Path = swapTo
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://"), func() { armed.Store(true) }
}

// TestPullRefusesWhenTheTagAnswersDifferentlyTheSecondTime: the signature
// is checked against whatever the tag resolved to, and the fetch used to
// resolve it again. Both halves reported success, and the file written into
// the output directory was never the one that verified.
func TestPullRefusesWhenTheTagAnswersDifferentlyTheSecondTime(t *testing.T) {
	reg := registrytest.New(t)

	signedBody := []byte("the weights a publisher signed")
	reg.PutBlob("llm/qwen3", signedBody)
	seedModel(t, reg, "llm/qwen3", "v1", []ocispec.Descriptor{localLayer(signedBody, "model.gguf")})
	priv, privKey := attestKeypair(t)
	pubKey := attestPubKeyFile(t, priv)

	// A second artifact nobody signed, in the same repository under another
	// tag. Same repository matters: a manifest's blobs are fetched from the
	// repository the request names, so a substitute served from somewhere
	// else fails on a missing blob and the refusal under test never has to
	// happen. Here the whole artifact is reachable and the copy would go
	// through, which is what a tag moving actually looks like.
	unsignedBody := []byte("the weights nobody ever signed")
	reg.PutBlob("llm/qwen3", unsignedBody)
	seedModel(t, reg, "llm/qwen3", "moved", []ocispec.Descriptor{localLayer(unsignedBody, "model.gguf")})

	host, arm := swappingRegistry(t, reg.Host(),
		"/v2/llm/qwen3/manifests/v1", "/v2/llm/qwen3/manifests/moved", 1)
	ref := host + "/llm/qwen3:v1"
	// Signed through the proxy, so the signature names this host.
	if err := runSign(t, ref, privKey); err != nil {
		t.Fatalf("signing the fixture: %v", err)
	}
	arm()

	home := t.TempDir()
	dir := filepath.Join(t.TempDir(), "models")
	t.Setenv("PALAN_HOME", home)
	v := viper.New()
	v.Set(keyRegistryPlainHTTP, true)
	v.Set(keyVerifyRequired, true)
	v.Set(keyVerifyKey, pubKey)
	cmd := newPullCmd(v)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{ref, "--output=" + dir})
	err := cmd.Execute()

	if err == nil {
		t.Fatal("pull verified one artifact and fetched another without noticing")
	}
	if !strings.Contains(err.Error(), "was checked") {
		t.Errorf("the refusal does not say the artifact differs from the checked one: %v", err)
	}
	// Positive state, which is the property the gate pattern rests on:
	// nothing unverified reached the directory a serving container mounts.
	entries, rerr := os.ReadDir(dir)
	if rerr != nil && !os.IsNotExist(rerr) {
		t.Fatal(rerr)
	}
	if len(entries) != 0 {
		t.Fatalf("the refusal left %d entr(ies) in the output directory", len(entries))
	}
	// And the unsigned weights are not in the store either.
	st, serr := store.Open(context.Background(), home)
	if serr != nil {
		t.Fatal(serr)
	}
	if _, berr := st.BlobPath(localLayer(unsignedBody, "model.gguf").Digest); berr == nil {
		t.Fatal("the store holds the weights that were never verified")
	}
}

// TestPullFetchesByDigestOnceTheTagHasBeenResolved covers the swap landing
// later, after the comparison has already agreed. Resolving the tag a third
// time to fetch it is another chance for the answer to differ, so the fetch
// asks for the digest instead. Here the pull must succeed and the bytes must
// be the signed ones, which is the only thing that distinguishes fetching
// the digest from fetching the tag again.
func TestPullFetchesByDigestOnceTheTagHasBeenResolved(t *testing.T) {
	reg := registrytest.New(t)

	signedBody := []byte("the weights a publisher signed")
	reg.PutBlob("llm/qwen3", signedBody)
	seedModel(t, reg, "llm/qwen3", "v1", []ocispec.Descriptor{localLayer(signedBody, "model.gguf")})
	priv, privKey := attestKeypair(t)
	pubKey := attestPubKeyFile(t, priv)

	unsignedBody := []byte("the weights nobody ever signed")
	reg.PutBlob("llm/qwen3", unsignedBody)
	seedModel(t, reg, "llm/qwen3", "moved", []ocispec.Descriptor{localLayer(unsignedBody, "model.gguf")})

	// Two honest answers, then substitution: the check and the descriptor
	// comparison both agree, and only the fetch is targeted.
	host, arm := swappingRegistry(t, reg.Host(),
		"/v2/llm/qwen3/manifests/v1", "/v2/llm/qwen3/manifests/moved", 2)
	ref := host + "/llm/qwen3:v1"
	if err := runSign(t, ref, privKey); err != nil {
		t.Fatalf("signing the fixture: %v", err)
	}
	arm()

	dir := filepath.Join(t.TempDir(), "models")
	t.Setenv("PALAN_HOME", t.TempDir())
	v := viper.New()
	v.Set(keyRegistryPlainHTTP, true)
	v.Set(keyVerifyRequired, true)
	v.Set(keyVerifyKey, pubKey)
	cmd := newPullCmd(v)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{ref, "--output=" + dir})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("the artifact that verified is still on the registry, so the pull must succeed: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "model.gguf")) // #nosec G304 -- test fixture under a temp dir
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(signedBody) {
		t.Fatalf("the output directory holds %q, which is not what verified", got)
	}
}

// TestRunFetchesTheModelItChecked: run verifies before it fetches, and then
// compares what landed against what verified, so a substitution is refused
// either way. What differs is what the refusal costs. Fetching whatever the
// tag answers with means the whole substituted artifact is downloaded,
// written into the content-addressed store and tagged under this reference
// before the comparison rejects it, leaving the store holding the thing
// that was just refused and the tag pointing at it. A later run without
// verification loads it.
//
// So the assertion is about the store, not about the error: a refusal has
// to leave nothing behind.
func TestRunFetchesTheModelItChecked(t *testing.T) {
	reg := registrytest.New(t)

	signedBody := []byte("the weights a publisher signed")
	reg.PutBlob("llm/qwen3", signedBody)
	seedModel(t, reg, "llm/qwen3", "v1", []ocispec.Descriptor{localLayer(signedBody, "model.gguf")})
	priv, privKey := attestKeypair(t)
	pubKey := attestPubKeyFile(t, priv)

	unsignedBody := []byte("the weights nobody ever signed")
	reg.PutBlob("llm/qwen3", unsignedBody)
	seedModel(t, reg, "llm/qwen3", "moved", []ocispec.Descriptor{localLayer(unsignedBody, "model.gguf")})

	host, arm := swappingRegistry(t, reg.Host(),
		"/v2/llm/qwen3/manifests/v1", "/v2/llm/qwen3/manifests/moved", 1)
	ref := host + "/llm/qwen3:v1"
	if err := runSign(t, ref, privKey); err != nil {
		t.Fatalf("signing the fixture: %v", err)
	}
	arm()

	home := t.TempDir()
	if _, err := runRunCmd(t, home, ref, pubKey, "", false); err == nil {
		t.Fatal("run verified one artifact and loaded another without noticing")
	}

	st, serr := store.Open(context.Background(), home)
	if serr != nil {
		t.Fatal(serr)
	}
	if _, berr := st.BlobPath(localLayer(unsignedBody, "model.gguf").Digest); berr == nil {
		t.Fatal("the refusal left the unverified weights in the store")
	}
	if _, rerr := st.Resolve(context.Background(), ref); rerr == nil {
		t.Fatal("the refusal left the reference tagged in the store, so a later run without --verify loads it")
	}
}
