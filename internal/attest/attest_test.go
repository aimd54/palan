// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package attest_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/aimd54/palan/internal/attest"
)

func keys(t *testing.T) (signature.Signer, signature.Verifier) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := signature.LoadSigner(k, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	v, err := signature.LoadVerifier(k.Public(), crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return s, v
}

func subject() ocispec.Descriptor {
	return ocispec.Descriptor{Digest: digest.Digest("sha256:" + strings.Repeat("a", 64)), Size: 12}
}

func sample() []attest.Layer {
	return []attest.Layer{{
		Digest:    "sha256:" + strings.Repeat("b", 64),
		Repo:      "huggingface.co/org/repo",
		Revision:  "e4f2c1d0000000000000000000000000000000aa",
		Path:      "model-00001-of-00002.safetensors",
		Published: "sha256:" + strings.Repeat("b", 64),
	}}
}

func TestVerifyReturnsTheLayersTheStatementCovers(t *testing.T) {
	s, v := keys(t)
	env, err := attest.Build(subject(), sample(), s)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	got, err := attest.Verify(env, subject(), v)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d layers, want 1", len(got))
	}
	if got[0].Repo != "huggingface.co/org/repo" || got[0].Path != "model-00001-of-00002.safetensors" {
		t.Errorf("layer = %+v, want the source it was built with", got[0])
	}
	if got[0].Revision != sample()[0].Revision {
		t.Errorf("revision = %q, want the one it was built with", got[0].Revision)
	}
}

func TestVerifyRefusesAStatementSignedByAnotherKey(t *testing.T) {
	s, _ := keys(t)
	_, other := keys(t)
	env, err := attest.Build(subject(), sample(), s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := attest.Verify(env, subject(), other); err == nil {
		t.Fatal("verified a statement the key never signed")
	}
}

func TestVerifyRefusesAStatementAboutAnotherArtifact(t *testing.T) {
	s, v := keys(t)
	env, err := attest.Build(subject(), sample(), s)
	if err != nil {
		t.Fatal(err)
	}
	other := ocispec.Descriptor{Digest: digest.Digest("sha256:" + strings.Repeat("c", 64)), Size: 12}
	if _, err := attest.Verify(env, other, v); err == nil {
		t.Fatal("accepted a statement whose subject is a different artifact")
	}
}

func TestVerifyRefusesATamperedPayload(t *testing.T) {
	s, v := keys(t)
	env, err := attest.Build(subject(), sample(), s)
	if err != nil {
		t.Fatal(err)
	}
	var b map[string]any
	if err := json.Unmarshal(env, &b); err != nil {
		t.Fatal(err)
	}
	b["payload"] = base64.StdEncoding.EncodeToString([]byte(`{"_type":"https://in-toto.io/Statement/v1"}`))
	edited, _ := json.Marshal(b)
	if _, err := attest.Verify(edited, subject(), v); err == nil {
		t.Fatal("verified a payload the signature does not cover")
	}
}

func TestBuildRefusesAnEmptyLayerSet(t *testing.T) {
	s, _ := keys(t)
	if _, err := attest.Build(subject(), nil, s); err == nil {
		t.Fatal("built a statement that vouches for nothing")
	}
}

func TestBuildRefusesALayerWithNoSource(t *testing.T) {
	s, _ := keys(t)
	bad := sample()
	bad[0].Repo = ""
	if _, err := attest.Build(subject(), bad, s); err == nil {
		t.Fatal("built a statement claiming a layer whose source is unknown")
	}
}
