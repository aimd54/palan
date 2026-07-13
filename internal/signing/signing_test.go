// Copyright The moci Authors
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/secure-systems-lab/go-securesystemslib/encrypted"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/aimd54/moci/internal/registrytest"
)

func testKeypair(t *testing.T) (*ecdsa.PrivateKey, []byte, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privPEM, err := cryptoutils.MarshalPrivateKeyToPEM(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := cryptoutils.MarshalPublicKeyToPEM(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return priv, privPEM, pubPEM
}

func testRepo(t *testing.T, reg *registrytest.Registry, name string) *remote.Repository {
	t.Helper()
	repo, err := remote.NewRepository(reg.Host() + "/" + name)
	if err != nil {
		t.Fatal(err)
	}
	repo.PlainHTTP = true
	repo.Client = &auth.Client{Credential: auth.StaticCredential("", auth.EmptyCredential)}
	return repo
}

// seedArtifact plants a manifest in the registry and returns its digest.
// The tag is baked into an annotation so different tags give different
// digests.
func seedArtifact(t *testing.T, reg *registrytest.Registry, repo, tag string) digest.Digest {
	t.Helper()
	manifest := ocispec.Manifest{
		MediaType:   ocispec.MediaTypeImageManifest,
		Annotations: map[string]string{"test.seed": tag},
	}
	manifest.SchemaVersion = 2
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return reg.PutManifest(repo, tag, ocispec.MediaTypeImageManifest, raw)
}

func TestSignVerifyRoundTrip(t *testing.T) {
	ctx := context.Background()
	reg := registrytest.New(t)
	target := seedArtifact(t, reg, "llm/tiny", "q4")
	_, privPEM, pubPEM := testKeypair(t)

	repo := testRepo(t, reg, "llm/tiny")
	repoRef := reg.Host() + "/llm/tiny"

	signer, err := LoadSigner(privPEM, nil)
	if err != nil {
		t.Fatalf("load signer: %v", err)
	}
	if _, err := Sign(ctx, repo, repoRef, target, signer); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !reg.HasManifest("llm/tiny", SigTag(target)) {
		t.Fatal("signature manifest not stored under the cosign tag")
	}

	verifier, err := LoadVerifier(pubPEM)
	if err != nil {
		t.Fatalf("load verifier: %v", err)
	}
	if err := Verify(ctx, repo, repoRef, target, verifier); err != nil {
		t.Errorf("verify: %v", err)
	}
}

func TestVerifyFailsWithWrongKey(t *testing.T) {
	ctx := context.Background()
	reg := registrytest.New(t)
	target := seedArtifact(t, reg, "llm/tiny", "q4")
	_, privPEM, _ := testKeypair(t)
	_, _, otherPubPEM := testKeypair(t)

	repo := testRepo(t, reg, "llm/tiny")
	repoRef := reg.Host() + "/llm/tiny"
	signer, _ := LoadSigner(privPEM, nil)
	if _, err := Sign(ctx, repo, repoRef, target, signer); err != nil {
		t.Fatal(err)
	}
	verifier, _ := LoadVerifier(otherPubPEM)
	if err := Verify(ctx, repo, repoRef, target, verifier); err == nil {
		t.Error("wrong key must fail verification")
	}
}

func TestVerifyFailsOnUnsigned(t *testing.T) {
	ctx := context.Background()
	reg := registrytest.New(t)
	target := seedArtifact(t, reg, "llm/tiny", "q4")
	_, _, pubPEM := testKeypair(t)

	repo := testRepo(t, reg, "llm/tiny")
	verifier, _ := LoadVerifier(pubPEM)
	err := Verify(ctx, repo, reg.Host()+"/llm/tiny", target, verifier)
	if !errors.Is(err, ErrNoSignature) {
		t.Errorf("expected ErrNoSignature, got %v", err)
	}
}

// TestVerifyRejectsDigestSubstitution: a valid signature for artifact A
// must not validate artifact B (the signature tag was copied over).
func TestVerifyRejectsDigestSubstitution(t *testing.T) {
	ctx := context.Background()
	reg := registrytest.New(t)
	targetA := seedArtifact(t, reg, "llm/tiny", "q4")
	targetB := seedArtifact(t, reg, "llm/tiny", "q5-other")
	_, privPEM, pubPEM := testKeypair(t)

	repo := testRepo(t, reg, "llm/tiny")
	repoRef := reg.Host() + "/llm/tiny"
	signer, _ := LoadSigner(privPEM, nil)
	if _, err := Sign(ctx, repo, repoRef, targetA, signer); err != nil {
		t.Fatal(err)
	}

	// Republish A's signature manifest under B's signature tag.
	reg.CopyManifest("llm/tiny", SigTag(targetA), SigTag(targetB))

	verifier, _ := LoadVerifier(pubPEM)
	err := Verify(ctx, repo, repoRef, targetB, verifier)
	if err == nil || !strings.Contains(err.Error(), "binds") {
		t.Errorf("substituted signature must fail with a binding error, got %v", err)
	}
}

func TestVerifyRejectsForeignIdentity(t *testing.T) {
	ctx := context.Background()
	reg := registrytest.New(t)
	target := seedArtifact(t, reg, "llm/tiny", "q4")
	_, privPEM, pubPEM := testKeypair(t)

	repo := testRepo(t, reg, "llm/tiny")
	signer, _ := LoadSigner(privPEM, nil)
	// Signed claiming a different repository identity.
	if _, err := Sign(ctx, repo, "evil.example/llm/other", target, signer); err != nil {
		t.Fatal(err)
	}
	verifier, _ := LoadVerifier(pubPEM)
	err := Verify(ctx, repo, reg.Host()+"/llm/tiny", target, verifier)
	if err == nil || !strings.Contains(err.Error(), "identity") {
		t.Errorf("foreign identity must be rejected, got %v", err)
	}
}

func TestLoadSignerCosignEncryptedKey(t *testing.T) {
	priv, _, _ := testKeypair(t)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := encrypted.Encrypt(der, []byte("hunter2"))
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: cosignPEMType, Bytes: enc})

	if _, err := LoadSigner(pemBytes, func() ([]byte, error) { return []byte("hunter2"), nil }); err != nil {
		t.Errorf("encrypted key with correct password: %v", err)
	}
	if _, err := LoadSigner(pemBytes, func() ([]byte, error) { return []byte("wrong"), nil }); err == nil {
		t.Error("wrong password must fail")
	}
	if _, err := LoadSigner(pemBytes, nil); err == nil {
		t.Error("encrypted key without a password source must fail")
	}
}
