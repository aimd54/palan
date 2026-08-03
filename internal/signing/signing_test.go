// Copyright The palan Authors
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
	oras "oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/aimd54/palan/internal/registrytest"
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

// seedArtifact plants a manifest in the registry and returns its descriptor.
// The tag is baked into an annotation so different tags give different
// digests. The config blob is real rather than a zero descriptor, because a
// signature names its subject and anything copying the signature walks into
// the subject's own successors.
func seedArtifact(t *testing.T, reg *registrytest.Registry, repo, tag string) ocispec.Descriptor {
	t.Helper()
	cfg := []byte("{}")
	reg.PutBlob(repo, cfg)
	manifest := ocispec.Manifest{
		MediaType:   ocispec.MediaTypeImageManifest,
		Config:      content.NewDescriptorFromBytes(ocispec.MediaTypeImageConfig, cfg),
		Layers:      []ocispec.Descriptor{},
		Annotations: map[string]string{"test.seed": tag},
	}
	manifest.SchemaVersion = 2
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	d := reg.PutManifest(repo, tag, ocispec.MediaTypeImageManifest, raw)
	return ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageManifest,
		Digest:    d,
		Size:      int64(len(raw)),
	}
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
	if !reg.HasManifest("llm/tiny", SigTag(target.Digest)) {
		t.Fatal("signature manifest not stored under the cosign tag")
	}

	verifier, err := LoadVerifier(pubPEM)
	if err != nil {
		t.Fatalf("load verifier: %v", err)
	}
	if err := Verify(ctx, repo, SigTag(target.Digest), repoRef, target, verifier); err != nil {
		t.Errorf("verify: %v", err)
	}
}

// TestSignAttachesSubject proves the signature is discoverable as a referrer
// and not only under its tag. The assertions are on the manifest that was
// stored: a signature whose subject went missing would still verify by tag, so
// checking that Sign returned no error proves nothing about this.
func TestSignAttachesSubject(t *testing.T) {
	ctx := context.Background()
	reg := registrytest.New(t)
	target := seedArtifact(t, reg, "llm/tiny", "q4")
	_, privPEM, _ := testKeypair(t)

	repo := testRepo(t, reg, "llm/tiny")
	signer, err := LoadSigner(privPEM, nil)
	if err != nil {
		t.Fatal(err)
	}
	sigDesc, err := Sign(ctx, repo, reg.Host()+"/llm/tiny", target, signer)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if sigDesc.ArtifactType != ArtifactTypeSignature {
		t.Errorf("returned descriptor artifact type = %q, want %q", sigDesc.ArtifactType, ArtifactTypeSignature)
	}

	raw, err := content.FetchAll(ctx, repo, sigDesc)
	if err != nil {
		t.Fatal(err)
	}
	var manifest ocispec.Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.ArtifactType != ArtifactTypeSignature {
		t.Errorf("manifest artifact type = %q, want %q", manifest.ArtifactType, ArtifactTypeSignature)
	}
	if manifest.Subject == nil {
		t.Fatal("signature manifest carries no subject, so no registry will index it as a referrer")
	}
	if manifest.Subject.Digest != target.Digest {
		t.Errorf("subject digest = %s, want %s", manifest.Subject.Digest, target.Digest)
	}
}

// TestSignedArtifactIsDiscoverableAsReferrer walks the subject edge the way a
// referrers query does. The local layout stands in for any target that answers
// from the graph rather than from a referrers endpoint, which is the same path
// an air-gapped bundle takes.
func TestSignedArtifactIsDiscoverableAsReferrer(t *testing.T) {
	ctx := context.Background()
	reg := registrytest.New(t)
	target := seedArtifact(t, reg, "llm/tiny", "q4")
	_, privPEM, _ := testKeypair(t)

	repo := testRepo(t, reg, "llm/tiny")
	ref := registry.Reference{Registry: reg.Host(), Repository: "llm/tiny", Reference: "q4"}
	signer, err := LoadSigner(privPEM, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Sign(ctx, repo, reg.Host()+"/llm/tiny", target, signer); err != nil {
		t.Fatal(err)
	}

	local, err := oci.NewWithContext(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := oras.Copy(ctx, repo, SigTag(target.Digest), local, SigRef(ref, target.Digest), oras.DefaultCopyOptions); err != nil {
		t.Fatalf("copying the signature into a local layout: %v", err)
	}

	refs, err := registry.Referrers(ctx, local, target, ArtifactTypeSignature)
	if err != nil {
		t.Fatalf("listing referrers: %v", err)
	}
	if len(refs) != 1 {
		t.Fatalf("referrers of the model = %d, want 1", len(refs))
	}
	if refs[0].ArtifactType != ArtifactTypeSignature {
		t.Errorf("referrer artifact type = %q, want %q", refs[0].ArtifactType, ArtifactTypeSignature)
	}
}

// TestVerifyFromReferrerWithoutTag covers the signature shape that has no tag
// at all: what `cosign sign --registry-referrers-mode=oci-1-1` writes. Before
// verification could follow a subject edge, such a model was reported unsigned,
// which is a wrong answer rather than a missing feature.
//
// The signature is copied in by descriptor and never tagged, and the absence of
// the tag is asserted first, so the test cannot pass through the tag path.
func TestVerifyFromReferrerWithoutTag(t *testing.T) {
	ctx := context.Background()
	reg := registrytest.New(t)
	target := seedArtifact(t, reg, "llm/tiny", "q4")
	_, privPEM, pubPEM := testKeypair(t)

	repo := testRepo(t, reg, "llm/tiny")
	ref := registry.Reference{Registry: reg.Host(), Repository: "llm/tiny", Reference: "q4"}
	repoRef := reg.Host() + "/llm/tiny"
	signer, err := LoadSigner(privPEM, nil)
	if err != nil {
		t.Fatal(err)
	}
	sigDesc, err := Sign(ctx, repo, repoRef, target, signer)
	if err != nil {
		t.Fatal(err)
	}

	local, err := oci.NewWithContext(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := oras.Copy(ctx, repo, "q4", local, ref.String(), oras.DefaultCopyOptions); err != nil {
		t.Fatalf("copying the model: %v", err)
	}
	if err := oras.CopyGraph(ctx, repo, local, sigDesc, oras.DefaultCopyGraphOptions); err != nil {
		t.Fatalf("copying the signature graph: %v", err)
	}

	sigRef := SigRef(ref, target.Digest)
	if _, err := local.Resolve(ctx, sigRef); !errors.Is(err, errdef.ErrNotFound) {
		t.Fatalf("signature must not be tagged for this test to mean anything, resolve gave %v", err)
	}

	verifier, err := LoadVerifier(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(ctx, local, sigRef, repoRef, target, verifier); err != nil {
		t.Errorf("verify from a referrer: %v", err)
	}

	// An untagged signature is held to the same standard as a tagged one.
	_, _, otherPubPEM := testKeypair(t)
	otherVerifier, err := LoadVerifier(otherPubPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(ctx, local, sigRef, repoRef, target, otherVerifier); err == nil {
		t.Error("wrong key must fail from a referrer too")
	}
	if err := Verify(ctx, local, sigRef, "evil.example/llm/other", target, verifier); err == nil {
		t.Error("foreign identity must be rejected from a referrer too")
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
	if err := Verify(ctx, repo, SigTag(target.Digest), repoRef, target, verifier); err == nil {
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
	err := Verify(ctx, repo, SigTag(target.Digest), reg.Host()+"/llm/tiny", target, verifier)
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
	reg.CopyManifest("llm/tiny", SigTag(targetA.Digest), SigTag(targetB.Digest))

	verifier, _ := LoadVerifier(pubPEM)
	err := Verify(ctx, repo, SigTag(targetB.Digest), repoRef, targetB, verifier)
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
	err := Verify(ctx, repo, SigTag(target.Digest), reg.Host()+"/llm/tiny", target, verifier)
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

func TestSigRefAndIsSigTag(t *testing.T) {
	d := digest.Digest("sha256:" + strings.Repeat("ab", 32))
	ref := registry.Reference{Registry: "reg.example", Repository: "llm/tiny", Reference: "q4"}

	got := SigRef(ref, d)
	want := "reg.example/llm/tiny:sha256-" + strings.Repeat("ab", 32) + ".sig"
	if got != want {
		t.Errorf("SigRef = %q, want %q", got, want)
	}
	if !IsSigTag(got) {
		t.Errorf("IsSigTag(%q) = false, want true", got)
	}
	for _, notSig := range []string{
		"reg.example/llm/tiny:q4",
		"reg.example/llm/tiny:sha256-deadbeef", // no .sig suffix
		"reg.example/llm/sig:latest",
	} {
		if IsSigTag(notSig) {
			t.Errorf("IsSigTag(%q) = true, want false", notSig)
		}
	}
}

// TestVerifyFromLocalStoreWithoutRegistry is the regression guard for the
// air-gap case that prompted this whole path: a signature carried in an OCI
// layout must verify with no registry reachable at all. The registry is closed
// partway through, so a lingering network dependency fails the test rather
// than passing unnoticed.
func TestVerifyFromLocalStoreWithoutRegistry(t *testing.T) {
	ctx := context.Background()
	reg := registrytest.New(t)
	target := seedArtifact(t, reg, "llm/tiny", "q4")
	_, privPEM, pubPEM := testKeypair(t)

	repo := testRepo(t, reg, "llm/tiny")
	ref := registry.Reference{Registry: reg.Host(), Repository: "llm/tiny", Reference: "q4"}
	repoRef := reg.Host() + "/llm/tiny"
	signer, err := LoadSigner(privPEM, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Sign(ctx, repo, repoRef, target, signer); err != nil {
		t.Fatal(err)
	}

	// Carry the signature into an on-disk layout, the way pull and save do.
	local, err := oci.NewWithContext(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sigRef := SigRef(ref, target.Digest)
	if _, err := oras.Copy(ctx, repo, SigTag(target.Digest), local, sigRef, oras.DefaultCopyOptions); err != nil {
		t.Fatalf("copying signature into the local layout: %v", err)
	}

	// Everything below runs with the registry gone.
	reg.Close()

	verifier, err := LoadVerifier(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(ctx, local, sigRef, repoRef, target, verifier); err != nil {
		t.Errorf("verify from the local store: %v", err)
	}

	// The guarantees must not weaken just because the source changed.
	_, _, otherPubPEM := testKeypair(t)
	otherVerifier, err := LoadVerifier(otherPubPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(ctx, local, sigRef, repoRef, target, otherVerifier); err == nil {
		t.Error("wrong key must fail from the local store too")
	}
	if err := Verify(ctx, local, sigRef, "evil.example/llm/other", target, verifier); err == nil {
		t.Error("foreign identity must be rejected from the local store too")
	}
	missing := digest.Digest("sha256:" + strings.Repeat("cd", 32))
	if err := Verify(ctx, local, SigRef(ref, missing), repoRef, ocispec.Descriptor{Digest: missing}, verifier); !errors.Is(err, ErrNoSignature) {
		t.Errorf("absent signature must report ErrNoSignature, got %v", err)
	}
}
