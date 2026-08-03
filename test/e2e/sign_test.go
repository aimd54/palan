// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/secure-systems-lab/go-securesystemslib/encrypted"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/aimd54/palan/internal/signing"
)

// testKeyPassword protects the generated cosign-format key; both palan and
// cosign read it from COSIGN_PASSWORD.
const testKeyPassword = "e2e-pass"

// writeTestKeys generates an ECDSA P-256 keypair in cosign's format: an
// encrypted SIGSTORE private key (accepted by cosign and palan alike) plus
// a plain PEM public key.
func writeTestKeys(t *testing.T) (privPath, pubPath string) {
	t.Helper()
	dir := t.TempDir()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	encDER, err := encrypted.Encrypt(privDER, []byte(testKeyPassword))
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	privPath = filepath.Join(dir, "cosign.key")
	pubPath = filepath.Join(dir, "cosign.pub")
	if err := os.WriteFile(privPath, pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED SIGSTORE PRIVATE KEY", Bytes: encDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return privPath, pubPath
}

// TestSignVerifyAndPullGate: M6 acceptance. Sign a pushed model, verify
// it, enforce the pull gate, and prove an unsigned artifact fails the gate.
func TestSignVerifyAndPullGate(t *testing.T) {
	t.Setenv("COSIGN_PASSWORD", testKeyPassword)
	host := registryHost(t)
	fx := writeFixtures(t, 256<<10)
	priv, pub := writeTestKeys(t)

	signedRef := host + "/llm/signed:v1"
	unsignedRef := host + "/llm/unsigned:v1"

	home := t.TempDir()
	palan(t, home, "pack", fx.ggufPath, "-t", signedRef)
	palan(t, home, "push", signedRef)
	palan(t, home, "pack", fx.ggufPath, "-t", unsignedRef)
	palan(t, home, "push", unsignedRef)

	palan(t, home, "sign", signedRef, "--key", priv)
	out := palan(t, home, "verify", signedRef, "--key", pub)
	if !strings.Contains(out, "Verified") {
		t.Errorf("verify output: %s", out)
	}

	// Gate: signed pulls pass, unsigned pulls are refused.
	homeB := t.TempDir()
	palan(t, homeB, "pull", signedRef, "--verify", "--verify-key", pub)
	if out, err := palanRun(homeB, "pull", unsignedRef, "--verify", "--verify-key", pub); err == nil {
		t.Errorf("unsigned pull with --verify must fail, got:\n%s", out)
	} else if !strings.Contains(out, "no signature") {
		t.Errorf("gate error should mention the missing signature:\n%s", out)
	}

	// Wrong key must also fail the gate.
	_, otherPub := writeTestKeys(t)
	if out, err := palanRun(homeB, "pull", signedRef, "--verify", "--verify-key", otherPub); err == nil {
		t.Errorf("pull verified with the wrong key:\n%s", out)
	}
}

// TestCosignInterop: the real cosign binary must verify palan's signatures
// and palan must verify cosign's (skipped when cosign is not installed).
func TestCosignInterop(t *testing.T) {
	cosign, err := exec.LookPath("cosign")
	if err != nil {
		t.Skip("cosign not in PATH")
	}
	t.Setenv("COSIGN_PASSWORD", testKeyPassword)
	host := registryHost(t)
	fx := writeFixtures(t, 128<<10)
	priv, pub := writeTestKeys(t)

	ref := host + "/llm/cosign-interop:v1"
	home := t.TempDir()
	palan(t, home, "pack", fx.ggufPath, "-t", ref)
	palan(t, home, "push", ref)

	// palan signs → cosign verifies.
	palan(t, home, "sign", ref, "--key", priv)
	cv := exec.Command(cosign, "verify", "--key", pub, "--insecure-ignore-tlog", "--allow-insecure-registry", ref)
	cv.Env = append(os.Environ(), "HOME="+t.TempDir())
	if out, err := cv.CombinedOutput(); err != nil {
		t.Errorf("cosign could not verify palan's signature: %v\n%s", err, out)
	}

	// cosign signs → palan verifies (distinct content so the signature tags
	// do not collide with v1's).
	fx2 := writeFixtures(t, 130<<10)
	ref2 := host + "/llm/cosign-interop:v2"
	palan(t, home, "pack", fx2.ggufPath, "-t", ref2)
	palan(t, home, "push", ref2)
	cs := exec.Command(cosign, "sign", "--key", priv, "--tlog-upload=false", "--allow-insecure-registry", "--yes", ref2)
	cs.Env = append(os.Environ(), "HOME="+t.TempDir())
	if out, err := cs.CombinedOutput(); err != nil {
		t.Fatalf("cosign sign failed: %v\n%s", err, out)
	}
	palan(t, home, "verify", ref2, "--key", pub)
}

// resolveRef resolves a reference against the e2e registry.
func resolveRef(t *testing.T, ref string) (*remote.Repository, ocispec.Descriptor) {
	t.Helper()
	parsed, err := registry.ParseReference(ref)
	if err != nil {
		t.Fatalf("parsing %q: %v", ref, err)
	}
	repo, err := remote.NewRepository(ref)
	if err != nil {
		t.Fatalf("opening %q: %v", ref, err)
	}
	repo.PlainHTTP = true
	desc, err := repo.Resolve(context.Background(), parsed.Reference)
	if err != nil {
		t.Fatalf("resolving %q: %v", ref, err)
	}
	return repo, desc
}

// TestSignatureIsIndexedByTheRegistry asks the registry what it has indexed
// against the model, which is what every referrers-aware tool sees. A tag can
// only be found by guessing its name, so a signature that exists solely under
// one is invisible here.
//
// The assertion is on the descriptor the registry returns, not on the request
// succeeding: an empty referrers list is a perfectly successful response.
func TestSignatureIsIndexedByTheRegistry(t *testing.T) {
	t.Setenv("COSIGN_PASSWORD", testKeyPassword)
	host := registryHost(t)
	fx := writeFixtures(t, 128<<10)
	priv, _ := writeTestKeys(t)

	ref := host + "/llm/referrers-indexed:v1"
	home := t.TempDir()
	palan(t, home, "pack", fx.ggufPath, "-t", ref)
	palan(t, home, "push", ref)
	palan(t, home, "sign", ref, "--key", priv)

	repo, desc := resolveRef(t, ref)
	refs, err := registry.Referrers(context.Background(), repo, desc, signing.ArtifactTypeSignature)
	if err != nil {
		t.Fatalf("asking the registry for referrers: %v", err)
	}
	if len(refs) != 1 {
		t.Fatalf("registry indexed %d signatures for the model, want 1", len(refs))
	}
	if refs[0].ArtifactType != signing.ArtifactTypeSignature {
		t.Errorf("indexed artifact type = %q, want %q", refs[0].ArtifactType, signing.ArtifactTypeSignature)
	}

	// The tag has to keep working: it is what cosign reads by default, and
	// the referrer is an addition rather than a replacement.
	if _, err := repo.Resolve(context.Background(), signing.SigTag(desc.Digest)); err != nil {
		t.Errorf("signature tag no longer resolves: %v", err)
	}
}

// TestVerifyCosignOCI11Signature covers the signature shape palan could not
// read at all: `cosign sign --registry-referrers-mode=oci-1-1` attaches the
// signature as a referrer and writes no tag, so resolving the tag found
// nothing and a signed model was reported unsigned.
//
// The absence of the tag is asserted before verifying, so the test cannot pass
// through the tag path and quietly prove nothing.
func TestVerifyCosignOCI11Signature(t *testing.T) {
	cosign, err := exec.LookPath("cosign")
	if err != nil {
		t.Skip("cosign not in PATH")
	}
	t.Setenv("COSIGN_PASSWORD", testKeyPassword)
	host := registryHost(t)
	fx := writeFixtures(t, 132<<10)
	priv, pub := writeTestKeys(t)

	ref := host + "/llm/oci11-signed:v1"
	home := t.TempDir()
	palan(t, home, "pack", fx.ggufPath, "-t", ref)
	palan(t, home, "push", ref)

	cs := exec.Command(cosign, "sign", "--key", priv,
		"--registry-referrers-mode=oci-1-1",
		"--tlog-upload=false", "--allow-insecure-registry", "--yes", ref)
	// cosign gates the mode behind this variable, which is the measure of how
	// far the ecosystem has moved: writing referrers is opt-in and reading
	// them is a separate opt-in again.
	cs.Env = append(os.Environ(), "HOME="+t.TempDir(), "COSIGN_EXPERIMENTAL=1")
	if out, err := cs.CombinedOutput(); err != nil {
		t.Fatalf("cosign sign in oci-1-1 mode failed: %v\n%s", err, out)
	}

	repo, desc := resolveRef(t, ref)
	if _, err := repo.Resolve(context.Background(), signing.SigTag(desc.Digest)); !errors.Is(err, errdef.ErrNotFound) {
		t.Fatalf("a signature tag exists, so this test would prove nothing: resolve gave %v", err)
	}

	palan(t, home, "verify", ref, "--key", pub)
}

// TestOfflineVerifyFromBundle is the end-to-end guard for the air-gap case:
// a bundle carried to a machine with no registry must still be verifiable,
// and a bundle whose model is unsigned must be refused on import without
// leaving anything behind.
//
// The registry is not merely unused after the export; the references point at
// a host that no longer serves them, so a lingering network dependency shows
// up as a failure rather than passing unnoticed.
func TestOfflineVerifyFromBundle(t *testing.T) {
	t.Setenv("COSIGN_PASSWORD", testKeyPassword)
	host := registryHost(t)
	fx := writeFixtures(t, 256<<10)
	priv, pub := writeTestKeys(t)

	signedRef := host + "/llm/air-signed:v1"
	unsignedRef := host + "/llm/air-unsigned:v1"

	online := t.TempDir()
	palan(t, online, "pack", fx.ggufPath, "-t", signedRef)
	palan(t, online, "push", signedRef)
	palan(t, online, "sign", signedRef, "--key", priv)
	palan(t, online, "pack", fx.ggufPath, "-t", unsignedRef)
	palan(t, online, "push", unsignedRef)

	// Pulling brings the signature down beside the model.
	if out := palan(t, online, "pull", signedRef); !strings.Contains(out, "Signature stored") {
		t.Errorf("pull should report the signature travelling:\n%s", out)
	}

	bundle := filepath.Join(t.TempDir(), "signed.tar")
	if out := palan(t, online, "save", signedRef, "-o", bundle); !strings.Contains(out, "signature") {
		t.Errorf("save should report the signature it included:\n%s", out)
	}

	offline := t.TempDir()
	palan(t, offline, "load", "-i", bundle, "--verify", "--verify-key", pub)

	out := palan(t, offline, "verify", signedRef, "--key", pub)
	if !strings.Contains(out, "Verified") {
		t.Errorf("verify from the bundle failed:\n%s", out)
	}
	if !strings.Contains(out, "local store") {
		t.Errorf("verification should have read the local store, not the registry:\n%s", out)
	}

	// A wrong key must still be rejected when the source is a bundle.
	_, otherPub := writeTestKeys(t)
	if out, err := palanRun(offline, "verify", signedRef, "--key", otherPub); err == nil {
		t.Errorf("wrong key verified against the local store:\n%s", out)
	}

	// An unsigned bundle must be refused, and must import nothing.
	unsignedBundle := filepath.Join(t.TempDir(), "unsigned.tar")
	palan(t, online, "pull", unsignedRef)
	palan(t, online, "save", unsignedRef, "-o", unsignedBundle)

	rejected := t.TempDir()
	out, err := palanRun(rejected, "load", "-i", unsignedBundle, "--verify", "--verify-key", pub)
	if err == nil {
		t.Errorf("an unsigned bundle must be refused:\n%s", out)
	} else if !strings.Contains(out, "no signature") {
		t.Errorf("refusal should name the missing signature:\n%s", out)
	}
	if listed := palan(t, rejected, "ls"); strings.Contains(listed, "air-unsigned") {
		t.Errorf("a refused bundle must import nothing, store holds:\n%s", listed)
	}
}

// TestLoadRejectsSignatureShapedModel covers a bundle crafted to slip past
// verification: a model tagged so it looks like a cosign signature. The
// verifier skips signature-shaped references, so anything left over has to be
// proven to belong to a model that verified, or the whole import is refused.
//
// Asserting on the exit status alone would not catch this. The earlier form
// of the check exited 0 and imported the model anyway, so the store is what
// the test looks at.
func TestLoadRejectsSignatureShapedModel(t *testing.T) {
	t.Setenv("COSIGN_PASSWORD", testKeyPassword)
	host := registryHost(t)
	fx := writeFixtures(t, 64<<10)
	_, pub := writeTestKeys(t)

	// A tag shaped exactly like a signature, attached to an ordinary model.
	disguised := host + "/llm/disguised:sha256-" + strings.Repeat("a", 64) + ".sig"

	online := t.TempDir()
	palan(t, online, "pack", fx.ggufPath, "-t", disguised)

	bundle := filepath.Join(t.TempDir(), "disguised.tar")
	palan(t, online, "save", disguised, "-o", bundle)

	offline := t.TempDir()
	out, err := palanRun(offline, "load", "-i", bundle, "--verify", "--verify-key", pub)
	if err == nil {
		t.Errorf("a signature-shaped model must not pass verification:\n%s", out)
	}
	if listed := palan(t, offline, "ls"); strings.Contains(listed, "disguised") {
		t.Errorf("nothing should have been imported, store holds:\n%s", listed)
	}
	// The store must be empty, not merely missing that one listing.
	blobs := filepath.Join(offline, "blobs", "sha256")
	if entries, err := os.ReadDir(blobs); err == nil && len(entries) > 0 {
		t.Errorf("refused bundle left %d blob(s) on disk", len(entries))
	}
}
