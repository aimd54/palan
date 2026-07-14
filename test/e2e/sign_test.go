// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secure-systems-lab/go-securesystemslib/encrypted"
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

// TestSignVerifyAndPullGate: M6 acceptance — sign a pushed model, verify
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
