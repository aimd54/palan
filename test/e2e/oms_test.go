// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/aimd54/palan/internal/omsig"
	"github.com/aimd54/palan/internal/signing"
)

// genKey writes an ECDSA P-256 key pair in the plain, unencrypted PEM forms
// both sides of this test need to agree on: PKCS8 for the private half, so
// the real `model_signing` tool's `serialization.load_pem_private_key` reads
// it, and SubjectPublicKeyInfo for the public half, so both `model_signing`
// and internal/signing.LoadVerifier read the same file. This is a different
// key format from writeTestKeys in sign_test.go, which produces an
// encrypted, cosign-flavored SIGSTORE PRIVATE KEY that the Python tool has
// no reason to understand.
func genKey(t *testing.T, privPath, pubPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(privPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// sha256OfFile hashes a file on disk, the same quantity omsig.Statement.Covers
// checks a signature's resource entries against.
func sha256OfFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// TestVerifiesASignatureTheSigningToolWrote proves the bundle reader against
// the tool that writes the format, rather than against our reading of it.
//
// What the real tool (package model-signing on PyPI, invoked as
// `model_signing`) writes is not what the format's own documentation
// suggested. The in-toto statement's top-level "subject" array holds exactly
// one entry, naming the signed directory as a whole (its basename) with a
// digest computed over every file's digest; that entry is not a file this
// package can check a download against. The per-file listing lives one level
// down, under "predicate.resources", as a name/algorithm/digest triple per
// file, named relative to the signed directory ("model.safetensors", not an
// absolute path and not prefixed with the directory name). internal/omsig
// was corrected to read resources rather than subjects once this was
// discovered; see the pinned shape in internal/omsig/omsig_test.go.
//
// The CLI flags are also spelled with underscores (--private_key,
// --public_key), not the hyphens a first guess from the tool's prose
// documentation would produce; Click, which the tool is built on, refuses
// the hyphenated spelling outright rather than normalizing it.
func TestVerifiesASignatureTheSigningToolWrote(t *testing.T) {
	tool := requireTool(t, "model_signing")

	dir := t.TempDir()
	model := filepath.Join(dir, "model")
	if err := os.MkdirAll(model, 0o750); err != nil {
		t.Fatal(err)
	}
	weights := filepath.Join(model, "model.safetensors")
	if err := os.WriteFile(weights, []byte("weights-for-interop"), 0o600); err != nil {
		t.Fatal(err)
	}
	// internal/cli/pack.go holds a resource's name against a repository path
	// with an exact string compare, so a shard nested under a subdirectory
	// has to come out spelled the way that compare expects: forward-slash
	// joined, relative to the signed directory. A flat fixture cannot catch
	// a change in that spelling; this file is what pins it.
	shardDir := filepath.Join(model, "sub")
	if err := os.MkdirAll(shardDir, 0o750); err != nil {
		t.Fatal(err)
	}
	shard := filepath.Join(shardDir, "weights.bin")
	if err := os.WriteFile(shard, []byte("shard-for-interop"), 0o600); err != nil {
		t.Fatal(err)
	}

	priv := filepath.Join(dir, "signing.key")
	pub := filepath.Join(dir, "signing.pub")
	genKey(t, priv, pub)

	sigPath := filepath.Join(dir, omsig.FileName)
	run(t, tool, "sign", "key", model, "--private_key", priv, "--signature", sigPath)

	bundle, err := os.ReadFile(sigPath)
	if err != nil {
		t.Fatalf("the signing tool wrote no signature: %v", err)
	}
	pemBytes, err := os.ReadFile(pub)
	if err != nil {
		t.Fatal(err)
	}
	v, err := signing.LoadVerifier(pemBytes)
	if err != nil {
		t.Fatal(err)
	}

	stmt, err := omsig.Verify(bundle, v)
	if err != nil {
		t.Fatalf("verifying a signature the tool wrote: %v", err)
	}
	sum := sha256OfFile(t, weights)
	if err := stmt.Covers("model.safetensors", sum); err != nil {
		t.Errorf("the statement does not cover the file that was signed: %v", err)
	}
	// Pins the exact spelling internal/cli/pack.go's exact-string compare
	// relies on: forward-slash joined, relative to the signed directory,
	// not "./sub/weights.bin" and not backslash-joined.
	shardSum := sha256OfFile(t, shard)
	if err := stmt.Covers("sub/weights.bin", shardSum); err != nil {
		t.Errorf("the statement does not cover the nested file under its relative path: %v", err)
	}

	// The other direction: the tool must accept what it wrote, so a failure
	// here is the fixture's fault and not the reader's.
	run(t, tool, "verify", "key", model, "--signature", sigPath, "--public_key", pub)
}
