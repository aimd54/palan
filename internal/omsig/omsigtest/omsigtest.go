// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

// Package omsigtest builds signed Sigstore bundles of the shape the
// model-signing tool writes, so a test can exercise omsig.Verify, or code
// built on it, without a network or a real signing key.
package omsigtest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/aimd54/palan/internal/omsig"
)

// Key generates a fresh ECDSA P-256 key and returns a verifier for it
// alongside the PEM encoding of its public half, for a test that needs a
// key with no bundle behind it (for example, one to prove an unrelated key
// does not verify a given signature).
func Key(t testing.TB) (verifier signature.Verifier, publicKeyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err = signature.LoadVerifier(key.Public(), crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	pem, err := cryptoutils.MarshalPublicKeyToPEM(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	return verifier, pem
}

// Bundle builds a Sigstore bundle of the shape the model-signing tool
// writes: a DSSE envelope carrying an in-toto statement, signed with a
// freshly generated key. subjects maps a repository path to its hex
// SHA-256; each entry becomes one of the predicate's "resources" listing,
// which is where the real tool records a per-file digest. The statement's
// own top-level "subject" array is populated the way the tool populates
// it, with a single entry naming the model as a whole, so a test bundle has
// the same shape a verifier will ever actually see; the value of that
// entry's digest is not meaningful here because nothing in this package
// checks it.
func Bundle(t testing.TB, subjects map[string]string) (bundle []byte, verifier signature.Verifier, publicKeyPEM []byte) {
	t.Helper()
	var resources []map[string]any
	for name, dig := range subjects {
		resources = append(resources, map[string]any{"name": name, "algorithm": "sha256", "digest": dig})
	}
	stmt := map[string]any{
		"_type": "https://in-toto.io/Statement/v1",
		"subject": []map[string]any{
			{"name": "model", "digest": map[string]string{"sha256": strings.Repeat("0", 64)}},
		},
		"predicateType": omsig.PredicateType,
		"predicate": map[string]any{
			"resources": resources,
			"serialization": map[string]any{
				"method":         "files",
				"hash_type":      "sha256",
				"allow_symlinks": false,
			},
		},
	}
	return SignStatement(t, stmt)
}

// SignStatement signs an arbitrary in-toto statement the same way Bundle
// does, so a test can carry a malformed statement (a bad predicate type, a
// resource with no digest, no resources at all) inside a signature that
// still verifies, and so exercise what happens after the signature checks
// out.
func SignStatement(t testing.TB, stmt map[string]any) (bundle []byte, verifier signature.Verifier, publicKeyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := signature.LoadSigner(key, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err = signature.LoadVerifier(key.Public(), crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	publicKeyPEM, err = cryptoutils.MarshalPublicKeyToPEM(key.Public())
	if err != nil {
		t.Fatal(err)
	}

	raw, err := json.Marshal(stmt)
	if err != nil {
		t.Fatal(err)
	}
	pae := fmt.Sprintf("DSSEv1 %d %s %d %s", len(omsig.PayloadType), omsig.PayloadType, len(raw), raw)
	sig, err := signer.SignMessage(strings.NewReader(pae))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err = json.Marshal(map[string]any{
		"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		"dsseEnvelope": map[string]any{
			"payload":     base64.StdEncoding.EncodeToString(raw),
			"payloadType": omsig.PayloadType,
			"signatures":  []map[string]any{{"sig": base64.StdEncoding.EncodeToString(sig)}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return bundle, verifier, publicKeyPEM
}
