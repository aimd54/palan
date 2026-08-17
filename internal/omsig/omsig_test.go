// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package omsig

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

	"github.com/sigstore/sigstore/pkg/signature"
)

// testBundle builds a Sigstore bundle of the shape the model-signing tool
// writes: a DSSE envelope carrying an in-toto statement, signed over the
// pre-authentication encoding.
func testBundle(t *testing.T, subjects map[string]string) ([]byte, signature.Verifier) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := signature.LoadSigner(key, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := signature.LoadVerifier(key.Public(), crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	var subs []map[string]any
	for name, dig := range subjects {
		subs = append(subs, map[string]any{"name": name, "digest": map[string]string{"sha256": dig}})
	}
	stmt, err := json.Marshal(map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       subs,
		"predicateType": PredicateType,
		"predicate":     map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	pae := fmt.Sprintf("DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(stmt), stmt)
	sig, err := signer.SignMessage(strings.NewReader(pae))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := json.Marshal(map[string]any{
		"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		"dsseEnvelope": map[string]any{
			"payload":     base64.StdEncoding.EncodeToString(stmt),
			"payloadType": payloadType,
			"signatures":  []map[string]any{{"sig": base64.StdEncoding.EncodeToString(sig)}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return bundle, verifier
}

func TestVerifyReturnsTheSubjectsTheSignatureCovers(t *testing.T) {
	want := map[string]string{
		"model.safetensors": "aa" + strings.Repeat("0", 62),
		"config.json":       "bb" + strings.Repeat("0", 62),
	}
	bundle, v := testBundle(t, want)

	st, err := Verify(bundle, v)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	for name, dig := range want {
		if st.Subjects[name] != dig {
			t.Errorf("subject %s = %q, want %q", name, st.Subjects[name], dig)
		}
	}
	if st.KeyID == "" {
		t.Error("Verify returned no identity, so the artifact could not record who signed it")
	}
	if err := st.Covers("model.safetensors", want["model.safetensors"]); err != nil {
		t.Errorf("Covers rejected a file the statement lists: %v", err)
	}
}

func TestVerifyRefusesASignatureOverDifferentBytes(t *testing.T) {
	bundle, v := testBundle(t, map[string]string{"model.safetensors": "aa" + strings.Repeat("0", 62)})
	// Re-sign nothing: tamper with the payload the signature was made over.
	var b map[string]any
	if err := json.Unmarshal(bundle, &b); err != nil {
		t.Fatal(err)
	}
	env := b["dsseEnvelope"].(map[string]any)
	tampered, _ := json.Marshal(map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []map[string]any{{"name": "model.safetensors", "digest": map[string]string{"sha256": "cc" + strings.Repeat("0", 62)}}},
		"predicateType": PredicateType,
	})
	env["payload"] = base64.StdEncoding.EncodeToString(tampered)
	edited, _ := json.Marshal(b)

	if _, err := Verify(edited, v); err == nil {
		t.Fatal("verified a statement the key never signed")
	}
}

func TestCoversRefusesAFileTheStatementDoesNotList(t *testing.T) {
	bundle, v := testBundle(t, map[string]string{"model.safetensors": "aa" + strings.Repeat("0", 62)})
	st, err := Verify(bundle, v)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Covers("tokenizer.json", "dd"+strings.Repeat("0", 62)); err == nil {
		t.Fatal("accepted a file the signature says nothing about")
	}
	if err := st.Covers("model.safetensors", "ee"+strings.Repeat("0", 62)); err == nil {
		t.Fatal("accepted bytes that do not hash to what the statement lists")
	}
}
