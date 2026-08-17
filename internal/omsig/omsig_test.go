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
	"errors"
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

// signStatement signs an arbitrary in-toto statement the same way testBundle
// does, so a test can carry a malformed statement (a bad predicate type, a
// subject with no digest, no subjects at all) inside a signature that still
// verifies, and so exercise what happens after the signature checks out.
func signStatement(t *testing.T, stmt map[string]any) ([]byte, signature.Verifier) {
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
	raw, err := json.Marshal(stmt)
	if err != nil {
		t.Fatal(err)
	}
	pae := fmt.Sprintf("DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(raw), raw)
	sig, err := signer.SignMessage(strings.NewReader(pae))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := json.Marshal(map[string]any{
		"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		"dsseEnvelope": map[string]any{
			"payload":     base64.StdEncoding.EncodeToString(raw),
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
	err = st.Covers("tokenizer.json", "dd"+strings.Repeat("0", 62))
	if err == nil {
		t.Fatal("accepted a file the signature says nothing about")
	}
	if !errors.Is(err, ErrNotCovered) {
		t.Errorf("Covers error = %v, want it to wrap ErrNotCovered so callers can match it with errors.Is", err)
	}
	if err := st.Covers("model.safetensors", "ee"+strings.Repeat("0", 62)); err == nil {
		t.Fatal("accepted bytes that do not hash to what the statement lists")
	}
}

func TestCoversIsCaseInsensitiveOnHexDigest(t *testing.T) {
	// Published in the statement with uppercase hex letters.
	dig := "AA" + strings.Repeat("0", 62)
	bundle, v := testBundle(t, map[string]string{"model.safetensors": dig})
	st, err := Verify(bundle, v)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Covers("model.safetensors", strings.ToLower(dig)); err != nil {
		t.Errorf("Covers rejected a lowercase digest matching an uppercase one in the statement: %v", err)
	}
	if err := st.Covers("model.safetensors", strings.ToUpper(dig)); err != nil {
		t.Errorf("Covers rejected an uppercase digest matching the statement: %v", err)
	}
}

func TestCoversRefusesAnEmptyDigest(t *testing.T) {
	bundle, v := testBundle(t, map[string]string{"model.safetensors": "aa" + strings.Repeat("0", 62)})
	st, err := Verify(bundle, v)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Covers("model.safetensors", ""); err == nil {
		t.Fatal("accepted an empty digest as covering a file")
	}
}

// TestVerifyRefusesAStatementThatVouchesForNothing exercises every case
// where a signature verifies but what it covers is degenerate: a signature
// that checks out while vouching for nothing is worse than no signature,
// because it looks like proof. Each case must be refused, not treated as
// vacuously valid.
func TestVerifyRefusesAStatementThatVouchesForNothing(t *testing.T) {
	validDigest := "aa" + strings.Repeat("0", 62)

	cases := []struct {
		name    string
		build   func(t *testing.T) ([]byte, signature.Verifier)
		wantErr string // substring the returned error must contain
	}{
		{
			name: "wrong payload type",
			build: func(t *testing.T) ([]byte, signature.Verifier) {
				bundle, v := testBundle(t, map[string]string{"model.safetensors": validDigest})
				var b map[string]any
				if err := json.Unmarshal(bundle, &b); err != nil {
					t.Fatal(err)
				}
				env := b["dsseEnvelope"].(map[string]any)
				env["payloadType"] = "application/vnd.other+json"
				edited, err := json.Marshal(b)
				if err != nil {
					t.Fatal(err)
				}
				return edited, v
			},
			wantErr: "payload type",
		},
		{
			name: "zero signatures",
			build: func(t *testing.T) ([]byte, signature.Verifier) {
				bundle, v := testBundle(t, map[string]string{"model.safetensors": validDigest})
				var b map[string]any
				if err := json.Unmarshal(bundle, &b); err != nil {
					t.Fatal(err)
				}
				env := b["dsseEnvelope"].(map[string]any)
				env["signatures"] = []map[string]any{}
				edited, err := json.Marshal(b)
				if err != nil {
					t.Fatal(err)
				}
				return edited, v
			},
			wantErr: "no signature",
		},
		{
			name: "wrong predicate type",
			build: func(t *testing.T) ([]byte, signature.Verifier) {
				return signStatement(t, map[string]any{
					"_type":         "https://in-toto.io/Statement/v1",
					"subject":       []map[string]any{{"name": "model.safetensors", "digest": map[string]string{"sha256": validDigest}}},
					"predicateType": "https://example.com/some/other/predicate/v1",
					"predicate":     map[string]any{},
				})
			},
			wantErr: "predicate",
		},
		{
			name: "subject with no sha256 digest",
			build: func(t *testing.T) ([]byte, signature.Verifier) {
				return signStatement(t, map[string]any{
					"_type":         "https://in-toto.io/Statement/v1",
					"subject":       []map[string]any{{"name": "model.safetensors", "digest": map[string]string{"sha1": "deadbeef"}}},
					"predicateType": PredicateType,
					"predicate":     map[string]any{},
				})
			},
			wantErr: "model.safetensors",
		},
		{
			name: "subject with a malformed sha256 digest",
			build: func(t *testing.T) ([]byte, signature.Verifier) {
				return signStatement(t, map[string]any{
					"_type":         "https://in-toto.io/Statement/v1",
					"subject":       []map[string]any{{"name": "model.safetensors", "digest": map[string]string{"sha256": "not-a-hex-digest"}}},
					"predicateType": PredicateType,
					"predicate":     map[string]any{},
				})
			},
			wantErr: "model.safetensors",
		},
		{
			name: "statement covers zero subjects",
			build: func(t *testing.T) ([]byte, signature.Verifier) {
				return signStatement(t, map[string]any{
					"_type":         "https://in-toto.io/Statement/v1",
					"subject":       []map[string]any{},
					"predicateType": PredicateType,
					"predicate":     map[string]any{},
				})
			},
			wantErr: "no files",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bundle, v := c.build(t)
			st, err := Verify(bundle, v)
			if err == nil {
				t.Fatalf("Verify accepted a statement that vouches for nothing: got %+v", st)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("error = %q, want it to mention %q", err.Error(), c.wantErr)
			}
		})
	}
}
