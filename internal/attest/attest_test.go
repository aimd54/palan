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
	"fmt"
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

// validStatement returns, as a plain map, the in-toto statement Build would
// construct for subject() and sample(). A test that wants a validly signed
// envelope around a statement Build itself would refuse to produce (a bad
// predicate type, a degenerate subject, a malformed layer digest) starts
// from a copy of this map, changes one field, and signs the result with
// signStatement, bypassing Build's own guards so it exercises what Verify
// does once the signature checks out.
func validStatement() map[string]any {
	dg := subject().Digest.String()
	alg, hexPart, _ := strings.Cut(dg, ":")
	return map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []map[string]any{{"name": dg, "digest": map[string]string{alg: hexPart}}},
		"predicateType": attest.PredicateType,
		"predicate":     map[string]any{"layers": sample()},
	}
}

// signStatement signs an arbitrary statement under payloadType and returns
// the DSSE envelope JSON, the same shape Verify reads. The pre-authentication
// encoding is built here directly from the DSSE spec formula rather than by
// calling into the attest package, so a test built on this helper does not
// share a bug with the code it exercises: a mistake in attest's own pae
// helper cannot make a test written against this helper pass for the wrong
// reason.
func signStatement(t *testing.T, s signature.Signer, payloadType string, stmt any) []byte {
	t.Helper()
	payload, err := json.Marshal(stmt)
	if err != nil {
		t.Fatal(err)
	}
	// DSSE pre-authentication encoding: "DSSEv1" SP LEN(payloadType) SP
	// payloadType SP LEN(payload) SP payload.
	pae := fmt.Sprintf("DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload)
	sig, err := s.SignMessage(strings.NewReader(pae))
	if err != nil {
		t.Fatal(err)
	}
	env, err := json.Marshal(map[string]any{
		"payloadType": payloadType,
		"payload":     base64.StdEncoding.EncodeToString(payload),
		"signatures":  []map[string]any{{"sig": base64.StdEncoding.EncodeToString(sig)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return env
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

// TestVerifyAcceptsASignatureOverTheIndependentlyBuiltPreAuthenticationEncoding
// pins the DSSE framing itself. Build and Verify both call the same
// unexported pae helper, so a bug that made both sign and check the raw
// payload instead of the pre-authentication encoding would leave every
// other test in this file green: Build and Verify would still agree with
// each other, just about the wrong thing. This test signs over a
// pre-authentication encoding built independently, from the DSSE spec
// formula, through signStatement rather than through anything in the
// attest package, and then asks Verify to accept the result. If Verify
// ever authenticates something other than this exact framing, the
// signature it receives will not match and it must refuse.
func TestVerifyAcceptsASignatureOverTheIndependentlyBuiltPreAuthenticationEncoding(t *testing.T) {
	s, v := keys(t)
	env := signStatement(t, s, attest.PayloadType, validStatement())
	got, err := attest.Verify(env, subject(), v)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(got) != 1 || got[0].Repo != sample()[0].Repo || got[0].Digest != sample()[0].Digest {
		t.Errorf("layers = %+v, want the one sample() carries", got)
	}
}

// TestVerifyRefusesATamperedPayload tampers with a single field of an
// otherwise completely valid, validly signed statement: one layer's
// repository. Every other structural check (payload type, predicate type,
// subject, layer completeness) still passes on the tampered statement, so
// the only possible reason Verify can refuse it is that the bytes no longer
// match what the signature was made over.
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
	raw, err := base64.StdEncoding.DecodeString(b["payload"].(string))
	if err != nil {
		t.Fatal(err)
	}
	var stmt map[string]any
	if err := json.Unmarshal(raw, &stmt); err != nil {
		t.Fatal(err)
	}
	predicate := stmt["predicate"].(map[string]any)
	layers := predicate["layers"].([]any)
	layer := layers[0].(map[string]any)
	layer["repo"] = "attacker.example/org/repo" // otherwise valid; only this signed field changed
	tampered, err := json.Marshal(stmt)
	if err != nil {
		t.Fatal(err)
	}
	b["payload"] = base64.StdEncoding.EncodeToString(tampered)
	edited, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
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

// TestVerifyRefusesAStatementThatVouchesForNothing exercises every refusal
// in Verify that runs on a statement whose signature already checks out:
// a wrong payload type and no signatures (both ahead of the expensive
// verification step), and a wrong predicate type, a subject count other
// than one, and a degenerate layer set (all three after it, where a
// refactor is most likely to reorder or drop a check without a test
// noticing). Each envelope here is validly signed; only the field a given
// case names is wrong, so an error and its message are both required, not
// merely an error, and one guard's message cannot satisfy another's
// assertion.
func TestVerifyRefusesAStatementThatVouchesForNothing(t *testing.T) {
	cases := []struct {
		name    string
		build   func(t *testing.T) ([]byte, signature.Verifier)
		wantErr string
	}{
		{
			name: "wrong payload type",
			build: func(t *testing.T) ([]byte, signature.Verifier) {
				s, v := keys(t)
				env := signStatement(t, s, "application/vnd.other+json", validStatement())
				return env, v
			},
			wantErr: "payload type",
		},
		{
			name: "no signatures",
			build: func(t *testing.T) ([]byte, signature.Verifier) {
				_, v := keys(t)
				payload, err := json.Marshal(validStatement())
				if err != nil {
					t.Fatal(err)
				}
				env, err := json.Marshal(map[string]any{
					"payloadType": attest.PayloadType,
					"payload":     base64.StdEncoding.EncodeToString(payload),
					"signatures":  []map[string]any{},
				})
				if err != nil {
					t.Fatal(err)
				}
				return env, v
			},
			wantErr: "no signature",
		},
		{
			name: "wrong predicate type",
			build: func(t *testing.T) ([]byte, signature.Verifier) {
				s, v := keys(t)
				stmt := validStatement()
				stmt["predicateType"] = "https://example.com/some/other/predicate/v1"
				env := signStatement(t, s, attest.PayloadType, stmt)
				return env, v
			},
			wantErr: "predicate",
		},
		{
			name: "subject count other than one",
			build: func(t *testing.T) ([]byte, signature.Verifier) {
				s, v := keys(t)
				stmt := validStatement()
				stmt["subject"] = []map[string]any{}
				env := signStatement(t, s, attest.PayloadType, stmt)
				return env, v
			},
			wantErr: "subjects",
		},
		{
			name: "layer validation Verify re-runs",
			build: func(t *testing.T) ([]byte, signature.Verifier) {
				s, v := keys(t)
				stmt := validStatement()
				stmt["predicate"] = map[string]any{"layers": []attest.Layer{}}
				env := signStatement(t, s, attest.PayloadType, stmt)
				return env, v
			},
			wantErr: "vouch for nothing",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env, v := c.build(t)
			got, err := attest.Verify(env, subject(), v)
			if err == nil {
				t.Fatalf("Verify accepted a statement that vouches for nothing: got %+v", got)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("error = %q, want it to mention %q", err.Error(), c.wantErr)
			}
		})
	}
}

// malformedDigests covers the ways a digest can fail to be the "sha256:"
// plus 64 lowercase hex characters form an OCI descriptor holds: a bare hex
// value with no algorithm prefix at all (the case a caller most plausibly
// hands in by mistake, and the one a silent accept would be most dangerous
// for), a properly prefixed value that is not hex, an uppercase hex value
// (valid hex, but not the canonical lowercase OCI form), and an empty
// value.
var malformedDigests = []struct {
	name   string
	digest string
}{
	{"bare hex with no algorithm prefix", strings.Repeat("b", 64)},
	{"sha256 prefix with malformed hex", "sha256:not-hex"},
	{"uppercase hex", "sha256:" + strings.Repeat("B", 64)},
	{"empty digest", ""},
}

// TestBuildRefusesAMalformedLayerDigest proves Build validates the form of
// a layer's own digest, not merely that it is present: none of these four
// values is empty-string-checked away by the "missing a repository or a
// path" guard, so if the format check were removed Build would sign each
// one.
func TestBuildRefusesAMalformedLayerDigest(t *testing.T) {
	for _, c := range malformedDigests {
		t.Run(c.name, func(t *testing.T) {
			s, _ := keys(t)
			bad := sample()
			bad[0].Digest = c.digest
			if _, err := attest.Build(subject(), bad, s); err == nil {
				t.Fatalf("built a statement whose layer digest is %s (%q)", c.name, c.digest)
			}
		})
	}
}

// TestBuildRefusesAMalformedPublishedDigest proves the same format check
// applies to Published, which is optional (empty is a legitimate "not
// known" value) but must be well formed whenever it is set.
func TestBuildRefusesAMalformedPublishedDigest(t *testing.T) {
	s, _ := keys(t)
	bad := sample()
	bad[0].Published = strings.Repeat("b", 64) // bare hex, no sha256: prefix
	if _, err := attest.Build(subject(), bad, s); err == nil {
		t.Fatal("built a statement whose published digest has no algorithm prefix")
	}
}

// TestVerifyRefusesAMalformedLayerDigest proves Verify re-checks digest
// form on the way in, not just Build on the way out: each statement here is
// validly signed and otherwise complete, built by signStatement rather than
// Build, so only the digest format itself can be the reason Verify refuses
// it.
func TestVerifyRefusesAMalformedLayerDigest(t *testing.T) {
	for _, c := range malformedDigests {
		t.Run(c.name, func(t *testing.T) {
			s, v := keys(t)
			layers := sample()
			layers[0].Digest = c.digest
			stmt := validStatement()
			stmt["predicate"] = map[string]any{"layers": layers}
			env := signStatement(t, s, attest.PayloadType, stmt)
			if _, err := attest.Verify(env, subject(), v); err == nil {
				t.Fatalf("accepted a statement whose layer digest is %s (%q)", c.name, c.digest)
			}
		})
	}
}

// TestVerifyRefusesAMalformedPublishedDigest is TestVerifyRefusesAMalformedLayerDigest's
// counterpart for Published.
func TestVerifyRefusesAMalformedPublishedDigest(t *testing.T) {
	s, v := keys(t)
	layers := sample()
	layers[0].Published = strings.Repeat("b", 64) // bare hex, no sha256: prefix
	stmt := validStatement()
	stmt["predicate"] = map[string]any{"layers": layers}
	env := signStatement(t, s, attest.PayloadType, stmt)
	if _, err := attest.Verify(env, subject(), v); err == nil {
		t.Fatal("accepted a statement whose published digest has no algorithm prefix")
	}
}
