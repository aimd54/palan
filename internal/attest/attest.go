// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

// Package attest states where an artifact's layers came from, in a
// statement a key signs and any holder of the public half can check.
//
// The statement is an in-toto Statement in a DSSE envelope, which is the
// shape cosign stores an attestation in, so what this package writes is
// readable by cosign verify-attestation and what cosign writes is readable
// here.
//
// This package builds and checks statements. It never decides trust on its
// own: a signer or a verifier is supplied by the caller, which is what keeps
// key handling in one place. A statement that covers no layers, or names a
// layer whose source is not fully known, is refused rather than produced or
// accepted, because a statement that verifies while vouching for nothing is
// worse than no statement at all.
package attest

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sigstore/sigstore/pkg/signature"
)

// PredicateType marks a statement written by this package.
const PredicateType = "https://palan.dev/source/v1"

// PayloadType is the DSSE payload type for an in-toto statement.
const PayloadType = "application/vnd.in-toto+json"

// ErrNoAttestation marks an artifact that carries none, which is not an
// error in itself: an unattested artifact is the ordinary case.
var ErrNoAttestation = errors.New("no attestation")

// Layer is where one of an artifact's layers came from.
type Layer struct {
	// Digest is the layer's own digest in the artifact, as an OCI descriptor
	// holds it: "sha256:" followed by 64 lowercase hex characters.
	Digest string `json:"digest"`
	// Repo is the repository the file was fetched from, host included.
	Repo string `json:"repo"`
	// Revision is the commit that repository reported, empty when it
	// reported none.
	Revision string `json:"revision,omitempty"`
	// Path is the file's path within the repository.
	Path string `json:"path"`
	// Published is the digest the repository published for the file, in the
	// same "sha256:<hex>" form as Digest, empty for a file it served inline
	// with none.
	Published string `json:"published,omitempty"`
}

// subject is one entry of an in-toto statement's top-level "subject" array.
type subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// statement is the in-toto Statement this package reads and writes.
type statement struct {
	Type          string    `json:"_type"`
	Subject       []subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     struct {
		Layers []Layer `json:"layers"`
	} `json:"predicate"`
}

// dsseSignature is one entry of a DSSE envelope's "signatures" array.
type dsseSignature struct {
	Sig string `json:"sig"`
}

// envelope is a DSSE envelope: a payload, its type, and the signatures made
// over it.
type envelope struct {
	Payload     string          `json:"payload"`
	PayloadType string          `json:"payloadType"`
	Signatures  []dsseSignature `json:"signatures"`
}

// pae is the DSSE pre-authentication encoding. The signature covers this
// rather than the payload, so a payload cannot be reinterpreted under
// another type.
func pae(payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(PayloadType), PayloadType, len(payload), payload))
}

// validDigest reports an error unless s is "sha256:" followed by exactly 64
// lowercase hex characters, the form an OCI descriptor's digest holds. A
// bare hex digest, an uppercase one, or one under another algorithm is
// refused rather than accepted silently.
func validDigest(s string) error {
	if s == "" {
		return errors.New("digest is empty")
	}
	if !strings.HasPrefix(s, "sha256:") {
		return fmt.Errorf("digest %q is not of the form sha256:<hex>", s)
	}
	if err := digest.Digest(s).Validate(); err != nil {
		return fmt.Errorf("digest %q is malformed: %w", s, err)
	}
	return nil
}

// validateLayers refuses a layer set that would leave Build or Verify
// vouching for less than it looks like: no layers at all, a layer whose
// repository or path is not known, or a digest that is not the form an OCI
// descriptor holds.
func validateLayers(layers []Layer) error {
	if len(layers) == 0 {
		return errors.New("a statement covering no layers would vouch for nothing")
	}
	for _, l := range layers {
		if l.Repo == "" || l.Path == "" {
			return fmt.Errorf("layer %q is missing a repository or a path, so its source is not known", l.Digest)
		}
		if err := validDigest(l.Digest); err != nil {
			return fmt.Errorf("layer %s: %w", l.Path, err)
		}
		if l.Published != "" {
			if err := validDigest(l.Published); err != nil {
				return fmt.Errorf("layer %s published digest: %w", l.Path, err)
			}
		}
	}
	return nil
}

// Build returns a signed DSSE envelope stating where subject's layers came
// from.
func Build(sub ocispec.Descriptor, layers []Layer, s signature.Signer) ([]byte, error) {
	if err := validateLayers(layers); err != nil {
		return nil, err
	}
	dg := sub.Digest.String()
	if err := validDigest(dg); err != nil {
		return nil, fmt.Errorf("subject: %w", err)
	}
	alg, hexPart, _ := strings.Cut(dg, ":")

	stmt := statement{
		Type:          "https://in-toto.io/Statement/v1",
		Subject:       []subject{{Name: dg, Digest: map[string]string{alg: hexPart}}},
		PredicateType: PredicateType,
	}
	stmt.Predicate.Layers = layers

	payload, err := json.Marshal(stmt)
	if err != nil {
		return nil, fmt.Errorf("encoding the statement: %w", err)
	}
	sig, err := s.SignMessage(bytes.NewReader(pae(payload)))
	if err != nil {
		return nil, fmt.Errorf("signing the statement: %w", err)
	}

	env := envelope{
		PayloadType: PayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  []dsseSignature{{Sig: base64.StdEncoding.EncodeToString(sig)}},
	}
	out, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("encoding the envelope: %w", err)
	}
	return out, nil
}

// Verify checks data against v, confirms the statement it carries is about
// sub, and returns the layers it covers. It refuses a statement whose
// signature does not verify, whose subject is a different artifact, or that
// covers nothing.
func Verify(data []byte, sub ocispec.Descriptor, v signature.Verifier) ([]Layer, error) {
	dg := sub.Digest.String()
	if err := validDigest(dg); err != nil {
		return nil, fmt.Errorf("subject: %w", err)
	}

	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("decoding the attestation: %w", err)
	}
	if env.PayloadType != PayloadType {
		return nil, fmt.Errorf("attestation carries payload type %q, want %q", env.PayloadType, PayloadType)
	}
	if len(env.Signatures) == 0 {
		return nil, errors.New("the attestation carries no signature")
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("decoding the signed statement: %w", err)
	}

	message := pae(payload)
	var verified bool
	var lastErr error
	for _, s := range env.Signatures {
		raw, err := base64.StdEncoding.DecodeString(s.Sig)
		if err != nil {
			lastErr = err
			continue
		}
		if err := v.VerifySignature(bytes.NewReader(raw), bytes.NewReader(message)); err != nil {
			lastErr = err
			continue
		}
		verified = true
		break
	}
	if !verified {
		return nil, fmt.Errorf("the attestation does not verify against the supplied key: %w", lastErr)
	}

	var stmt statement
	if err := json.Unmarshal(payload, &stmt); err != nil {
		return nil, fmt.Errorf("decoding the signed statement: %w", err)
	}
	if stmt.PredicateType != PredicateType {
		return nil, fmt.Errorf("statement predicate is %q, want %q", stmt.PredicateType, PredicateType)
	}
	if len(stmt.Subject) != 1 {
		return nil, fmt.Errorf("statement names %d subjects, want exactly the artifact", len(stmt.Subject))
	}
	// dg already passed validDigest above, so it is guaranteed to contain a
	// colon: the split below cannot silently produce an empty wantHex the
	// way an unvalidated "sha256:" subject would.
	wantAlg, wantHex, _ := strings.Cut(dg, ":")
	if got, ok := stmt.Subject[0].Digest[wantAlg]; !ok || !strings.EqualFold(got, wantHex) {
		return nil, fmt.Errorf("the attestation is about a different artifact than %s", sub.Digest)
	}
	if err := validateLayers(stmt.Predicate.Layers); err != nil {
		return nil, err
	}
	return stmt.Predicate.Layers, nil
}
