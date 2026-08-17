// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

// Package omsig verifies the signature a model repository publishes over the
// files it releases.
//
// The signature is a Sigstore bundle holding a DSSE envelope, whose payload is
// an in-toto statement. The statement's own top-level subject names the model
// as a whole (its directory name, and a digest computed over every file's
// digest), which this package does not use; the per-file listing this package
// reads instead lives one level down, under the predicate, as a "resources"
// array of name/algorithm/digest triples. This package checks the signature
// over the statement and reports what those resources cover; deciding
// whether a download matches is the caller's, so a file the statement omits
// can be refused by name.
//
// Verification is key based. A keyless signature carries its trust material
// in the same bundle and needs a trusted root to check it against, which is a
// separate decision from reading the format.
package omsig

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/sigstore/sigstore/pkg/signature"
)

// FileName is where the signing tool writes its signature by default.
const FileName = "model.sig"

// PredicateType marks an in-toto statement written by the model-signing tool.
const PredicateType = "https://model_signing/signature/v1.0"

// PayloadType is the DSSE payload type for an in-toto statement.
const PayloadType = "application/vnd.in-toto+json"

// ErrNotCovered marks a file the signature says nothing about.
var ErrNotCovered = errors.New("not covered by the signature")

// Statement is a verified signature's contents.
type Statement struct {
	// Subjects maps a path within the repository to a hex SHA-256.
	Subjects map[string]string
	// KeyID identifies the key that signed, as the SHA-256 of its public
	// key, so an artifact can record who vouched for it.
	KeyID string
}

type bundle struct {
	DSSE struct {
		Payload     string `json:"payload"`
		PayloadType string `json:"payloadType"`
		Signatures  []struct {
			Sig string `json:"sig"`
		} `json:"signatures"`
	} `json:"dsseEnvelope"`
}

type statement struct {
	Type          string `json:"_type"`
	PredicateType string `json:"predicateType"`
	Predicate     struct {
		// Resources is the tool's per-file listing: one entry per signed
		// file, named relative to the model directory it was signed from.
		// The statement's own "subject" array holds one entry instead, for
		// the model as a whole, which is not what a caller checking a
		// single downloaded file needs.
		Resources []struct {
			Name      string `json:"name"`
			Algorithm string `json:"algorithm"`
			Digest    string `json:"digest"`
		} `json:"resources"`
	} `json:"predicate"`
}

// Verify checks the bundle's signature with v and returns what it covers.
func Verify(data []byte, v signature.Verifier) (*Statement, error) {
	var b bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("decoding the signature bundle: %w", err)
	}
	if b.DSSE.PayloadType != PayloadType {
		return nil, fmt.Errorf("signature carries payload type %q, want %q", b.DSSE.PayloadType, PayloadType)
	}
	if len(b.DSSE.Signatures) == 0 {
		return nil, errors.New("the signature bundle carries no signature")
	}
	payload, err := base64.StdEncoding.DecodeString(b.DSSE.Payload)
	if err != nil {
		return nil, fmt.Errorf("decoding the signed statement: %w", err)
	}

	// DSSE signs the pre-authentication encoding, not the payload, so that
	// a payload cannot be reinterpreted under another type.
	pae := []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(PayloadType), PayloadType, len(payload), payload))

	var lastErr error
	verified := false
	for _, s := range b.DSSE.Signatures {
		sig, err := base64.StdEncoding.DecodeString(s.Sig)
		if err != nil {
			lastErr = err
			continue
		}
		if err := v.VerifySignature(bytes.NewReader(sig), bytes.NewReader(pae)); err != nil {
			lastErr = err
			continue
		}
		verified = true
		break
	}
	if !verified {
		return nil, fmt.Errorf("the signature does not verify against the supplied key: %w", lastErr)
	}

	var st statement
	if err := json.Unmarshal(payload, &st); err != nil {
		return nil, fmt.Errorf("decoding the signed statement: %w", err)
	}
	if st.PredicateType != PredicateType {
		return nil, fmt.Errorf("statement predicate is %q, want %q", st.PredicateType, PredicateType)
	}
	out := &Statement{Subjects: make(map[string]string, len(st.Predicate.Resources))}
	for _, r := range st.Predicate.Resources {
		if r.Algorithm != "sha256" {
			return nil, fmt.Errorf("the statement lists %s under algorithm %q, want sha256", r.Name, r.Algorithm)
		}
		if raw, err := hex.DecodeString(r.Digest); err != nil || len(raw) != sha256.Size {
			return nil, fmt.Errorf("the statement lists %s with a malformed sha256 digest %q, want 64 hexadecimal characters", r.Name, r.Digest)
		}
		out.Subjects[r.Name] = strings.ToLower(r.Digest)
	}
	if len(out.Subjects) == 0 {
		return nil, errors.New("the statement covers no files")
	}
	id, err := keyID(v)
	if err != nil {
		return nil, err
	}
	out.KeyID = id
	return out, nil
}

// Covers reports whether the statement lists path with the given digest.
// sha256hex is compared case-insensitively: Subjects already stores a
// lowercase hex digest, so the comparison lowercases only sha256hex, once,
// and compares with ==, rather than folding Unicode case on every call.
func (s *Statement) Covers(path, sha256hex string) error {
	if sha256hex == "" {
		return fmt.Errorf("%s: no sha256 given to compare against the signature", path)
	}
	want, ok := s.Subjects[path]
	if !ok {
		return fmt.Errorf("%s is %w", path, ErrNotCovered)
	}
	if got := strings.ToLower(sha256hex); got != want {
		return fmt.Errorf("%s hashes to %s and the signature covers %s", path, sha256hex, want)
	}
	return nil
}

// keyID names the verifying key by the digest of its public key, which is
// stable across encodings of the same key.
func keyID(v signature.Verifier) (string, error) {
	pub, err := v.PublicKey()
	if err != nil {
		return "", fmt.Errorf("reading the verifying key: %w", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("encoding the verifying key: %w", err)
	}
	sum := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
