// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

// Package omsig verifies the signature a model repository publishes over the
// files it releases.
//
// The signature is a Sigstore bundle holding a DSSE envelope, whose payload is
// an in-toto statement listing each file and the SHA-256 it hashes to. This
// package checks the signature over that statement and reports what it
// covers; deciding whether a download matches is the caller's, so a file the
// statement omits can be refused by name.
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

// payloadType is the DSSE payload type for an in-toto statement.
const payloadType = "application/vnd.in-toto+json"

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
	Subject       []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
}

// Verify checks the bundle's signature with v and returns what it covers.
func Verify(data []byte, v signature.Verifier) (*Statement, error) {
	var b bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("decoding the signature bundle: %w", err)
	}
	if b.DSSE.PayloadType != payloadType {
		return nil, fmt.Errorf("signature carries payload type %q, want %q", b.DSSE.PayloadType, payloadType)
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
	pae := []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload))

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
	out := &Statement{Subjects: make(map[string]string, len(st.Subject))}
	for _, s := range st.Subject {
		d, ok := s.Digest["sha256"]
		if !ok {
			return nil, fmt.Errorf("the statement lists %s without a sha256 digest", s.Name)
		}
		if raw, err := hex.DecodeString(d); err != nil || len(raw) != sha256.Size {
			return nil, fmt.Errorf("the statement lists %s with a malformed sha256 digest %q, want 64 hexadecimal characters", s.Name, d)
		}
		out.Subjects[s.Name] = strings.ToLower(d)
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
