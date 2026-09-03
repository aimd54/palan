// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package keyless

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	digest "github.com/opencontainers/go-digest"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore/pkg/signature"
	"google.golang.org/protobuf/encoding/protojson"
)

// MediaTypePrefix is what a Sigstore bundle's media type begins with. It is
// how a bundle is recognised among the things attached to an artifact,
// across the versions of the format.
const MediaTypePrefix = "application/vnd.dev.sigstore.bundle"

// payloadType is the only DSSE payload palan reads: an in-toto statement,
// which is what a keyless signature over an OCI artifact wraps.
const payloadType = "application/vnd.in-toto+json"

// Result is what a verified bundle turned out to say.
type Result struct {
	// Subject and Issuer are the identity the certificate carried, not the
	// pattern from the policy that admitted it, so a log line names who
	// actually signed rather than who was allowed to.
	Subject string
	Issuer  string
	// LogIndex and IntegratedTime locate the entry in the transparency log,
	// which is what somebody investigating an artifact goes and looks up.
	LogIndex       int64
	IntegratedTime time.Time
}

// String renders the result as one line for a person reading command
// output.
func (r Result) String() string {
	return fmt.Sprintf("%s (via %s), logged at %s as entry %d",
		r.Subject, r.Issuer, r.IntegratedTime.Format(time.RFC3339), r.LogIndex)
}

// Verify checks a Sigstore bundle with no network access and reports who
// signed the artifact.
//
// Everything the bundle carries is treated as a claim. root is the only
// thing believed outright, and it is what an operator pinned: the
// certificate must chain to an authority root names, and the inclusion
// proof must rebuild a log root that a key root names has signed. allowed
// then decides whether that signer is one this artifact accepts; an empty
// list is refused, because a bundle that verifies says an identity signed
// the artifact and not that the identity was supposed to.
func Verify(bundleJSON []byte, artifact digest.Digest, root *TrustedRoot, allowed []Identity) (*Result, error) {
	if root == nil {
		return nil, fmt.Errorf("no trusted root is pinned, so there is nothing to check this signature against")
	}
	if len(allowed) == 0 {
		return nil, fmt.Errorf("no identity is allowed to sign this artifact")
	}
	for i, id := range allowed {
		if err := id.Validate(); err != nil {
			return nil, fmt.Errorf("allowed identity %d: %w", i+1, err)
		}
	}

	var pb protobundle.Bundle
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(bundleJSON, &pb); err != nil {
		return nil, fmt.Errorf("parsing the signature bundle: %w", err)
	}
	leaf, err := bundleCertificate(&pb)
	if err != nil {
		return nil, err
	}
	envelope := pb.GetDsseEnvelope()
	if envelope == nil {
		return nil, fmt.Errorf(
			"the bundle carries no DSSE envelope, and a keyless signature over an artifact is one")
	}
	if got := envelope.GetPayloadType(); got != payloadType {
		return nil, fmt.Errorf("the signed payload is %q, and palan reads %q", got, payloadType)
	}
	if len(envelope.GetSignatures()) != 1 {
		return nil, fmt.Errorf(
			"the envelope carries %d signatures, and palan reads the single-signature envelopes a keyless signing tool writes",
			len(envelope.GetSignatures()))
	}
	sig := envelope.GetSignatures()[0].GetSig()
	pl := envelope.GetPayload()

	// Done first because it is the cheapest claim to settle and everything
	// after it is about a signature that has already been shown to be this
	// certificate's work over these bytes.
	verifier, err := signature.LoadVerifier(leaf.PublicKey, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("reading the signing certificate's public key: %w", err)
	}
	if err := verifier.VerifySignature(
		bytes.NewReader(sig), bytes.NewReader(pae(payloadType, pl))); err != nil {
		return nil, fmt.Errorf("the signature does not verify against its own certificate: %w", err)
	}

	entries := pb.GetVerificationMaterial().GetTlogEntries()
	if len(entries) == 0 {
		return nil, fmt.Errorf(
			"the bundle names no transparency log entry, so nothing dates the signature and its certificate cannot be checked against the moment it was used")
	}
	integrated, err := verifyLogEntry(entries[0], root, sig, pl, leaf.Raw)
	if err != nil {
		return nil, err
	}
	if err := verifyChain(leaf, root, integrated); err != nil {
		return nil, err
	}

	subject, issuer, err := certIdentity(leaf)
	if err != nil {
		return nil, err
	}
	if !anyMatches(allowed, subject, issuer) {
		return nil, fmt.Errorf(
			"%s (via %s) signed this artifact, and no rule allows that identity; the allowed identities are %s",
			subject, issuer, describe(allowed))
	}

	if err := statementCovers(pl, artifact); err != nil {
		return nil, err
	}
	return &Result{
		Subject:        subject,
		Issuer:         issuer,
		LogIndex:       entries[0].GetLogIndex(),
		IntegratedTime: integrated,
	}, nil
}

// bundleCertificate reads the signing certificate. Both shapes the format
// allows are read: one certificate on its own, or a chain whose first
// entry is the signer. Anything else, including a bundle that names a bare
// public key, has no identity to hold to a policy.
func bundleCertificate(pb *protobundle.Bundle) (*x509.Certificate, error) {
	material := pb.GetVerificationMaterial()
	if material == nil {
		return nil, fmt.Errorf("the bundle carries no verification material")
	}
	var der []byte
	switch content := material.GetContent().(type) {
	case *protobundle.VerificationMaterial_Certificate:
		der = content.Certificate.GetRawBytes()
	case *protobundle.VerificationMaterial_X509CertificateChain:
		certs := content.X509CertificateChain.GetCertificates()
		if len(certs) == 0 {
			return nil, fmt.Errorf("the bundle's certificate chain is empty")
		}
		der = certs[0].GetRawBytes()
	default:
		return nil, fmt.Errorf(
			"the bundle identifies its signer by public key rather than by certificate, so there is no identity to hold to a policy")
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parsing the signing certificate: %w", err)
	}
	return leaf, nil
}

// statement is the part of an in-toto statement palan reads: what the
// signature is about.
type statement struct {
	Subject []struct {
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
}

// statementCovers checks that the signed payload is about this artifact.
//
// Without it a bundle that verifies in every other way would still be
// somebody else's signature over somebody else's artifact, attached to
// this one.
func statementCovers(payload []byte, artifact digest.Digest) error {
	var st statement
	if err := json.Unmarshal(payload, &st); err != nil {
		return fmt.Errorf("decoding the signed statement: %w", err)
	}
	if err := artifact.Validate(); err != nil {
		return fmt.Errorf("the artifact digest %q is not usable: %w", artifact, err)
	}
	for _, s := range st.Subject {
		if s.Digest[artifact.Algorithm().String()] == artifact.Encoded() {
			return nil
		}
	}
	return fmt.Errorf(
		"the signature is over %d other subject(s) and not over %s", len(st.Subject), artifact)
}

// pae is DSSE's pre-authentication encoding: the bytes a DSSE signature
// actually covers. Framing the type and the payload with their lengths is
// what keeps a payload from being reinterpreted under a different type.
func pae(payloadType string, payload []byte) []byte {
	var b bytes.Buffer
	b.WriteString("DSSEv1 ")
	b.WriteString(strconv.Itoa(len(payloadType)))
	b.WriteByte(' ')
	b.WriteString(payloadType)
	b.WriteByte(' ')
	b.WriteString(strconv.Itoa(len(payload)))
	b.WriteByte(' ')
	b.Write(payload)
	return b.Bytes()
}

// anyMatches reports whether any allowed identity covers this signer.
func anyMatches(allowed []Identity, subject, issuer string) bool {
	for _, id := range allowed {
		if id.matches(subject, issuer) {
			return true
		}
	}
	return false
}

// describe renders the allowed identities for a refusal, so an operator can
// see what the policy holds without going to look it up.
func describe(allowed []Identity) string {
	out := make([]string, 0, len(allowed))
	for _, id := range allowed {
		out = append(out, fmt.Sprintf("%s (via %s)", id.Subject, id.Issuer))
	}
	return strings.Join(out, ", ")
}
