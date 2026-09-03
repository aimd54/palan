// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package keyless

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// Fulcio records the OpenID provider that vouched for a signer in a private
// extension, because a certificate has no standard field for it. The first
// OID carries the value as a bare string and the second, which replaced it,
// carries it DER-encoded. Certificates in circulation use either, so both
// are read.
var (
	oidIssuer   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
	oidIssuerV2 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}
)

// Identity is one signer a policy allows: who they are, and which OpenID
// provider is trusted to say so.
//
// Both halves are required. A subject alone is a name anybody's provider
// can mint, so accepting one without saying which provider must have
// asserted it lets a signer authenticated anywhere at all pass as the
// signer authenticated where it matters.
type Identity struct {
	// Subject is matched against the certificate's subject alternative
	// name, with "*" standing for any run of characters. Workflow
	// identities carry the git ref that built them, so they change with
	// every release and an exact name would have to be edited each time.
	Subject string
	// Issuer is the OpenID provider's URL, matched exactly. Providers are
	// stable, and a pattern here would widen the very thing that keeps a
	// subject from being claimable by anyone.
	Issuer string
}

// Validate refuses an identity that would let through more than whoever
// wrote it can have meant.
func (id Identity) Validate() error {
	if id.Subject == "" {
		return fmt.Errorf("names no subject")
	}
	if id.Issuer == "" {
		return fmt.Errorf("names no issuer for subject %q", id.Subject)
	}
	if strings.Trim(id.Subject, "*") == "" {
		return fmt.Errorf(
			"subject %q matches every identity the issuer ever certified, which no policy means to allow",
			id.Subject)
	}
	if strings.Contains(id.Issuer, "*") {
		return fmt.Errorf(
			"issuer %q contains a wildcard, and an issuer is matched exactly", id.Issuer)
	}
	return nil
}

// matches reports whether a certificate's subject and issuer satisfy this
// identity.
func (id Identity) matches(subject, issuer string) bool {
	return id.Issuer == issuer && globMatch(id.Subject, subject)
}

// globMatch matches a pattern in which "*" stands for any run of
// characters, slashes included. Subjects are URLs and email addresses
// rather than paths, so nothing here treats a slash as a boundary.
func globMatch(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == s
	}
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	for _, part := range parts[1 : len(parts)-1] {
		i := strings.Index(s, part)
		if i < 0 {
			return false
		}
		s = s[i+len(part):]
	}
	return strings.HasSuffix(s, parts[len(parts)-1])
}

// verifyChain establishes that leaf was issued by a pinned authority, as of
// at.
//
// The time is the moment the signature was recorded in the transparency
// log, not now. A keyless signing certificate lives for minutes: checking
// it against the present would refuse every signature older than that,
// which is to say all of them.
func verifyChain(leaf *x509.Certificate, root *TrustedRoot, at time.Time) error {
	var reasons []string
	for _, a := range root.authorities {
		if !a.valid.covers(at) {
			reasons = append(reasons, "an authority not trusted at that time")
			continue
		}
		_, err := leaf.Verify(x509.VerifyOptions{
			Roots:         a.roots,
			Intermediates: a.intermediates,
			CurrentTime:   at,
			// Fulcio issues for code signing, and accepting a certificate
			// meant for anything else would let a TLS certificate from the
			// same authority stand in for a signing one.
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		})
		if err == nil {
			return nil
		}
		reasons = append(reasons, err.Error())
	}
	return fmt.Errorf(
		"the signing certificate does not chain to any pinned certificate authority as of %s: %s",
		at.Format(time.RFC3339), strings.Join(reasons, "; "))
}

// certIdentity reads who a signing certificate says its holder is.
//
// The subject comes from the subject alternative name, which Fulcio fills
// with an email address for a person and a URI for a workload. A
// certificate carrying neither is refused rather than given an empty
// subject, which would otherwise be compared against a policy and could
// match a pattern that was meant to be narrow.
func certIdentity(leaf *x509.Certificate) (subject, issuer string, err error) {
	switch {
	case len(leaf.EmailAddresses) > 0:
		subject = leaf.EmailAddresses[0]
	case len(leaf.URIs) > 0:
		subject = leaf.URIs[0].String()
	default:
		return "", "", fmt.Errorf(
			"the signing certificate carries no email address or URI to identify its holder")
	}

	for _, ext := range leaf.Extensions {
		switch {
		case ext.Id.Equal(oidIssuerV2):
			var v string
			if _, err := asn1.Unmarshal(ext.Value, &v); err != nil {
				return "", "", fmt.Errorf("decoding the certificate's issuer extension: %w", err)
			}
			// The current extension wins outright when both are present,
			// so a certificate carrying two different issuers cannot have
			// the more permissive one selected by ordering.
			return subject, v, nil
		case ext.Id.Equal(oidIssuer):
			issuer = string(ext.Value)
		}
	}
	if issuer == "" {
		return "", "", fmt.Errorf(
			"the signing certificate does not record which OpenID provider authenticated %s", subject)
	}
	return subject, issuer, nil
}

// parseCertificates reads a PEM block or chain into certificates, in the
// order they appear.
func parseCertificates(data []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no certificate found")
	}
	return out, nil
}

// parseDER reads a single DER-encoded certificate.
func parseDER(der []byte) (*x509.Certificate, error) {
	return x509.ParseCertificate(der)
}
