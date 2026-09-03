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
	if _, err := classifySubject(id.Subject); err != nil {
		return fmt.Errorf("subject %q %w", id.Subject, err)
	}
	if strings.Contains(id.Issuer, "*") {
		return fmt.Errorf(
			"issuer %q contains a wildcard, and an issuer is matched exactly", id.Issuer)
	}
	return nil
}

// subjectKind is the shape of an identity: an address, a URL, or a
// pattern with no wildcard at all.
//
// The kind is carried rather than inferred at each use because a pattern
// and the identity it is compared against must be the same kind. Matching
// treats a subject as plain text, so an address pattern will happily match
// a URL that ends the right way, and the reasoning that makes each kind
// safe does not survive being applied to the other.
type subjectKind int

const (
	// subjectExact has no wildcard, so it matches only itself.
	subjectExact subjectKind = iota
	subjectMail
	subjectURL
)

// classifySubject decides what shape a pattern is and refuses one that
// leaves open the part of an identity its holder does not choose.
//
// The property being enforced is that a pattern cannot match an identity
// under a different authority. Everything below is in service of that one
// sentence, and each rule exists because some pattern that reads as though
// it pins something does not.
func classifySubject(pattern string) (subjectKind, error) {
	if pattern == "" {
		return 0, fmt.Errorf("is empty")
	}
	if !strings.Contains(pattern, "*") {
		return subjectExact, nil
	}

	if i := strings.Index(pattern, "://"); i >= 0 {
		// A wildcard before the scheme unanchors the whole pattern.
		// Matching is a prefix, a series of contained runs and a suffix,
		// so "*://forge.example/org/*" asks only that "://forge.example/org/"
		// appear somewhere, which a path on any host can supply.
		if strings.Contains(pattern[:i], "*") {
			return 0, fmt.Errorf(
				"wildcards the scheme, which leaves the host unanchored: it would match any URL merely containing %q",
				pattern[i:])
		}
		host := pattern[i+len("://"):]
		if j := strings.Index(host, "/"); j >= 0 {
			host = host[:j]
		}
		// A host is never relaxed, because matching does not treat "/" as
		// a boundary: "https://*.example.com/org/*" would also reach
		// "https://elsewhere.test/x.example.com/org/y".
		if host == "" || strings.Contains(host, "*") {
			return 0, fmt.Errorf(
				"wildcards the host, so it matches identities at any host; name the host literally, as in \"https://forge.example/org/repo/*\"")
		}
		return subjectURL, nil
	}

	if j := strings.LastIndex(pattern, "@"); j >= 0 {
		// A URL carries an "@" too: a workflow identity ends in one, as in
		// "...release.yml@refs/tags/v1.0.0". Read as an address that makes
		// the git ref the domain, and a literal ref then reads as a
		// pinned domain while the host is wildcarded away. Requiring both
		// halves to be free of "/" is what keeps a path from being taken
		// for an address.
		if strings.Contains(pattern[:j], "/") {
			return 0, fmt.Errorf(
				"looks like a path rather than an address: everything before the last %q is the part a signer chooses, so this pins nothing; name the host, as in \"https://forge.example/org/repo/*\"",
				"@")
		}
		if err := pinsAMailDomain(pattern[j+1:]); err != nil {
			return 0, err
		}
		return subjectMail, nil
	}

	return 0, fmt.Errorf(
		"is neither an address nor a URL, so there is no authority in it to pin; write it as \"*@example.com\" or \"https://forge.example/...\"")
}

// pinsAMailDomain checks the domain of an address pattern. A wildcard
// inside it is allowed when a literal domain follows, because an address
// has no path: matching anchors the pattern's tail to the end of the
// identity, so "*@*.example.com" can only match an address in that domain.
func pinsAMailDomain(domain string) error {
	if domain == "" {
		return fmt.Errorf("names no domain")
	}
	if strings.Contains(domain, "/") {
		return fmt.Errorf(
			"has %q in its domain, so it is a path rather than an address and pins nothing", "/")
	}
	if i := strings.LastIndex(domain, "*"); i >= 0 {
		tail := domain[i+1:]
		if !strings.HasPrefix(tail, ".") || len(tail) < 2 {
			return fmt.Errorf(
				"wildcards the domain, so it matches an address at any domain; end it on a literal domain, as in \"*@example.com\"")
		}
	}
	return nil
}

// matches reports whether a certificate's subject and issuer satisfy this
// identity.
//
// The pattern's shape has to agree with the certificate's. Matching is
// plain text, so an address pattern would otherwise match a URL that
// happens to end the right way: a git ref may contain "@" and ".", so
// "*@example.com" reaches a workflow identity built from a tag named
// "v1@example.com". Each kind's safety argument rests on the shape of the
// identity it is compared against, and neither argument survives the swap.
func (id Identity) matches(subject, issuer string, kind subjectKind) bool {
	if id.Issuer != issuer {
		return false
	}
	if k, err := classifySubject(id.Subject); err != nil || (k != subjectExact && k != kind) {
		return false
	}
	return globMatch(id.Subject, subject)
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
func certIdentity(leaf *x509.Certificate) (subject, issuer string, kind subjectKind, err error) {
	// A certificate naming its holder more than once is refused rather than
	// resolved by picking one. Reading the first would let a signer put an
	// allowed identity where the check looks and their real one elsewhere,
	// and there is no reading of "who signed this" that returns two answers.
	if n := len(leaf.EmailAddresses) + len(leaf.URIs); n != 1 {
		if n == 0 {
			return "", "", 0, fmt.Errorf(
				"the signing certificate carries no email address or URI to identify its holder")
		}
		return "", "", 0, fmt.Errorf(
			"the signing certificate names its holder %d times, and an identity has one name", n)
	}
	if len(leaf.EmailAddresses) == 1 {
		subject, kind = leaf.EmailAddresses[0], subjectMail
	} else {
		subject, kind = leaf.URIs[0].String(), subjectURL
	}

	for _, ext := range leaf.Extensions {
		switch {
		case ext.Id.Equal(oidIssuerV2):
			var v string
			if _, err := asn1.Unmarshal(ext.Value, &v); err != nil {
				return "", "", 0, fmt.Errorf("decoding the certificate's issuer extension: %w", err)
			}
			// The current extension wins outright when both are present,
			// so a certificate carrying two different issuers cannot have
			// the more permissive one selected by ordering.
			return subject, v, kind, nil
		case ext.Id.Equal(oidIssuer):
			issuer = string(ext.Value)
		}
	}
	if issuer == "" {
		return "", "", 0, fmt.Errorf(
			"the signing certificate does not record which OpenID provider authenticated %s", subject)
	}
	return subject, issuer, kind, nil
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
