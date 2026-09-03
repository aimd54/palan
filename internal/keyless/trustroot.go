// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

// Package keyless verifies a Sigstore bundle with no network access.
//
// A keyless signature names an identity where a key names a file, and
// checking one normally reaches a certificate authority for the signing
// certificate and a transparency log for proof the signature was recorded.
// Neither is reachable from a disconnected host, so everything needed
// travels with the artifact: the signing certificate, the log entry, and
// the inclusion proof that places that entry in the log. What cannot
// travel with it is the decision about whom to trust, so that is pinned
// separately, as a Sigstore trusted root the operator holds on disk.
//
// The material in a bundle is supplied by whoever produced it and none of
// it is trusted on its own. The pinned root is the only starting point:
// the certificate must chain to a certificate authority it names, and the
// inclusion proof must reconstruct a log root that a log key it names has
// signed.
//
// Signing is out of scope. Producing a keyless signature needs the very
// services this package exists to avoid, so palan verifies what other
// tools sign.
package keyless

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"time"

	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	prototrust "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// TrustedRoot is the material an operator pinned: the certificate
// authorities allowed to issue signing certificates, and the transparency
// logs whose signatures over a log root are believed.
//
// It is the answer to "whom do we trust", which is the one question a
// bundle cannot answer about itself.
type TrustedRoot struct {
	authorities []certAuthority
	logs        map[string]logKey
}

// certAuthority is one issuer, with the window during which it was trusted
// to issue. A rotated or withdrawn authority stays in the file with a
// closed window so that signatures it issued while it was current still
// verify and ones dated outside it do not.
type certAuthority struct {
	roots         *x509.CertPool
	intermediates *x509.CertPool
	valid         window
}

// logKey is one transparency log's public key and the window during which
// it was trusted, keyed elsewhere by the log's own identifier.
type logKey struct {
	public crypto.PublicKey
	valid  window
}

// window is a validity range with optional ends. A missing start or end
// means unbounded in that direction, which is how a currently-live service
// is recorded.
type window struct {
	start, end *time.Time
}

// covers reports whether t falls inside the window.
func (w window) covers(t time.Time) bool {
	if w.start != nil && t.Before(*w.start) {
		return false
	}
	if w.end != nil && t.After(*w.end) {
		return false
	}
	return true
}

// LoadTrustedRoot parses a Sigstore trusted root, the JSON that
// `cosign trusted-root create` writes and that Sigstore's own TUF
// repository distributes. Using that format rather than one of palan's own
// means the pinned root is a file operators already know how to obtain and
// can hand to other tools unchanged.
func LoadTrustedRoot(data []byte) (*TrustedRoot, error) {
	var pb prototrust.TrustedRoot
	// Unknown fields are tolerated: a trusted root is a living document
	// that gains services over time, and a file naming one palan does not
	// use must not become unreadable for that reason alone.
	opts := protojson.UnmarshalOptions{DiscardUnknown: true}
	if err := opts.Unmarshal(data, &pb); err != nil {
		return nil, fmt.Errorf("parsing the trusted root: %w", err)
	}

	root := &TrustedRoot{logs: make(map[string]logKey)}
	for i, ca := range pb.GetCertificateAuthorities() {
		a, err := newCertAuthority(ca)
		if err != nil {
			return nil, fmt.Errorf("trusted root certificate authority %d: %w", i+1, err)
		}
		root.authorities = append(root.authorities, a)
	}
	for i, tlog := range pb.GetTlogs() {
		id, key, err := newLogKey(tlog)
		if err != nil {
			return nil, fmt.Errorf("trusted root transparency log %d: %w", i+1, err)
		}
		root.logs[id] = key
	}

	// Refused rather than carried: a root with no authority verifies no
	// certificate and a root with no log verifies no inclusion proof, so
	// either way every signature checked against it would be refused for a
	// reason that points at the signature instead of at the file.
	if len(root.authorities) == 0 {
		return nil, fmt.Errorf("the trusted root names no certificate authority")
	}
	if len(root.logs) == 0 {
		return nil, fmt.Errorf("the trusted root names no transparency log")
	}
	return root, nil
}

// newCertAuthority splits one authority's chain into the root it ends with
// and the intermediates leading to it. The chain is ordered leaf-most
// first, so the last certificate is the trust anchor.
func newCertAuthority(ca *prototrust.CertificateAuthority) (certAuthority, error) {
	raw := ca.GetCertChain().GetCertificates()
	if len(raw) == 0 {
		return certAuthority{}, fmt.Errorf("names no certificate")
	}
	certs := make([]*x509.Certificate, 0, len(raw))
	for i, c := range raw {
		parsed, err := x509.ParseCertificate(c.GetRawBytes())
		if err != nil {
			return certAuthority{}, fmt.Errorf("certificate %d: %w", i+1, err)
		}
		certs = append(certs, parsed)
	}
	out := certAuthority{
		roots:         x509.NewCertPool(),
		intermediates: x509.NewCertPool(),
		valid:         windowOf(ca.GetValidFor()),
	}
	out.roots.AddCert(certs[len(certs)-1])
	for _, c := range certs[:len(certs)-1] {
		out.intermediates.AddCert(c)
	}
	return out, nil
}

// newLogKey reads one log's public key and the identifier a bundle uses to
// name it. The identifier is the SHA-256 of the key's DER encoding, so it
// is derived here rather than believed: a file whose stated log identifier
// does not match its own key would otherwise let a bundle select a key by
// a name nothing checks.
func newLogKey(tlog *prototrust.TransparencyLogInstance) (string, logKey, error) {
	der := tlog.GetPublicKey().GetRawBytes()
	if len(der) == 0 {
		return "", logKey{}, fmt.Errorf("names no public key")
	}
	public, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return "", logKey{}, fmt.Errorf("parsing the public key: %w", err)
	}
	id := logIDOf(der)
	if stated := tlog.GetLogId().GetKeyId(); len(stated) > 0 && hex.EncodeToString(stated) != id {
		return "", logKey{}, fmt.Errorf(
			"states log id %s but its key hashes to %s",
			hex.EncodeToString(stated), id)
	}
	return id, logKey{
		public: public,
		valid:  windowOf(tlog.GetPublicKey().GetValidFor()),
	}, nil
}

// windowOf converts a protobuf time range, treating an absent bound as
// unbounded.
func windowOf(r *protocommon.TimeRange) window {
	var w window
	if r == nil {
		return w
	}
	if s := r.GetStart(); s != nil {
		t := s.AsTime()
		w.start = &t
	}
	if e := r.GetEnd(); e != nil {
		t := e.AsTime()
		w.end = &t
	}
	return w
}

// logIDOf is how a transparency log names itself in a bundle: the SHA-256
// of its DER-encoded public key, in hex.
func logIDOf(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}
