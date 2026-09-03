// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package keylesstest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"strconv"
	"testing"
	"time"

	digest "github.com/opencontainers/go-digest"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	prototrust "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// oidIssuerV2 is the extension a certificate authority uses to record which
// OpenID provider authenticated the holder.
var oidIssuerV2 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}

// Origin is the name the fixture log gives itself in its checkpoints.
const Origin = "log.test"

// SignedAt is when every fixture signature is made and recorded. It is
// fixed rather than taken from the clock so that a certificate's ten-minute
// life, and the check of it against log time, mean the same thing on every
// run and in ten years.
var SignedAt = time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)

// Log is a certificate authority and a transparency log that agree with
// each other, and the trusted root that pins them both.
type Log struct {
	caKey   *ecdsa.PrivateKey
	caCert  *x509.Certificate
	logKey  *ecdsa.PrivateKey
	logDER  []byte
	entries tree

	// TrustedRoot is the pinned material, in the format
	// `cosign trusted-root create` writes.
	TrustedRoot []byte
}

// NewLog builds a fresh authority and log. Everything it later signs chains
// to this authority and is recorded in this log, and nothing else does.
func NewLog(t *testing.T) *Log {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating the authority key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "keylesstest authority"},
		NotBefore:             SignedAt.Add(-24 * time.Hour),
		NotAfter:              SignedAt.Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("creating the authority certificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing the authority certificate: %v", err)
	}

	logKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating the log key: %v", err)
	}
	logDER, err := x509.MarshalPKIXPublicKey(&logKey.PublicKey)
	if err != nil {
		t.Fatalf("encoding the log key: %v", err)
	}

	l := &Log{caKey: caKey, caCert: caCert, logKey: logKey, logDER: logDER}
	l.TrustedRoot = l.trustedRoot(t)
	return l
}

// trustedRoot renders what an operator would have pinned for this log.
func (l *Log) trustedRoot(t *testing.T) []byte {
	t.Helper()
	id := sha256.Sum256(l.logDER)
	root := &prototrust.TrustedRoot{
		MediaType: "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
		CertificateAuthorities: []*prototrust.CertificateAuthority{{
			CertChain: &protocommon.X509CertificateChain{
				Certificates: []*protocommon.X509Certificate{{RawBytes: l.caCert.Raw}},
			},
			ValidFor: &protocommon.TimeRange{
				Start: timestamppb.New(SignedAt.Add(-24 * time.Hour)),
			},
		}},
		Tlogs: []*prototrust.TransparencyLogInstance{{
			BaseUrl:       "https://" + Origin,
			HashAlgorithm: protocommon.HashAlgorithm_SHA2_256,
			PublicKey: &protocommon.PublicKey{
				RawBytes:   l.logDER,
				KeyDetails: protocommon.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
				ValidFor: &protocommon.TimeRange{
					Start: timestamppb.New(SignedAt.Add(-24 * time.Hour)),
				},
			},
			LogId: &protocommon.LogId{KeyId: id[:]},
		}},
	}
	out, err := protojson.Marshal(root)
	if err != nil {
		t.Fatalf("encoding the trusted root: %v", err)
	}
	return out
}

// Signer is one identity the authority will certify.
type Signer struct {
	Subject string
	Issuer  string
}

// Certify issues a short-lived signing certificate for a signer, the way a
// keyless certificate authority does: valid for ten minutes around the
// moment of signing, and recording the provider that authenticated the
// holder.
func (l *Log) Certify(t *testing.T, s Signer) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating the signing key: %v", err)
	}
	issuer, err := asn1.MarshalWithParams(s.Issuer, "utf8")
	if err != nil {
		t.Fatalf("encoding the issuer extension: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		NotBefore:    SignedAt.Add(-5 * time.Minute),
		NotAfter:     SignedAt.Add(5 * time.Minute),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		ExtraExtensions: []pkix.Extension{{
			Id:    oidIssuerV2,
			Value: issuer,
		}},
	}
	if u, err := url.Parse(s.Subject); err == nil && u.Scheme != "" {
		tmpl.URIs = []*url.URL{u}
	} else {
		tmpl.EmailAddresses = []string{s.Subject}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, l.caCert, &key.PublicKey, l.caKey)
	if err != nil {
		t.Fatalf("issuing the signing certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing the signing certificate: %v", err)
	}
	return key, cert
}

// signed is one signature and everything the log records about it.
type signed struct {
	cert    *x509.Certificate
	payload []byte
	sig     []byte
	body    []byte
}

// sign produces a DSSE-enveloped in-toto statement over an artifact, and
// the log entry a transparency log would record for it.
func (l *Log) sign(t *testing.T, artifact digest.Digest, s Signer) signed {
	t.Helper()
	return l.signWith(t, l, artifact, s)
}

// signWith is sign, with the certificate issued by a named authority. It
// exists so a test can present a signature made under one authority and
// recorded in another's log, which is the only way to ask whether the chain
// is checked at all rather than whether the log is the pinned one.
func (l *Log) signWith(t *testing.T, ca *Log, artifact digest.Digest, s Signer) signed {
	t.Helper()
	return l.signPayload(t, ca, statementOver(t, artifact), s)
}

// statementOver builds the in-toto statement a keyless signature over an
// artifact wraps.
func statementOver(t *testing.T, artifact digest.Digest) []byte {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"_type":         "https://in-toto.io/Statement/v0.1",
		"predicateType": "https://cosign.sigstore.dev/attestation/v1",
		"subject": []map[string]any{{
			"name":   "artifact",
			"digest": map[string]string{artifact.Algorithm().String(): artifact.Encoded()},
		}},
		"predicate": map[string]any{},
	})
	if err != nil {
		t.Fatalf("encoding the statement: %v", err)
	}
	return payload
}

// signPayload signs arbitrary bytes as a DSSE envelope, so a test can
// present something that is correctly signed by an allowed identity and is
// not the kind of document palan reads.
func (l *Log) signPayload(t *testing.T, ca *Log, payload []byte, s Signer) signed {
	t.Helper()
	key, cert := ca.Certify(t, s)

	digestOfPAE := sha256.Sum256(pae("application/vnd.in-toto+json", payload))
	sig, err := ecdsa.SignASN1(rand.Reader, key, digestOfPAE[:])
	if err != nil {
		t.Fatalf("signing the statement: %v", err)
	}

	payloadHash := sha256.Sum256(payload)
	body, err := json.Marshal(map[string]any{
		"apiVersion": "0.0.1",
		"kind":       "dsse",
		"spec": map[string]any{
			"payloadHash": map[string]string{
				"algorithm": "sha256",
				"value":     hex.EncodeToString(payloadHash[:]),
			},
			"signatures": []map[string]string{{
				"signature": base64.StdEncoding.EncodeToString(sig),
				"verifier": base64.StdEncoding.EncodeToString(pem.EncodeToMemory(
					&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
			}},
		},
	})
	if err != nil {
		t.Fatalf("encoding the log entry: %v", err)
	}
	return signed{cert: cert, payload: payload, sig: sig, body: body}
}

// Bundle signs an artifact, records it in the log, and returns the material
// a verifier would receive: certificate, envelope, entry and proof.
func (l *Log) Bundle(t *testing.T, artifact digest.Digest, s Signer) []byte {
	t.Helper()
	sg := l.sign(t, artifact, s)
	return l.assemble(t, sg, sg.body)
}

// BundleProvingAnotherEntry returns a bundle whose inclusion proof is
// genuine and whose log entry is genuine, and which are about a different
// signature than the one the bundle carries.
//
// This is what a proof alone cannot rule out. Every check that treats the
// proof as evidence the signature was logged passes here, and only holding
// the proven entry against the signature in hand catches it.
func (l *Log) BundleProvingAnotherEntry(t *testing.T, artifact digest.Digest, s Signer) []byte {
	t.Helper()
	elsewhere := l.sign(t, digest.FromString("another artifact"), s)
	sg := l.sign(t, artifact, s)
	return l.assemble(t, sg, elsewhere.body)
}

// assemble records logged in the tree and builds a bundle around sg,
// proving inclusion of whatever was recorded.
//
// The entry sits among others rather than alone, so that the proof has
// siblings on both sides of it and exercises a path through the tree
// instead of the single-branch case a one-entry log would give.
func (l *Log) assemble(t *testing.T, sg signed, logged []byte) []byte {
	t.Helper()
	for i := 0; i < 5; i++ {
		l.entries.add([]byte("unrelated entry " + strconv.Itoa(len(l.entries.leaves))))
	}
	index := l.entries.add(logged)
	l.entries.add([]byte("a later entry"))

	proof, err := l.entries.inclusionProof(index)
	if err != nil {
		t.Fatalf("building the inclusion proof: %v", err)
	}
	root := l.entries.root()
	size := int64(len(l.entries.leaves))

	id := sha256.Sum256(l.logDER)
	bundle := &protobundle.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_Certificate{
				Certificate: &protocommon.X509Certificate{RawBytes: sg.cert.Raw},
			},
			TlogEntries: []*protorekor.TransparencyLogEntry{{
				LogIndex:       int64(index),
				LogId:          &protocommon.LogId{KeyId: id[:]},
				KindVersion:    &protorekor.KindVersion{Kind: "dsse", Version: "0.0.1"},
				IntegratedTime: SignedAt.Unix(),
				InclusionPromise: &protorekor.InclusionPromise{
					SignedEntryTimestamp: l.entryTimestamp(t, logged, int64(index)),
				},
				InclusionProof: &protorekor.InclusionProof{
					LogIndex:   int64(index),
					RootHash:   root,
					TreeSize:   size,
					Hashes:     proof,
					Checkpoint: &protorekor.Checkpoint{Envelope: l.checkpoint(t, root, size)},
				},
				CanonicalizedBody: logged,
			}},
		},
		Content: &protobundle.Bundle_DsseEnvelope{
			DsseEnvelope: &protodsse.Envelope{
				Payload:     sg.payload,
				PayloadType: "application/vnd.in-toto+json",
				Signatures:  []*protodsse.Signature{{Sig: sg.sig}},
			},
		},
	}
	out, err := protojson.Marshal(bundle)
	if err != nil {
		t.Fatalf("encoding the bundle: %v", err)
	}
	return out
}

// checkpoint signs a tree head in the note format transparency logs use:
// the log's name, the number of entries, and the root, then a blank line
// and one signature line. The signature covers the text and the newline
// ending it, and not the blank line separating text from signatures.
func (l *Log) checkpoint(t *testing.T, root []byte, size int64) string {
	t.Helper()
	text := fmt.Sprintf("%s - 1\n%d\n%s\n",
		Origin, size, base64.StdEncoding.EncodeToString(root))
	sum := sha256.Sum256([]byte(text))
	sig, err := ecdsa.SignASN1(rand.Reader, l.logKey, sum[:])
	if err != nil {
		t.Fatalf("signing the checkpoint: %v", err)
	}
	id := sha256.Sum256(l.logDER)
	line := append(append([]byte{}, id[:4]...), sig...)
	return text + "\n— " + Origin + " " + base64.StdEncoding.EncodeToString(line) + "\n"
}

// entryTimestamp signs what a transparency log signs when it accepts an
// entry: the entry's bytes, when it was recorded, which log recorded it,
// and where in that log it sits.
//
// The signed bytes are written out by hand rather than encoded from a
// struct shared with the package under test, so that a misplaced field or
// a wrong name fails here instead of matching a verifier that made the
// same mistake. The canonical form sorts the keys, which is why logID
// precedes logIndex.
func (l *Log) entryTimestamp(t *testing.T, body []byte, index int64) []byte {
	t.Helper()
	id := sha256.Sum256(l.logDER)
	signed := fmt.Sprintf(
		`{"body":%q,"integratedTime":%d,"logID":%q,"logIndex":%d}`,
		base64.StdEncoding.EncodeToString(body),
		SignedAt.Unix(),
		hex.EncodeToString(id[:]),
		index)
	sum := sha256.Sum256([]byte(signed))
	sig, err := ecdsa.SignASN1(rand.Reader, l.logKey, sum[:])
	if err != nil {
		t.Fatalf("signing the entry timestamp: %v", err)
	}
	return sig
}

// pae is DSSE's pre-authentication encoding, written out here rather than
// borrowed from the package under test so that a mistake in one is not
// matched by the same mistake in the other.
func pae(payloadType string, payload []byte) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "DSSEv1 %d %s %d ", len(payloadType), payloadType, len(payload))
	b.Write(payload)
	return b.Bytes()
}

// BundleFromAnotherAuthority returns a bundle whose certificate was issued
// by other, recorded in this log. The log is the pinned one and its proof
// is genuine, so the only thing wrong is who issued the certificate.
func (l *Log) BundleFromAnotherAuthority(t *testing.T, artifact digest.Digest, s Signer, other *Log) []byte {
	t.Helper()
	sg := l.signWith(t, other, artifact, s)
	return l.assemble(t, sg, sg.body)
}

// BundleMisrecordingItsPayload returns a bundle whose log entry names this
// signature and this certificate while recording a hash of some other
// payload. An entry that disagrees with itself this way is one no honest
// log would hold.
func (l *Log) BundleMisrecordingItsPayload(t *testing.T, artifact digest.Digest, s Signer) []byte {
	t.Helper()
	sg := l.sign(t, artifact, s)
	var body map[string]any
	if err := json.Unmarshal(sg.body, &body); err != nil {
		t.Fatalf("decoding the log entry: %v", err)
	}
	spec := body["spec"].(map[string]any)
	spec["payloadHash"] = map[string]string{
		"algorithm": "sha256",
		"value":     hex.EncodeToString(make([]byte, 32)),
	}
	edited, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("re-encoding the log entry: %v", err)
	}
	return l.assemble(t, sg, edited)
}

// BundleOverAnotherDocument returns a bundle correctly signed by an allowed
// identity over a payload that is not an in-toto statement. Everything
// about it verifies; it simply is not a statement about an artifact.
func (l *Log) BundleOverAnotherDocument(t *testing.T, s Signer) []byte {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"_type": "https://example.com/SomethingElse/v1",
		"note":  "correctly signed, and not a statement about anything",
	})
	if err != nil {
		t.Fatal(err)
	}
	sg := l.signPayload(t, l, payload, s)
	return l.assemble(t, sg, sg.body)
}
