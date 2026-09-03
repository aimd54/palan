// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package keyless

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/bits"
	"strconv"
	"strings"
	"time"

	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/sigstore/pkg/signature"
)

// verifyLogEntry establishes when a signature was recorded, and that it was
// recorded at all. Those are two separate claims proven by two separate
// signatures, and conflating them is the easiest mistake to make here.
//
// The inclusion proof, with its checkpoint, proves that an entry is in the
// log. It says nothing about when: a checkpoint signs the log's size and
// root and carries no date, and the proof binds only the entry's bytes,
// which carry none either. The entry's timestamp is proven instead by the
// log's signature over it, the signed entry timestamp, and that signature
// is what makes the timestamp worth anything at all.
//
// The timestamp has to be worth something, because a keyless signing
// certificate lives about ten minutes and is checked against the moment
// the log recorded the signature rather than against the present. An
// unproven timestamp would put the expiry of every such certificate in the
// hands of whoever wrote the bundle, which is to say there would be no
// expiry.
//
// So the timestamp is proven first, and everything measured against it
// follows.
func verifyLogEntry(entry *protorekor.TransparencyLogEntry, root *TrustedRoot, sig, payload, certDER []byte) (time.Time, error) {
	proof := entry.GetInclusionProof()
	if proof == nil {
		return time.Time{}, fmt.Errorf(
			"the log entry carries no inclusion proof, so there is no offline evidence it was ever recorded")
	}
	if proof.GetCheckpoint().GetEnvelope() == "" {
		return time.Time{}, fmt.Errorf(
			"the inclusion proof carries no checkpoint, so its log root is unsigned and proves nothing")
	}

	id := hex.EncodeToString(entry.GetLogId().GetKeyId())
	key, ok := root.logs[id]
	if !ok {
		return time.Time{}, fmt.Errorf(
			"the entry names transparency log %s, which the trusted root does not list", id)
	}
	logVerifier, err := signature.LoadVerifier(key.public, crypto.SHA256)
	if err != nil {
		return time.Time{}, fmt.Errorf("loading the transparency log key: %w", err)
	}

	// The log is named by the entry, and the key is chosen by that name, so
	// on its own the name proves nothing. What binds them is that the
	// signature checked here covers the name too: an entry relabelled to a
	// different pinned log would need that log's signature, and one
	// relabelled to a log the root does not list was already refused above.
	if err := verifyEntryTimestamp(entry, logVerifier); err != nil {
		return time.Time{}, err
	}
	integrated := time.Unix(entry.GetIntegratedTime(), 0).UTC()
	if !key.valid.covers(integrated) {
		return time.Time{}, fmt.Errorf(
			"the entry is dated %s, outside the window the trusted root gives transparency log %s",
			integrated.Format(time.RFC3339), id)
	}

	// The checkpoint's own fields are read back out of the text the log
	// signed, never out of the surrounding envelope, so that anything the
	// signature does not cover cannot influence what is compared.
	signedRoot, signedSize, err := verifyCheckpoint(proof.GetCheckpoint().GetEnvelope(), logVerifier)
	if err != nil {
		return time.Time{}, err
	}
	if signedSize != proof.GetTreeSize() {
		return time.Time{}, fmt.Errorf(
			"the inclusion proof is against a tree of %d entries but its checkpoint signs one of %d",
			proof.GetTreeSize(), signedSize)
	}
	if !bytes.Equal(signedRoot, proof.GetRootHash()) {
		return time.Time{}, fmt.Errorf(
			"the inclusion proof states a log root the checkpoint does not sign")
	}

	body := entry.GetCanonicalizedBody()
	if len(body) == 0 {
		return time.Time{}, fmt.Errorf("the log entry carries no body, so there is nothing to prove inclusion of")
	}
	computed, err := rootFromInclusionProof(
		proof.GetLogIndex(), proof.GetTreeSize(), leafHash(body), proof.GetHashes())
	if err != nil {
		return time.Time{}, fmt.Errorf("checking the inclusion proof: %w", err)
	}
	if !bytes.Equal(computed, signedRoot) {
		return time.Time{}, fmt.Errorf(
			"the inclusion proof does not rebuild the log root the checkpoint signs, so this entry is not in that log")
	}

	// A proof shows that some entry is in the log. Without this the entry
	// could be any of the millions the log holds, and a genuine proof for
	// somebody else's signature would satisfy every check above.
	if err := bodyDescribes(body, sig, payload, certDER); err != nil {
		return time.Time{}, fmt.Errorf("the proven log entry is not about this signature: %w", err)
	}
	return integrated, nil
}

// entryTimestamp is what a transparency log signs when it accepts an entry.
// The fields are declared in the order the canonical form sorts them, so
// encoding the struct produces those bytes directly: the values are an
// integer, a base64 string and a hex string, none of which the canonical
// form would render differently from the ordinary encoder.
type entryTimestamp struct {
	Body           string `json:"body"`
	IntegratedTime int64  `json:"integratedTime"`
	LogID          string `json:"logID"`
	LogIndex       int64  `json:"logIndex"`
}

// verifyEntryTimestamp checks the log's own signature over when it recorded
// this entry.
//
// This is the only thing that dates a signature. Everything else in a
// bundle is either undated or dated by whoever wrote the bundle, so without
// this a certificate would be checked against a moment the bundle chose,
// and a certificate that may be checked against any moment does not expire.
//
// An entry carrying no such signature is refused rather than accepted with
// its stated time, because accepting it is the same as having no expiry
// check while reporting one.
func verifyEntryTimestamp(entry *protorekor.TransparencyLogEntry, verifier signature.Verifier) error {
	set := entry.GetInclusionPromise().GetSignedEntryTimestamp()
	if len(set) == 0 {
		return fmt.Errorf(
			"the log entry carries no signed timestamp, so nothing dates this signature and its certificate cannot be held to the moment it was used")
	}
	signed, err := json.Marshal(entryTimestamp{
		Body:           base64.StdEncoding.EncodeToString(entry.GetCanonicalizedBody()),
		IntegratedTime: entry.GetIntegratedTime(),
		LogID:          hex.EncodeToString(entry.GetLogId().GetKeyId()),
		LogIndex:       entry.GetLogIndex(),
	})
	if err != nil {
		return fmt.Errorf("encoding the entry's timestamp: %w", err)
	}
	if err := verifier.VerifySignature(
		bytes.NewReader(set), bytes.NewReader(signed)); err != nil {
		return fmt.Errorf(
			"the transparency log did not sign this entry as stated, so its date, its index and its contents are all unproven: %w", err)
	}
	return nil
}

// verifyCheckpoint checks a signed tree head and returns the log root and
// tree size it commits to.
//
// The format is the signed note used across transparency logs: lines of
// text, a blank line, then one signature line per signer. The signature
// covers the text and the newline ending it, and not the blank line that
// separates text from signatures.
func verifyCheckpoint(envelope string, verifier signature.Verifier) ([]byte, int64, error) {
	split := strings.LastIndex(envelope, "\n\n")
	if split < 0 {
		return nil, 0, fmt.Errorf("the checkpoint has no signature block")
	}
	text, sigs := envelope[:split+1], envelope[split+2:]

	if err := verifyAnyNoteSignature(text, sigs, verifier); err != nil {
		return nil, 0, err
	}

	// Read after verifying, and out of the text the signature covered.
	lines := strings.Split(text, "\n")
	if len(lines) < 4 {
		return nil, 0, fmt.Errorf("the checkpoint names no log root")
	}
	size, err := strconv.ParseInt(lines[1], 10, 64)
	if err != nil {
		return nil, 0, fmt.Errorf("the checkpoint's tree size %q is not a number", lines[1])
	}
	if size <= 0 {
		return nil, 0, fmt.Errorf("the checkpoint signs a tree of %d entries", size)
	}
	rootHash, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil {
		return nil, 0, fmt.Errorf("the checkpoint's log root is not base64: %w", err)
	}
	if len(rootHash) != sha256.Size {
		return nil, 0, fmt.Errorf(
			"the checkpoint's log root is %d bytes, not the %d a SHA-256 root has",
			len(rootHash), sha256.Size)
	}
	return rootHash, size, nil
}

// verifyAnyNoteSignature accepts the checkpoint if any one of its signature
// lines verifies. A checkpoint may be co-signed by witnesses whose keys are
// not pinned here, so a line that does not verify is a line for somebody
// else rather than a forgery.
func verifyAnyNoteSignature(text, sigs string, verifier signature.Verifier) error {
	found := false
	for _, line := range strings.Split(strings.TrimRight(sigs, "\n"), "\n") {
		// A signature line is "— <name> <base64>", where the base64
		// holds a four-byte hint at the key followed by the signature.
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[0] != "—" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(fields[2])
		if err != nil || len(raw) <= 4 {
			continue
		}
		found = true
		if err := verifier.VerifySignature(
			bytes.NewReader(raw[4:]), strings.NewReader(text)); err == nil {
			return nil
		}
	}
	if !found {
		return fmt.Errorf("the checkpoint carries no readable signature")
	}
	return fmt.Errorf("no signature on the checkpoint verifies against the trusted log key")
}

// rekorBody is the part of a log entry palan reads. A log entry records far
// more than this; these are the fields that say which signature it is about.
type rekorBody struct {
	Kind string `json:"kind"`
	Spec struct {
		PayloadHash struct {
			Algorithm string `json:"algorithm"`
			Value     string `json:"value"`
		} `json:"payloadHash"`
		Signatures []struct {
			Signature string `json:"signature"`
			Verifier  string `json:"verifier"`
		} `json:"signatures"`
	} `json:"spec"`
}

// bodyDescribes checks that the log entry just proven to be in the log is
// the record of this signature.
//
// Three things are compared, and together they leave nothing to choose: the
// payload hash fixes what was signed, the signature fixes the signing, and
// the verifier fixes who did it. The envelope hash the entry also carries is
// not compared, because reproducing it means canonicalising JSON by
// somebody else's rules, and it would add nothing: the envelope is its
// payload, its payload type and its signature, the first and last are
// compared here, and the payload type is covered by the signature itself.
func bodyDescribes(body, sig, payload, certDER []byte) error {
	var parsed rekorBody
	if err := json.Unmarshal(body, &parsed); err != nil {
		return fmt.Errorf("decoding the entry: %w", err)
	}
	if parsed.Kind != "dsse" {
		return fmt.Errorf(
			"it records a %q entry, and palan reads the %q entries a keyless signature over an artifact produces",
			parsed.Kind, "dsse")
	}
	if alg := parsed.Spec.PayloadHash.Algorithm; alg != "sha256" {
		return fmt.Errorf("it hashes its payload with %q, which palan does not read", alg)
	}
	want := sha256.Sum256(payload)
	if parsed.Spec.PayloadHash.Value != hex.EncodeToString(want[:]) {
		return fmt.Errorf("it records a different payload")
	}
	for _, s := range parsed.Spec.Signatures {
		entrySig, err := base64.StdEncoding.DecodeString(s.Signature)
		if err != nil || !bytes.Equal(entrySig, sig) {
			continue
		}
		pem, err := base64.StdEncoding.DecodeString(s.Verifier)
		if err != nil {
			continue
		}
		certs, err := parseCertificates(pem)
		if err != nil || len(certs) == 0 || !bytes.Equal(certs[0].Raw, certDER) {
			continue
		}
		return nil
	}
	return fmt.Errorf("none of its signatures is this one, made by this certificate")
}

// leafHash is how a transparency log hashes an entry into its tree: the
// entry's bytes under a leaf prefix, which keeps a leaf from ever colliding
// with an interior node.
func leafHash(body []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(body)
	return h.Sum(nil)
}

// hashChildren combines two subtree hashes under an interior-node prefix.
func hashChildren(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// rootFromInclusionProof rebuilds the log root that a tree of size entries
// must have if leaf sits at index, given the sibling hashes on the path
// from that leaf to the root (RFC 6962).
//
// The number of hashes a proof needs is fixed by index and size alone, so a
// proof of any other length is refused rather than consumed as far as it
// goes: stopping early would rebuild the root of a subtree and comparing
// that against the signed root is not the question being asked.
func rootFromInclusionProof(index, size int64, leaf []byte, hashes [][]byte) ([]byte, error) {
	if index < 0 || size <= 0 || index >= size {
		return nil, fmt.Errorf("entry %d is not in a log of %d entries", index, size)
	}
	// Sibling hashes come in two runs: those inside the subtree containing
	// the leaf, then those along the tree's right border.
	inner := bits.Len64(uint64(index) ^ uint64(size-1))
	border := bits.OnesCount64(uint64(index) >> uint(inner))
	if len(hashes) != inner+border {
		return nil, fmt.Errorf(
			"the proof carries %d hashes, and entry %d of %d needs %d",
			len(hashes), index, size, inner+border)
	}
	for _, h := range hashes {
		if len(h) != sha256.Size {
			return nil, fmt.Errorf("a proof hash is %d bytes, not %d", len(h), sha256.Size)
		}
	}

	res := leaf
	for i, h := range hashes[:inner] {
		if (index>>uint(i))&1 == 0 {
			res = hashChildren(res, h)
		} else {
			res = hashChildren(h, res)
		}
	}
	for _, h := range hashes[inner:] {
		res = hashChildren(h, res)
	}
	return res, nil
}
