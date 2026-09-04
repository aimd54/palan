// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/aimd54/palan/internal/store"
)

// Link names, in the order a chain is walked: from the reference somebody
// typed, through the signature and what allowed it, to the bytes on disk.
const (
	linkReference = "reference"
	linkSignature = "signature"
	linkPolicy    = "policy"
	linkLog       = "transparency log"
	linkSources   = "provenance"
	linkContent   = "content"
)

// explanation is what verify established about one artifact, and what it
// did not. Text and JSON render from this same value, so the two cannot
// come to disagree about what was proven.
type explanation struct {
	Reference string `json:"reference"`
	Digest    string `json:"digest"`
	// Source is where the signature was read from: the local store, or the
	// registry. It decides whether this result needed a network.
	Source string `json:"source"`
	Links  []link `json:"links"`
}

// link is one step between the reference and the bytes. Proven says whether
// this host established that step; Detail says what was established, or why
// it could not be.
//
// An unproven link is not a failure. Verification succeeded, or verify would
// have returned an error instead of an explanation. These are the steps the
// chain does not cover, named rather than omitted, because a chain printed
// with its gaps removed reads as a chain with no gaps, which is the claim
// this command exists to avoid making.
type link struct {
	Name   string `json:"link"`
	Proven bool   `json:"proven"`
	Detail string `json:"detail"`
}

// rehashOutcome is what the content link has to report: whether the blobs
// were re-read, and what came back.
type rehashOutcome struct {
	ran    bool
	report store.RehashReport
}

// explain assembles the chain from what verification returned. It asserts
// nothing of its own: every link is a restatement of a result the steps
// above already produced, which is why a link can be added here without
// anything needing to re-derive it.
func explain(ref, dgst string, src verifySource, by verifiedBy, att attestationReport, rh rehashOutcome) explanation {
	e := explanation{Reference: ref, Digest: dgst, Source: src.name}
	e.Links = append(e.Links,
		link{
			Name:   linkReference,
			Proven: true,
			Detail: fmt.Sprintf("%s resolves to this digest in the %s", ref, src.name),
		},
		signatureLink(by),
	)
	e.Links = append(e.Links, policyLink(by))
	if by.keyless != nil {
		e.Links = append(e.Links, logLink(by))
	}
	e.Links = append(e.Links, sourcesLink(att), contentLink(rh))
	return e
}

// signatureLink says who signed, in the terms the signature itself used: a
// key file for a key-based signature, an identity and the provider that
// authenticated it for a keyless one.
func signatureLink(by verifiedBy) link {
	if by.keyless != nil {
		return link{
			Name:   linkSignature,
			Proven: true,
			Detail: fmt.Sprintf("signed by %s, authenticated by %s", by.keyless.Subject, by.keyless.Issuer),
		}
	}
	return link{
		Name:   linkSignature,
		Proven: true,
		Detail: "a signature over this digest verifies under the configured key",
	}
}

// policyLink says what permitted this signer, which is not the same
// question as who signed.
//
// Printed unproven rather than omitted when nothing recorded an answer.
// Every path that accepts a signature fills this in today, so the unproven
// form is unreachable; it exists because a path added later that forgets to
// would otherwise drop the link, and a chain that lost one still reads as
// complete. That is the failure this whole file is written to prevent, and
// it should not be possible here of all places.
func policyLink(by verifiedBy) link {
	if by.admitted == "" {
		return link{
			Name:   linkPolicy,
			Proven: false,
			Detail: "nothing recorded what allowed this signer to sign it",
		}
	}
	return link{
		Name:   linkPolicy,
		Proven: true,
		Detail: "this signer is allowed to sign it by " + by.admitted,
	}
}

// logLink reports what dates a keyless signature. A Fulcio certificate lives
// minutes, so without the log entry there is no moment to hold it to, and
// this is the link that supplies one.
func logLink(by verifiedBy) link {
	detail := fmt.Sprintf(
		"entry %d, recorded %s; its inclusion proof rebuilds a log root signed by a key in %s",
		by.keyless.LogIndex,
		by.keyless.IntegratedTime.UTC().Format(time.RFC3339),
		by.trustRoot)
	return link{Name: linkLog, Proven: true, Detail: detail}
}

// sourcesLink reports where the artifact's files came from, when a signed
// statement says so and it held against the artifact's own layers.
//
// Three answers, all of them useful and only one of them a proof: the
// sources were established, the artifact claims sources nothing vouches
// for, or the artifact claims none at all. The third is not a gap, and it
// is spelled out rather than left blank so that a reader can tell it apart
// from the second.
func sourcesLink(att attestationReport) link {
	if len(att.provenance) > 0 {
		return link{
			Name:   linkSources,
			Proven: true,
			Detail: "packed from " + strings.Join(att.provenance, ", "),
		}
	}
	if att.warning != "" {
		return link{
			Name:   linkSources,
			Proven: false,
			Detail: strings.TrimPrefix(att.warning, "WARNING: "),
		}
	}
	return link{
		Name:   linkSources,
		Proven: false,
		Detail: "no layer records an upstream file, so this artifact was packed from local disk and names no source to check",
	}
}

// contentLink reports whether the bytes on this host were read back.
//
// Unproven by default, and stated as such on every run: a signature covers
// a manifest, and a manifest names blobs by digest, so nothing above this
// line has looked at a weight file. Leaving the link out when it was not
// asked for would let a chain that never touched the weights read as one
// that did.
func contentLink(rh rehashOutcome) link {
	if !rh.ran {
		return link{
			Name:   linkContent,
			Proven: false,
			Detail: "the blobs were not read back; --rehash holds them to the digests the manifest records",
		}
	}
	return link{
		Name:   linkContent,
		Proven: true,
		Detail: fmt.Sprintf(
			"%d blobs re-read (%s), each hashing to the digest the manifest records",
			rh.report.Blobs, humanBytes(rh.report.Bytes)),
	}
}

// renderExplanation writes the chain for a person, one link per line, with
// the verdict first on each so the unproven ones can be found by eye in a
// long output.
func renderExplanation(w io.Writer, e explanation) error {
	if _, err := fmt.Fprintf(w, "Verified %s@%s\n  source: %s\n\n", e.Reference, e.Digest, e.Source); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	for _, l := range e.Links {
		verdict := "unproven"
		if l.Proven {
			verdict = "proven"
		}
		if _, err := fmt.Fprintf(tw, "  %s\t%s\t%s\n", verdict, l.Name, l.Detail); err != nil {
			return err
		}
	}
	return tw.Flush()
}

// renderExplanationJSON writes the same chain for a program. Nothing else
// goes to the stream, so the output parses whole.
func renderExplanationJSON(w io.Writer, e explanation) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(e)
}
