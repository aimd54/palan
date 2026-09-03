// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package keyless_test

import (
	"strings"
	"testing"

	digest "github.com/opencontainers/go-digest"

	"github.com/aimd54/palan/internal/keyless"
	"github.com/aimd54/palan/internal/keyless/keylesstest"
)

var (
	artifact = digest.FromString("a model")
	workflow = keylesstest.Signer{
		Subject: "https://forge.example/org/repo/.github/workflows/release.yml@refs/tags/v1.4.0",
		Issuer:  "https://token.forge.example",
	}
)

func allow(subject, issuer string) []keyless.Identity {
	return []keyless.Identity{{Subject: subject, Issuer: issuer}}
}

func rootOf(t *testing.T, l *keylesstest.Log) *keyless.TrustedRoot {
	t.Helper()
	root, err := keyless.LoadTrustedRoot(l.TrustedRoot)
	if err != nil {
		t.Fatalf("loading the trusted root: %v", err)
	}
	return root
}

// TestABuiltBundleVerifies is the control the negative tests below need: it
// says the material this package builds is material the verifier accepts,
// so a later refusal is caused by the one thing that test changed.
//
// It also puts the entry in the middle of a log with entries on both sides
// of it, which is the path through a tree that a log holding one entry
// never exercises.
func TestABuiltBundleVerifies(t *testing.T) {
	l := keylesstest.NewLog(t)
	bundle := l.Bundle(t, artifact, workflow)

	got, err := keyless.Verify(bundle, artifact, rootOf(t, l),
		allow(workflow.Subject, workflow.Issuer))
	if err != nil {
		t.Fatalf("verifying: %v", err)
	}
	if got.Subject != workflow.Subject {
		t.Errorf("subject = %q, want %q", got.Subject, workflow.Subject)
	}
	if got.Issuer != workflow.Issuer {
		t.Errorf("issuer = %q, want %q", got.Issuer, workflow.Issuer)
	}
	if !got.IntegratedTime.Equal(keylesstest.SignedAt) {
		t.Errorf("integrated time = %s, want %s", got.IntegratedTime, keylesstest.SignedAt)
	}
}

// TestAProofOfAnotherEntryIsRefused is the check a valid inclusion proof
// cannot make on its own.
//
// The certificate is genuine, the signature verifies under it, the
// checkpoint is signed by the pinned log key, and the inclusion proof
// rebuilds that exact root. Every one of those passes. What the log
// actually recorded is a different signature, and only comparing the proven
// entry against the signature in hand says so.
func TestAProofOfAnotherEntryIsRefused(t *testing.T) {
	l := keylesstest.NewLog(t)
	bundle := l.BundleProvingAnotherEntry(t, artifact, workflow)

	_, err := keyless.Verify(bundle, artifact, rootOf(t, l),
		allow(workflow.Subject, workflow.Issuer))
	if err == nil {
		t.Fatal("a proof of somebody else's log entry verified")
	}
	if !strings.Contains(err.Error(), "not about this signature") {
		t.Errorf("refusal does not say the entry is the wrong one: %v", err)
	}
}

// TestAnotherAuthorityIsRefused verifies a wholly genuine bundle against a
// root that pins a different authority and a different log. Nothing about
// the bundle is malformed; it is simply not the one this operator trusts.
func TestAnotherAuthorityIsRefused(t *testing.T) {
	mine := keylesstest.NewLog(t)
	theirs := keylesstest.NewLog(t)
	bundle := theirs.Bundle(t, artifact, workflow)

	_, err := keyless.Verify(bundle, artifact, rootOf(t, mine),
		allow(workflow.Subject, workflow.Issuer))
	if err == nil {
		t.Fatal("a bundle from an unpinned authority verified")
	}
}

// TestAWorkflowPatternSurvivesARelease is why a subject is matched by
// pattern: the identity carries the tag it was built from, so a policy
// naming one exactly would need editing for every release.
func TestAWorkflowPatternSurvivesARelease(t *testing.T) {
	l := keylesstest.NewLog(t)
	next := keylesstest.Signer{
		Subject: strings.Replace(workflow.Subject, "v1.4.0", "v1.5.0", 1),
		Issuer:  workflow.Issuer,
	}
	pattern := "https://forge.example/org/repo/.github/workflows/release.yml@refs/tags/*"

	for _, s := range []keylesstest.Signer{workflow, next} {
		bundle := l.Bundle(t, artifact, s)
		got, err := keyless.Verify(bundle, artifact, rootOf(t, l),
			allow(pattern, s.Issuer))
		if err != nil {
			t.Fatalf("verifying %s: %v", s.Subject, err)
		}
		if got.Subject != s.Subject {
			t.Errorf("subject = %q, want %q", got.Subject, s.Subject)
		}
	}
}

// TestAPatternDoesNotReachAnotherRepository holds the pattern to the shape
// somebody writing it would expect: it ends at the tag, and must not admit
// a workflow in a different repository that happens to share the tail.
func TestAPatternDoesNotReachAnotherRepository(t *testing.T) {
	l := keylesstest.NewLog(t)
	elsewhere := keylesstest.Signer{
		Subject: "https://forge.example/attacker/repo/.github/workflows/release.yml@refs/tags/v1.4.0",
		Issuer:  workflow.Issuer,
	}
	bundle := l.Bundle(t, artifact, elsewhere)
	pattern := "https://forge.example/org/repo/.github/workflows/release.yml@refs/tags/*"

	_, err := keyless.Verify(bundle, artifact, rootOf(t, l),
		allow(pattern, elsewhere.Issuer))
	if err == nil {
		t.Fatal("a workflow in another repository matched the pattern")
	}
}

// TestACertificateFromAnotherAuthorityIsRefused isolates the chain. The
// signature was recorded in the pinned log and its proof is genuine, so
// nothing here is caught by the log checks: the certificate simply was not
// issued by an authority this operator pinned.
func TestACertificateFromAnotherAuthorityIsRefused(t *testing.T) {
	l := keylesstest.NewLog(t)
	other := keylesstest.NewLog(t)
	bundle := l.BundleFromAnotherAuthority(t, artifact, workflow, other)

	_, err := keyless.Verify(bundle, artifact, rootOf(t, l),
		allow(workflow.Subject, workflow.Issuer))
	if err == nil {
		t.Fatal("a certificate from an unpinned authority verified")
	}
	if !strings.Contains(err.Error(), "does not chain") {
		t.Errorf("refusal does not point at the certificate: %v", err)
	}
}

// TestAnEntryDisagreeingWithItselfIsRefused covers the log entry naming
// this signature and this certificate while recording a hash of some other
// payload. Matching the signature alone would accept it.
func TestAnEntryDisagreeingWithItselfIsRefused(t *testing.T) {
	l := keylesstest.NewLog(t)
	bundle := l.BundleMisrecordingItsPayload(t, artifact, workflow)

	_, err := keyless.Verify(bundle, artifact, rootOf(t, l),
		allow(workflow.Subject, workflow.Issuer))
	if err == nil {
		t.Fatal("a log entry recording another payload verified")
	}
	if !strings.Contains(err.Error(), "records a different payload") {
		t.Errorf("refusal does not name the disagreement: %v", err)
	}
}
