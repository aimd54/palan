// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package keyless

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	digest "github.com/opencontainers/go-digest"
)

// The fixtures are real. The bundle is a keyless signature made against the
// public Sigstore instance, and the trusted root is that instance's own, so
// a mistake in the wire formats fails here rather than passing against
// material this package also produced.
const (
	fixtureArtifact = digest.Digest(
		"sha256:732112270d7e59418a8c080b134b24cabd67d250d0d0147a97ed95ba5c280aa4")
	fixtureSubject = "cody@soyland.com"
	fixtureIssuer  = "https://github.com/login/oauth"
)

func fixtureIdentity() []Identity {
	return []Identity{{Subject: fixtureSubject, Issuer: fixtureIssuer}}
}

func loadFixtures(t *testing.T) (bundle []byte, root *TrustedRoot) {
	t.Helper()
	bundle, err := os.ReadFile(filepath.Join("testdata", "public-good-bundle.json"))
	if err != nil {
		t.Fatalf("reading the bundle fixture: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join("testdata", "trusted-root-public-good.json"))
	if err != nil {
		t.Fatalf("reading the trusted root fixture: %v", err)
	}
	root, err = LoadTrustedRoot(raw)
	if err != nil {
		t.Fatalf("loading the trusted root: %v", err)
	}
	return bundle, root
}

// TestARealBundleVerifiesWithNoNetwork is the whole point of the package:
// material that travelled with an artifact, checked against a root pinned
// on disk, with nothing reached over the wire.
func TestARealBundleVerifiesWithNoNetwork(t *testing.T) {
	bundle, root := loadFixtures(t)

	got, err := Verify(bundle, fixtureArtifact, root, fixtureIdentity())
	if err != nil {
		t.Fatalf("verifying: %v", err)
	}
	if got.Subject != fixtureSubject {
		t.Errorf("subject = %q, want %q", got.Subject, fixtureSubject)
	}
	if got.Issuer != fixtureIssuer {
		t.Errorf("issuer = %q, want %q", got.Issuer, fixtureIssuer)
	}
	if got.LogIndex != 175508996 {
		t.Errorf("log index = %d, want 175508996", got.LogIndex)
	}
	// The certificate expired ten minutes after it was issued, years ago.
	// Verification succeeding at all is what proves the check was made
	// against the moment the signature was logged.
	want := time.Unix(1740770291, 0).UTC()
	if !got.IntegratedTime.Equal(want) {
		t.Errorf("integrated time = %s, want %s", got.IntegratedTime, want)
	}
	if leaf := certExpiry(t, bundle); !leaf.Before(time.Now()) {
		t.Errorf("the fixture certificate expires at %s, which is not yet past, so this test no longer proves the certificate is checked against log time", leaf)
	}
}

// TestAnInclusionProofIsRequired pins the milestone's own acceptance
// criterion: the proof is what makes the log entry evidence, and a bundle
// without one must not verify on the strength of everything else being
// intact.
func TestAnInclusionProofIsRequired(t *testing.T) {
	bundle, root := loadFixtures(t)
	stripped := mutateBundle(t, bundle, func(b map[string]any) {
		entry := firstTlogEntry(t, b)
		delete(entry, "inclusionProof")
	})

	_, err := Verify(stripped, fixtureArtifact, root, fixtureIdentity())
	if err == nil {
		t.Fatal("a bundle with no inclusion proof verified")
	}
	if !strings.Contains(err.Error(), "no offline evidence") {
		t.Errorf("refusal does not say what is missing: %v", err)
	}
}

// TestASignedCheckpointIsRequired covers the other half: an inclusion proof
// states its own log root, so without a checkpoint signed by the log there
// is nothing to stop a bundle stating a root of its own devising and
// building a proof that reaches it.
func TestASignedCheckpointIsRequired(t *testing.T) {
	bundle, root := loadFixtures(t)
	stripped := mutateBundle(t, bundle, func(b map[string]any) {
		proof := firstTlogEntry(t, b)["inclusionProof"].(map[string]any)
		delete(proof, "checkpoint")
	})

	_, err := Verify(stripped, fixtureArtifact, root, fixtureIdentity())
	if err == nil {
		t.Fatal("a bundle with no checkpoint verified")
	}
	if !strings.Contains(err.Error(), "unsigned") {
		t.Errorf("refusal does not say what is missing: %v", err)
	}
}

// TestAProofThatDoesNotReachTheSignedRootIsRefused breaks one sibling hash.
// The checkpoint still verifies and the entry is still this signature's, so
// the only thing that can catch it is rebuilding the root.
func TestAProofThatDoesNotReachTheSignedRootIsRefused(t *testing.T) {
	bundle, root := loadFixtures(t)
	broken := mutateBundle(t, bundle, func(b map[string]any) {
		proof := firstTlogEntry(t, b)["inclusionProof"].(map[string]any)
		hashes := proof["hashes"].([]any)
		hashes[0] = flipFirstByte(t, hashes[0].(string))
	})

	_, err := Verify(broken, fixtureArtifact, root, fixtureIdentity())
	if err == nil {
		t.Fatal("a proof that rebuilds a different root verified")
	}
	if !strings.Contains(err.Error(), "not in that log") {
		t.Errorf("refusal does not say the entry is unproven: %v", err)
	}
}

// TestAProofOfTheWrongLengthIsRefused stops a proof being consumed as far
// as it goes. A short proof rebuilds the root of a subtree, and comparing
// that against the signed log root is a different question from the one
// being asked.
func TestAProofOfTheWrongLengthIsRefused(t *testing.T) {
	bundle, root := loadFixtures(t)
	short := mutateBundle(t, bundle, func(b map[string]any) {
		proof := firstTlogEntry(t, b)["inclusionProof"].(map[string]any)
		hashes := proof["hashes"].([]any)
		proof["hashes"] = hashes[:len(hashes)-1]
	})

	_, err := Verify(short, fixtureArtifact, root, fixtureIdentity())
	if err == nil {
		t.Fatal("a proof of the wrong length verified")
	}
	if !strings.Contains(err.Error(), "hashes") {
		t.Errorf("refusal does not name the proof's length: %v", err)
	}
}

// TestAnUnsignedLogRootIsRefused restates the proof's own root hash. The
// rebuilt root now matches what the bundle claims, and only the
// checkpoint's signature stands between that and acceptance.
func TestAnUnsignedLogRootIsRefused(t *testing.T) {
	bundle, root := loadFixtures(t)
	restated := mutateBundle(t, bundle, func(b map[string]any) {
		proof := firstTlogEntry(t, b)["inclusionProof"].(map[string]any)
		proof["rootHash"] = flipFirstByte(t, proof["rootHash"].(string))
	})

	_, err := Verify(restated, fixtureArtifact, root, fixtureIdentity())
	if err == nil {
		t.Fatal("a log root the checkpoint does not sign verified")
	}
	if !strings.Contains(err.Error(), "checkpoint does not sign") {
		t.Errorf("refusal does not point at the checkpoint: %v", err)
	}
}

// TestATamperedCheckpointIsRefused edits the signed text itself, which is
// what a log operator handing out two different roots would have to do.
func TestATamperedCheckpointIsRefused(t *testing.T) {
	bundle, root := loadFixtures(t)
	edited := mutateBundle(t, bundle, func(b map[string]any) {
		cp := firstTlogEntry(t, b)["inclusionProof"].(map[string]any)["checkpoint"].(map[string]any)
		env := cp["envelope"].(string)
		cp["envelope"] = strings.Replace(env, "53604735", "53604736", 1)
	})

	_, err := Verify(edited, fixtureArtifact, root, fixtureIdentity())
	if err == nil {
		t.Fatal("an edited checkpoint verified")
	}
	if !strings.Contains(err.Error(), "no signature on the checkpoint verifies") {
		t.Errorf("refusal does not point at the checkpoint's signature: %v", err)
	}
}

// TestALogPalanDoesNotPinIsRefused gives the entry a log identifier the
// trusted root does not carry. Everything else about the bundle is intact,
// so this is the check that keeps a signature recorded in somebody's own
// log from passing as one recorded in the pinned one.
func TestALogPalanDoesNotPinIsRefused(t *testing.T) {
	bundle, root := loadFixtures(t)
	relabelled := mutateBundle(t, bundle, func(b map[string]any) {
		entry := firstTlogEntry(t, b)
		entry["logId"] = map[string]any{
			"keyId": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		}
	})

	_, err := Verify(relabelled, fixtureArtifact, root, fixtureIdentity())
	if err == nil {
		t.Fatal("an entry from an unpinned log verified")
	}
	if !strings.Contains(err.Error(), "trusted root does not list") {
		t.Errorf("refusal does not say the log is unpinned: %v", err)
	}
}

// TestASignatureOverAnotherArtifactIsRefused is the attack the rest of the
// package cannot see: a bundle that is entirely genuine, attached to an
// artifact it was never about.
func TestASignatureOverAnotherArtifactIsRefused(t *testing.T) {
	bundle, root := loadFixtures(t)
	other := digest.Digest(
		"sha256:0000000000000000000000000000000000000000000000000000000000000000")

	_, err := Verify(bundle, other, root, fixtureIdentity())
	if err == nil {
		t.Fatal("a signature over another artifact verified")
	}
	if !strings.Contains(err.Error(), "not over") {
		t.Errorf("refusal does not say what the signature covers: %v", err)
	}
}

// TestAnIdentityNoRuleNamesIsRefused checks the policy half. The signature
// is real and the log entry proves it; the question is whether this signer
// is allowed here.
func TestAnIdentityNoRuleNamesIsRefused(t *testing.T) {
	bundle, root := loadFixtures(t)

	_, err := Verify(bundle, fixtureArtifact, root, []Identity{
		{Subject: "someone@example.com", Issuer: fixtureIssuer},
	})
	if err == nil {
		t.Fatal("an identity no rule names verified")
	}
	if !strings.Contains(err.Error(), fixtureSubject) {
		t.Errorf("refusal does not name who actually signed: %v", err)
	}
}

// TestTheIssuerIsPartOfTheIdentity holds the subject constant and changes
// only the provider. A subject is a name any provider can mint, so
// accepting one without the provider that asserted it is the whole
// difference between an identity and a string.
func TestTheIssuerIsPartOfTheIdentity(t *testing.T) {
	bundle, root := loadFixtures(t)

	_, err := Verify(bundle, fixtureArtifact, root, []Identity{
		{Subject: fixtureSubject, Issuer: "https://accounts.example.com"},
	})
	if err == nil {
		t.Fatal("a subject certified by another provider verified")
	}
}

// TestASubjectPatternAdmitsAMatchingSigner covers the reason patterns
// exist: a workflow identity carries the ref that built it and changes with
// every release.
func TestASubjectPatternAdmitsAMatchingSigner(t *testing.T) {
	bundle, root := loadFixtures(t)

	got, err := Verify(bundle, fixtureArtifact, root, []Identity{
		{Subject: "*@soyland.com", Issuer: fixtureIssuer},
	})
	if err != nil {
		t.Fatalf("verifying under a pattern: %v", err)
	}
	if got.Subject != fixtureSubject {
		t.Errorf("subject = %q, want the certificate's own %q", got.Subject, fixtureSubject)
	}
}

// TestAnIdentityMatchingEverythingIsRefused catches the pattern somebody
// writes to make a refusal go away.
func TestAnIdentityMatchingEverythingIsRefused(t *testing.T) {
	bundle, root := loadFixtures(t)

	// The bare wildcards are what somebody tries first. The rest are what
	// they write next when the first is refused, and they mean the same
	// thing: no domain is pinned, so a signer chooses their own.
	for _, subject := range []string{
		"*", "**", "*@*", "**@**", "*.*", "https://*", "*@*.*",
	} {
		_, err := Verify(bundle, fixtureArtifact, root, []Identity{
			{Subject: subject, Issuer: fixtureIssuer},
		})
		if err == nil {
			t.Errorf("subject %q was accepted as a policy", subject)
		}
	}
}

// TestAPatternPinningADomainIsAccepted is the other side of the guard: the
// patterns operators legitimately need must still load, or the guard just
// pushes them towards turning verification off.
func TestAPatternPinningADomainIsAccepted(t *testing.T) {
	bundle, root := loadFixtures(t)

	for _, subject := range []string{
		"*@soyland.com",
		"cody@soyland.com",
		"*@*.soyland.com",
	} {
		if err := (Identity{Subject: subject, Issuer: fixtureIssuer}).Validate(); err != nil {
			t.Errorf("subject %q was refused: %v", subject, err)
		}
	}
	// A workflow identity carries a version that moves, and the pattern for
	// it has to pin the forge rather than the tag.
	err := (Identity{
		Subject: "https://forge.example/org/repo/.github/workflows/release.yml@refs/tags/*",
		Issuer:  "https://token.forge.example",
	}).Validate()
	if err != nil {
		t.Errorf("a workflow pattern was refused: %v", err)
	}
	_ = bundle
	_ = root
}

// TestNoAllowedIdentityIsRefused: a bundle that verifies says an identity
// signed the artifact, never that the identity was supposed to.
func TestNoAllowedIdentityIsRefused(t *testing.T) {
	bundle, root := loadFixtures(t)

	if _, err := Verify(bundle, fixtureArtifact, root, nil); err == nil {
		t.Fatal("a bundle verified with no identity allowed")
	}
}

func TestNoPinnedRootIsRefused(t *testing.T) {
	bundle, _ := loadFixtures(t)

	if _, err := Verify(bundle, fixtureArtifact, nil, fixtureIdentity()); err == nil {
		t.Fatal("a bundle verified against no trusted root")
	}
}

// TestASignatureThatDoesNotVerifyIsRefused edits the signed statement. This
// is checked before anything else, so the refusal names the signature
// rather than one of the things a changed payload also breaks.
func TestASignatureThatDoesNotVerifyIsRefused(t *testing.T) {
	bundle, root := loadFixtures(t)
	edited := mutateBundle(t, bundle, func(b map[string]any) {
		b["dsseEnvelope"].(map[string]any)["payload"] =
			flipFirstByte(t, b["dsseEnvelope"].(map[string]any)["payload"].(string))
	})

	_, err := Verify(edited, fixtureArtifact, root, fixtureIdentity())
	if err == nil {
		t.Fatal("a signature over edited bytes verified")
	}
	if !strings.Contains(err.Error(), "does not verify against its own certificate") {
		t.Errorf("refusal does not point at the signature: %v", err)
	}
}

// TestASignedTimestampIsRequired pins what dates a signature. An inclusion
// proof shows an entry is in the log and says nothing about when: a
// checkpoint signs a size and a root, and the entry's bytes carry no date.
// Only the log's own signature over the timestamp does.
func TestASignedTimestampIsRequired(t *testing.T) {
	bundle, root := loadFixtures(t)
	stripped := mutateBundle(t, bundle, func(b map[string]any) {
		delete(firstTlogEntry(t, b), "inclusionPromise")
	})

	_, err := Verify(stripped, fixtureArtifact, root, fixtureIdentity())
	if err == nil {
		t.Fatal("a log entry with no signed timestamp verified")
	}
	if !strings.Contains(err.Error(), "no signed timestamp") {
		t.Errorf("refusal does not say what is missing: %v", err)
	}
}

// TestAForgedLogTimestampIsRefused is the check that gives certificate
// expiry any meaning at all.
//
// A keyless signing certificate lives about ten minutes and is held against
// the moment the log recorded the signature. If that moment were taken from
// the bundle unchecked, whoever wrote the bundle would choose it, and a
// certificate that can be checked against any moment has no expiry. Each
// time below is inside the fixture certificate's ten-minute life and is not
// the time the log actually recorded.
func TestAForgedLogTimestampIsRefused(t *testing.T) {
	bundle, root := loadFixtures(t)

	for _, forged := range []int64{1740770292, 1740770591, 1740770890} {
		edited := mutateBundle(t, bundle, func(b map[string]any) {
			firstTlogEntry(t, b)["integratedTime"] = forged
		})
		got, err := Verify(edited, fixtureArtifact, root, fixtureIdentity())
		if err == nil {
			t.Errorf("a log entry redated to %s verified, and reported that date as %s",
				time.Unix(forged, 0).UTC(), got.IntegratedTime)
			continue
		}
		if !strings.Contains(err.Error(), "did not sign this entry as stated") {
			t.Errorf("refusal for %d does not point at the log's signature: %v", forged, err)
		}
	}
}

// TestAForgedLogIndexIsRefused covers the number an incident responder
// follows. It is reported in the result, so an unchecked one would send
// somebody to look up an entry of the attacker's choosing. It is a
// different number from the one the inclusion proof uses, so the proof does
// not cover it.
func TestAForgedLogIndexIsRefused(t *testing.T) {
	bundle, root := loadFixtures(t)
	edited := mutateBundle(t, bundle, func(b map[string]any) {
		firstTlogEntry(t, b)["logIndex"] = "999999999"
	})

	got, err := Verify(edited, fixtureArtifact, root, fixtureIdentity())
	if err == nil {
		t.Fatalf("a relabelled log index verified, reported as entry %d", got.LogIndex)
	}
}

// TestACertificateNamingItsHolderTwiceIsRefused. Only one name can be
// checked against a policy, so a certificate carrying two lets a signer put
// an allowed identity where the check looks and their real one beside it.
// Refusing is the only answer that does not have to choose.
func TestACertificateNamingItsHolderTwiceIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name   string
		emails []string
		uris   []string
	}{
		{"two addresses", []string{"allowed@example.com", "real@evil.example"}, nil},
		{"an address and a URI", []string{"allowed@example.com"}, []string{"https://evil.example/who"}},
		{"neither", nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert := certWithSANs(t, tc.emails, tc.uris)
			if _, _, err := certIdentity(cert); err == nil {
				t.Fatal("a certificate with an ambiguous holder was read")
			}
		})
	}

	// The control: one name is read, so the refusals above are about the
	// count and not about the certificate being unreadable.
	subject, issuer, err := certIdentity(certWithSANs(t, []string{"one@example.com"}, nil))
	if err != nil {
		t.Fatalf("a certificate naming its holder once was refused: %v", err)
	}
	if subject != "one@example.com" || issuer != "https://issuer.example" {
		t.Errorf("read %q via %q, want the certificate's own values", subject, issuer)
	}
}
