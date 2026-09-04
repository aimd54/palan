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
//
// The table is checked against Validate rather than through Verify. A
// pattern that leaves the authority open does not happen to match the
// fixture's own signer, so verification would refuse it either way and the
// test would pass whether the guard existed or not.
func TestAnIdentityMatchingEverythingIsRefused(t *testing.T) {
	// The bare wildcards are what somebody tries first. The rest are what
	// they write next when the first is refused, and every one of them
	// leaves the authority open, so a signer chooses their own.
	//
	// The workflow shapes are the ones that matter. Anchoring on the
	// workflow file and wildcarding the organisation is the ordinary way
	// to write a keyless identity, and under a provider every repository
	// on a forge shares it admits any repository with a file of that name.
	for _, subject := range []string{
		"*", "**", "*@*", "**@**", "*.*", "https://*", "*@*.*",
		"*/.github/workflows/release.yml@refs/tags/*",
		"*/.gitlab-ci.yml@*",
		"*@example.com*",
		"https://*.example.com/org/repo/*",
		"https://*/org/repo/*",
		"*.github/workflows/ci.yaml@*",
		// A wildcard inside the domain with no dot after it does not
		// anchor a domain, it extends one: this matches an address at
		// "evilexample.com".
		"*@*example.com",
		"*@ex*ample.com",
		// A pattern that names no domain at all.
		"*@",
		"*@*.",
		// A literal tail after a wildcarded organisation. The refusal for
		// the "@refs/tags/*" form above says to end on a literal domain,
		// and this is what somebody writes next: the git ref then reads
		// as a pinned domain while the host is wildcarded away.
		"*/.github/workflows/release.yml@refs/tags/v1.0.0",
		"*@refs/heads/main",
		"*@refs/tags/v1",
		// A path before the "@" with a real domain after it. The domain
		// is genuinely pinned, and the pattern still describes a path
		// rather than an address, so calling it one is a misreading.
		"*/workflows/release.yml@example.com",
		// A wildcard before the scheme unanchors the whole pattern, so a
		// literal host stops meaning anything.
		"*://forge.example/org/repo/*",
		"http*://forge.example/org/repo/*",
	} {
		if err := (Identity{Subject: subject, Issuer: fixtureIssuer}).Validate(); err == nil {
			t.Errorf("subject %q was accepted as a policy", subject)
		}
	}
}

// TestTheAuthorityGuardIsConsulted proves the table above is enforced where
// it matters and not merely by a function nothing calls: the same pattern
// is refused by a verification that would otherwise have succeeded.
func TestTheAuthorityGuardIsConsulted(t *testing.T) {
	bundle, root := loadFixtures(t)

	// The control: pinning the fixture signer's own domain verifies.
	if _, err := Verify(bundle, fixtureArtifact, root,
		[]Identity{{Subject: "*@soyland.com", Issuer: fixtureIssuer}}); err != nil {
		t.Fatalf("a pattern pinning the signer's domain was refused: %v", err)
	}
	// The same signer, reached by a pattern that pins no authority.
	_, err := Verify(bundle, fixtureArtifact, root,
		[]Identity{{Subject: "*@*", Issuer: fixtureIssuer}})
	if err == nil {
		t.Fatal("a pattern pinning no authority was used to verify")
	}
	if !strings.Contains(err.Error(), "wildcards the domain") {
		t.Errorf("refusal does not name the pattern's fault: %v", err)
	}
}

// TestAPatternPinningADomainIsAccepted is the other side of the guard: the
// patterns operators legitimately need must still load, or the guard just
// pushes them towards turning verification off.
func TestAPatternPinningADomainIsAccepted(t *testing.T) {
	for _, subject := range []string{
		"*@soyland.com",
		"cody@soyland.com",
		// A wildcard inside an address's domain is safe, because an
		// address has no path and matching anchors the literal tail to
		// the end of the identity.
		"*@*.soyland.com",
		// An exact subject can only match itself, so there is no
		// authority to pin. These are what an internal forge and a
		// workload identity actually look like, and refusing them pushes
		// an operator towards turning verification off.
		"spiffe://prod/ns/ci/sa/builder",
		"https://gitea/acme/repo/main",
		// A host needs no dot to be a host.
		"https://gitea/acme/repo/*",
		"https://192.168.10.4/acme/repo/*",
		// Neither an address nor a URL with a host, so there is no
		// authority to pin; being exact, it can only match itself.
		"urn:example:builder",
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
	// Asserted, because a bundle that failed to parse at all would refuse
	// too, and would prove nothing about the index being covered.
	if !strings.Contains(err.Error(), "did not sign this entry as stated") {
		t.Errorf("refusal does not point at the log's signature: %v", err)
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
			if _, _, _, err := certIdentity(cert); err == nil {
				t.Fatal("a certificate with an ambiguous holder was read")
			}
		})
	}

	// The control: one name is read, so the refusals above are about the
	// count and not about the certificate being unreadable.
	subject, issuer, kind, err := certIdentity(certWithSANs(t, []string{"one@example.com"}, nil))
	if err != nil {
		t.Fatalf("a certificate naming its holder once was refused: %v", err)
	}
	if subject != "one@example.com" || issuer != "https://issuer.example" {
		t.Errorf("read %q via %q, want the certificate's own values", subject, issuer)
	}
	if kind != subjectMail {
		t.Errorf("an email SAN was read as kind %d, want an address", kind)
	}
}

// TestNoAcceptedPatternReachesAForeignIdentity is the test the three
// previous versions of this guard needed and did not have.
//
// Each of those versions was checked against a table of patterns somebody
// thought of, and each passed while admitting a shape nobody had. The
// property the guard exists to establish is not "these particular patterns
// are refused": it is that a pattern the guard accepts cannot match an
// identity under an authority it did not name. That is what this asserts,
// by holding every accepted pattern against identities an attacker can
// actually obtain.
func TestNoAcceptedPatternReachesAForeignIdentity(t *testing.T) {
	// Identities a stranger can get for themselves. The workflow ones need
	// only a public repository and a tag; a git ref may contain "@" and
	// ".", so the last two are creatable by anyone.
	foreign := []struct {
		subject string
		kind    subjectKind
	}{
		{"https://github.com/mallory/pwn/.github/workflows/release.yml@refs/tags/v1.0.0", subjectURL},
		{"https://github.com/mallory/pwn/.github/workflows/release.yml@refs/heads/main", subjectURL},
		{"https://evil.test/mallory/repo/.github/workflows/ci.yaml@refs/tags/v1", subjectURL},
		{"https://evil.test/x/://forge.example/org/repo/y", subjectURL},
		{"https://evil.test/a@b/x.example.com", subjectURL},
		{"https://evil.test/a/x.yml@refs/tags/v1@example.com", subjectURL},
		{"mallory@evil.test", subjectMail},
		{"mallory@evilexample.com", subjectMail},
		{"mallory@example.com.evil.test", subjectMail},
	}

	// Patterns an operator would legitimately write, each with the identity
	// it was written for.
	accepted := []struct {
		pattern string
		mine    string
		kind    subjectKind
	}{
		{"*@example.com", "release@example.com", subjectMail},
		{"*@*.example.com", "release@ci.example.com", subjectMail},
		{
			"https://forge.example/org/repo/.github/workflows/release.yml@refs/tags/*",
			"https://forge.example/org/repo/.github/workflows/release.yml@refs/tags/v9.9.9",
			subjectURL,
		},
		{"https://gitea/acme/repo/*", "https://gitea/acme/repo/main", subjectURL},
		{
			"https://github.com/org/repo/.github/workflows/*",
			"https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1.0.0",
			subjectURL,
		},
		{"spiffe://prod/ns/ci/sa/builder", "spiffe://prod/ns/ci/sa/builder", subjectExact},
	}

	const issuer = "https://token.actions.githubusercontent.com"
	for _, a := range accepted {
		id := Identity{Subject: a.pattern, Issuer: issuer}
		if err := id.Validate(); err != nil {
			t.Errorf("pattern %q was refused: %v", a.pattern, err)
			continue
		}
		// The control. A guard that refused everything would satisfy the
		// property below and be useless.
		if !id.matches(a.mine, issuer, a.kind) {
			t.Errorf("pattern %q does not match the identity it was written for, %q",
				a.pattern, a.mine)
		}
		for _, f := range foreign {
			if id.matches(f.subject, issuer, f.kind) {
				t.Errorf("pattern %q reaches foreign identity %q", a.pattern, f.subject)
			}
		}
	}
}

// TestAPatternOnlyMatchesItsOwnKindOfIdentity: matching is plain text, so
// an address pattern would otherwise reach a URL that ends the right way,
// and a git ref may contain both "@" and ".".
func TestAPatternOnlyMatchesItsOwnKindOfIdentity(t *testing.T) {
	const issuer = "https://issuer.example"
	mail := Identity{Subject: "*@example.com", Issuer: issuer}

	if !mail.matches("release@example.com", issuer, subjectMail) {
		t.Fatal("an address pattern does not match an address")
	}
	if mail.matches("https://evil.test/a/x.yml@refs/tags/v1@example.com", issuer, subjectURL) {
		t.Error("an address pattern matched a URL identity")
	}

	url := Identity{Subject: "https://forge.example/org/repo/*", Issuer: issuer}
	if url.matches("nobody@forge.example/org/repo/x", issuer, subjectMail) {
		t.Error("a URL pattern matched an address identity")
	}
}

// TestABundleFormatPalanDoesNotReadIsRefused. Discovery matches the media
// type by prefix so a later version is found rather than passed over in
// silence, and the parser tolerates fields it does not know. Together
// those would let a future bundle be read under today's rules and reach a
// verdict, which is worse than saying plainly that it cannot be read yet.
func TestABundleFormatPalanDoesNotReadIsRefused(t *testing.T) {
	bundle, root := loadFixtures(t)

	for _, tc := range []struct {
		name, mediaType, want string
	}{
		{"a later version", "application/vnd.dev.sigstore.bundle.v0.4+json", "v0.4"},
		{"an older version", "application/vnd.dev.sigstore.bundle+json;version=0.2", "0.2"},
		{"none at all", "", "declares no format version"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			edited := mutateBundle(t, bundle, func(b map[string]any) {
				if tc.mediaType == "" {
					delete(b, "mediaType")
					return
				}
				b["mediaType"] = tc.mediaType
			})
			_, err := Verify(edited, fixtureArtifact, root, fixtureIdentity())
			if err == nil {
				t.Fatalf("a bundle declaring %q verified", tc.mediaType)
			}
			// The refusal has to name what it could not read, or an
			// operator has no way to tell an unsupported format from a
			// broken signature.
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("refusal does not name the format: %v", err)
			}
		})
	}
}

// TestTheSupportedFormatStillVerifies is the control: the version check
// must not be satisfied by refusing everything.
func TestTheSupportedFormatStillVerifies(t *testing.T) {
	bundle, root := loadFixtures(t)
	if _, err := Verify(bundle, fixtureArtifact, root, fixtureIdentity()); err != nil {
		t.Fatalf("the supported format was refused: %v", err)
	}
}

// TestNoPatternTheGuardAcceptsReachesAnotherAuthority generates the side
// of the property that kept going wrong.
//
// The test above holds a handful of hand-written patterns against a
// hand-written corpus of hostile identities. That is the adversary's side
// generated and the operator's side enumerated, and every defect this
// guard has had was on the enumerated side: a shape nobody thought to
// list. So this one enumerates nothing. It builds every short string over
// the characters that give an identity its structure, keeps the ones the
// guard accepts, and for each asks the only question that matters: swap
// the authority out of an identity this pattern matches, and does it still
// match?
func TestNoPatternTheGuardAcceptsReachesAnotherAuthority(t *testing.T) {
	const issuer = "https://issuer.example"
	// Built from tokens rather than characters, so that the space reaches
	// the shapes that need length. A URL pattern with a wildcarded scheme
	// and a named account is nine characters ("*://a/a/*"), which a walk
	// over single characters would have to go nine deep to produce, and
	// that space is too large to cross with identities.
	tokens := []string{"a", "*", ".", "/", "@", "://"}

	var accepted, exercised int
	var walk func(pattern string, depth int)
	walk = func(pattern string, depth int) {
		if pattern != "" && strings.Contains(pattern, "*") {
			if kind, err := classifySubject(pattern); err == nil {
				accepted++
				if checkAuthorityHolds(t, pattern, kind, issuer) {
					exercised++
				}
			}
		}
		if depth == 0 {
			return
		}
		for _, tok := range tokens {
			walk(pattern+tok, depth-1)
		}
	}
	walk("", 7)

	if accepted < 100 {
		t.Fatalf("only %d patterns were accepted, so this proves little", accepted)
	}
	if exercised < 100 {
		t.Fatalf("only %d accepted patterns matched anything, so the swap was rarely tested", exercised)
	}
	t.Logf("%d patterns accepted, %d of them matched an identity and had its authority swapped",
		accepted, exercised)
}

// checkAuthorityHolds builds an identity the pattern matches, replaces the
// authority in it, and requires the pattern to stop matching. It reports
// whether the pattern matched anything at all, so the caller can tell a
// guard that is holding from one that accepts only patterns matching
// nothing.
func checkAuthorityHolds(t *testing.T, pattern string, kind subjectKind, issuer string) bool {
	t.Helper()
	id := Identity{Subject: pattern, Issuer: issuer}
	// "z" is in no pattern, so filling wildcards with it cannot introduce
	// a "/", "@" or ":" that changes the identity's structure.
	mine := strings.ReplaceAll(pattern, "*", "z")
	if !id.matches(mine, issuer, kind) {
		return false
	}
	if theirs, ok := swapAuthority(mine, kind); ok {
		if id.matches(theirs, issuer, kind) {
			t.Errorf("pattern %q matches %q, whose authority it never named", pattern, theirs)
		}
	}

	// The account under a host is as much the authority as the host is,
	// since one provider serves every account on a shared one. Swapping
	// the host alone does not reach this: a pattern that names the host
	// and wildcards the account still refuses a swapped host, and still
	// admits every stranger under the original.
	if kind == subjectURL {
		if theirs, ok := swapAccount(mine); ok && id.matches(theirs, issuer, subjectURL) {
			t.Errorf("pattern %q matches %q, whose account it never named", pattern, theirs)
		}
	}

	// A URL's authority is at its start, so nothing may come before it.
	// Swapping the host is not enough to find this: the attack is an
	// identity that begins somewhere else and carries the pattern's
	// literal run further along, which is what an unanchored pattern
	// matches.
	if kind == subjectURL {
		for _, before := range []string{"q://evil.test/", "evil.test/", "x"} {
			if id.matches(before+mine, issuer, subjectURL) {
				t.Errorf("pattern %q matches %q, which begins at another authority",
					pattern, before+mine)
			}
		}
	}

	// And a pattern must not reach the other kind of identity at all. The
	// safety argument for an address rests on an address having no path,
	// and the argument for a URL rests on its host being anchored;
	// neither survives being applied to the other.
	other := subjectMail
	if kind == subjectMail {
		other = subjectURL
	}
	if id.matches(mine, issuer, other) {
		t.Errorf("pattern %q reaches %q read as the other kind of identity", pattern, mine)
	}
	return true
}

// swapAccount replaces the first path segment of a URL identity, which is
// the account a workload belongs to on every forge that has them.
func swapAccount(identity string) (string, bool) {
	i := strings.Index(identity, "://")
	if i < 0 {
		return "", false
	}
	rest := identity[i+len("://"):]
	j := strings.Index(rest, "/")
	if j < 0 {
		return "", false
	}
	host, path := rest[:j], rest[j+1:]
	tail := ""
	if k := strings.Index(path, "/"); k >= 0 {
		tail = path[k:]
	}
	return identity[:i+len("://")] + host + "/mallory" + tail, true
}

// swapAuthority replaces the part of an identity its holder cannot choose:
// the host of a URL, the domain of an address.
func swapAuthority(identity string, kind subjectKind) (string, bool) {
	const foreign = "evil.test"
	switch kind {
	case subjectURL:
		i := strings.Index(identity, "://")
		if i < 0 {
			return "", false
		}
		rest := identity[i+len("://"):]
		if j := strings.Index(rest, "/"); j >= 0 {
			return identity[:i+len("://")] + foreign + rest[j:], true
		}
		return identity[:i+len("://")] + foreign, true
	case subjectMail:
		i := strings.LastIndex(identity, "@")
		if i < 0 {
			return "", false
		}
		return identity[:i+1] + foreign, true
	}
	return "", false
}

// TestAForgeIsNotAPublisher covers the shape the guide already warned
// about and the code did not enforce.
//
// One OpenID provider serves every account on a public forge, so naming
// the host names a company rather than a signer. A stranger with a free
// account, a public repository, a workflow file and a tag obtains an
// identity that satisfies a host-only pattern.
func TestAForgeIsNotAPublisher(t *testing.T) {
	const issuer = "https://token.actions.githubusercontent.com"
	stranger := "https://github.com/mallory/pwn/.github/workflows/release.yml@refs/tags/v1.0.0"

	for _, pattern := range []string{
		"https://github.com/*",
		"https://github.com/*/repo/.github/workflows/release.yml@refs/tags/*",
		"https://gitlab.com/*/*/.gitlab-ci.yml@*",
	} {
		id := Identity{Subject: pattern, Issuer: issuer}
		if err := id.Validate(); err == nil {
			t.Errorf("pattern %q, which names no account, was accepted", pattern)
			if id.matches(stranger, issuer, subjectURL) {
				t.Errorf("  and it reaches %q", stranger)
			}
		}
	}

	// The control: naming the account is what the guide asks for, and it
	// must still work.
	ours := Identity{
		Subject: "https://github.com/org/repo/.github/workflows/release.yml@refs/tags/*",
		Issuer:  issuer,
	}
	if err := ours.Validate(); err != nil {
		t.Fatalf("a pattern naming host and account was refused: %v", err)
	}
	if ours.matches(stranger, issuer, subjectURL) {
		t.Error("a pattern naming another account reached the stranger")
	}
	mine := "https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v2.0.0"
	if !ours.matches(mine, issuer, subjectURL) {
		t.Errorf("the pattern does not match its own identity %q", mine)
	}
}

// TestADomainEverybodySharesIsNotADomain: "*@*.com" names every address on
// the internet that ends in .com.
func TestADomainEverybodySharesIsNotADomain(t *testing.T) {
	for _, pattern := range []string{"*@*.com", "*@*.a", "*@*.test"} {
		if err := (Identity{Subject: pattern, Issuer: "https://issuer.example"}).Validate(); err == nil {
			t.Errorf("pattern %q, which names only a shared suffix, was accepted", pattern)
		}
	}
	// Two labels is the line, so a registrable domain still works.
	for _, pattern := range []string{"*@*.example.com", "*@example.com"} {
		if err := (Identity{Subject: pattern, Issuer: "https://issuer.example"}).Validate(); err != nil {
			t.Errorf("pattern %q was refused: %v", pattern, err)
		}
	}
}
