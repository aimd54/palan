// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	digest "github.com/opencontainers/go-digest"

	"github.com/aimd54/palan/internal/attest"
	"github.com/aimd54/palan/internal/registrytest"
)

// TestIsAttTag checks both reference forms IsSigTag already handles: a bare
// tag, and a fully-qualified store reference (registry/repo:tag), which is
// the form store.List returns and what ls, the picker, and airgap pass in.
// The two functions must not diverge on which forms they recognise.
func TestIsAttTag(t *testing.T) {
	d := digest.Digest("sha256:" + strings.Repeat("ab", 32))
	bare := AttTag(d)
	full := "reg.example/llm/tiny:" + bare
	for _, tag := range []string{bare, full} {
		if !IsAttTag(tag) {
			t.Errorf("IsAttTag(%q) = false, want true", tag)
		}
	}
	for _, notAtt := range []string{
		"reg.example/llm/tiny:q4",
		"reg.example/llm/tiny:sha256-deadbeef",                             // no .att suffix
		"reg.example/llm/tiny:sha256-" + strings.Repeat("ab", 32) + ".sig", // a signature, not an attestation
		"reg.example/att:latest",
	} {
		if IsAttTag(notAtt) {
			t.Errorf("IsAttTag(%q) = true, want false", notAtt)
		}
	}
}

// TestFetchAttestationTreatsAHiddenMissingTagAsAbsent mirrors
// TestPullSurvivesRegistryThatHidesMissingTags in internal/transfer: some
// registries answer 401 or 403 for a tag that does not exist rather than
// 404. An artifact with no attestation, resolved against such a registry,
// must still read as carrying none, the same way the pull path already
// treats an equally hidden signature tag as no reason to fail.
func TestFetchAttestationTreatsAHiddenMissingTagAsAbsent(t *testing.T) {
	ctx := context.Background()
	reg := registrytest.New(t)
	target := seedArtifact(t, reg, "llm/tiny", "q4")
	reg.SetMissingManifestStatus(http.StatusUnauthorized)

	repo := testRepo(t, reg, "llm/tiny")
	if _, err := FetchAttestation(ctx, repo, target); !errors.Is(err, attest.ErrNoAttestation) {
		t.Fatalf("err = %v, want ErrNoAttestation: a registry hiding a missing tag behind 401 must still read as absent", err)
	}
}

// TestFetchAttestationDoesNotHideAGenuineFailure: a status unrelated to a
// hidden miss is a real problem. Reporting it as ErrNoAttestation would let
// an outage pass as a clean verification of an unattested artifact.
func TestFetchAttestationDoesNotHideAGenuineFailure(t *testing.T) {
	ctx := context.Background()
	reg := registrytest.New(t)
	target := seedArtifact(t, reg, "llm/tiny", "q4")
	reg.SetMissingManifestStatus(http.StatusInternalServerError)

	repo := testRepo(t, reg, "llm/tiny")
	_, err := FetchAttestation(ctx, repo, target)
	if err == nil {
		t.Fatal("a registry error unrelated to a hidden tag must not verify as unattested")
	}
	if errors.Is(err, attest.ErrNoAttestation) {
		t.Errorf("err = %v, must not read as ErrNoAttestation: this is an outage, not an absence", err)
	}
}
