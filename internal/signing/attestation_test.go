// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/aimd54/palan/internal/attest"
	"github.com/aimd54/palan/internal/registrytest"
)

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
