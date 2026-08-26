// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry/remote"

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
	_, err := FetchAttestation(ctx, repo, AttTag(target.Digest), target)
	if !errors.Is(err, attest.ErrNoAttestation) {
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
	_, err := FetchAttestation(ctx, repo, AttTag(target.Digest), target)
	if err == nil {
		t.Fatal("a registry error unrelated to a hidden tag must not verify as unattested")
	}
	if errors.Is(err, attest.ErrNoAttestation) {
		t.Errorf("err = %v, must not read as ErrNoAttestation: this is an outage, not an absence", err)
	}
}

// TestPushAttestationAnnotatesTheEnvelopeLayer pins the two annotations an
// attestation's envelope layer carries. Without the signature key, cosign
// refuses the attestation entirely, reporting the layer as missing it,
// which was checked by removing it and watching the interop test fail.
// predicateType is not required by cosign, which reads the type from inside
// the envelope; it is pinned because cosign writes it on every attestation
// it creates and a consumer reading manifests rather than payloads has
// nothing else to filter on. Neither annotation is reachable from palan's
// own read path, which finds the layer by media type, so nothing but a
// check here or the interop test catches their removal.
func TestPushAttestationAnnotatesTheEnvelopeLayer(t *testing.T) {
	ctx := context.Background()
	reg := registrytest.New(t)
	repo := testRepo(t, reg, "llm/tiny")

	cfg := []byte("{}")
	reg.PutBlob("llm/tiny", cfg)
	subjectRaw := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}`)
	subject := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageManifest,
		Digest:    reg.PutManifest("llm/tiny", "v1", ocispec.MediaTypeImageManifest, subjectRaw),
		Size:      int64(len(subjectRaw)),
	}

	envelope := []byte(`{"payloadType":"application/vnd.in-toto+json","payload":"e30=","signatures":[]}`)
	if _, err := PushAttestation(ctx, repo, subject, envelope); err != nil {
		t.Fatalf("PushAttestation: %v", err)
	}

	raw, err := content.FetchAll(ctx, repo, mustResolve(t, repo, AttTag(subject.Digest)))
	if err != nil {
		t.Fatal(err)
	}
	var man ocispec.Manifest
	if err := json.Unmarshal(raw, &man); err != nil {
		t.Fatal(err)
	}
	if len(man.Layers) != 1 {
		t.Fatalf("attestation manifest carries %d layers, want exactly the envelope", len(man.Layers))
	}
	ann := man.Layers[0].Annotations
	sig, ok := ann[AnnotationSignature]
	if !ok {
		t.Errorf("the envelope layer carries no %s annotation, so cosign refuses the attestation", AnnotationSignature)
	}

	if sig != "" {
		t.Errorf("%s = %q, want empty: a DSSE envelope carries its own signatures", AnnotationSignature, sig)
	}
	if got := ann[AnnotationPredicateType]; got != attest.PredicateType {
		t.Errorf("%s = %q, want %q", AnnotationPredicateType, got, attest.PredicateType)
	}
}

// mustResolve resolves ref or fails the test.
func mustResolve(t *testing.T, repo *remote.Repository, ref string) ocispec.Descriptor {
	t.Helper()
	desc, err := repo.Resolve(context.Background(), ref)
	if err != nil {
		t.Fatalf("resolving %s: %v", ref, err)
	}
	return desc
}
