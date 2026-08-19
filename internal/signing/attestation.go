// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	oras "oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/errcode"

	"github.com/aimd54/palan/internal/attest"
	"github.com/aimd54/palan/pkg/modelspec"
)

// ArtifactTypeAttestation types the attestation manifest for the referrers
// API. It is the DSSE envelope media type, the same value cosign uses both
// as the manifest's artifact type and as the envelope layer's media type,
// so an attestation written here is the shape cosign verify-attestation
// expects.
const ArtifactTypeAttestation = "application/vnd.dsse.envelope.v1+json"

// AttTag is where an attestation lives, following cosign's convention so the
// same object is readable by cosign verify-attestation.
func AttTag(d digest.Digest) string {
	return strings.Replace(d.String(), ":", "-", 1) + ".att"
}

// IsAttTag reports whether a reference is an attestation rather than a
// model, so listings and imports can tell them apart. It recognises the
// same reference forms IsSigTag does: a bare tag such as "sha256-<hex>.att"
// and a fully-qualified store reference such as
// "registry.example/repo:sha256-<hex>.att", since the local store tags
// everything by full reference.
func IsAttTag(ref string) bool {
	tag := ref
	if i := strings.LastIndex(ref, ":"); i >= 0 {
		tag = ref[i+1:]
	}
	return strings.HasPrefix(tag, "sha256-") && strings.HasSuffix(tag, ".att")
}

// LayersFromManifest reads the source annotations off man's layers and
// returns the attest.Layer set they describe. A layer that carries no
// source annotations, such as a file packed from local disk, contributes
// nothing: it is not a claim this package can make on that layer's behalf.
//
// io.palan.origin.sha256 holds bare hex on a layer, which is the value this
// function reads, while attest.Layer.Published needs the "sha256:"-prefixed
// form an OCI descriptor's digest holds. This is where that conversion
// happens. The same annotation key on the manifest as a whole is written
// "sha256:"-prefixed instead; that is a different annotation on a different
// object, and this function never reads it.
func LayersFromManifest(man ocispec.Manifest) []attest.Layer {
	var layers []attest.Layer
	for _, l := range man.Layers {
		repo := l.Annotations[modelspec.AnnotationSourceRepo]
		path := l.Annotations[modelspec.AnnotationSourcePath]
		if repo == "" || path == "" {
			continue
		}
		al := attest.Layer{
			Digest:   l.Digest.String(),
			Repo:     repo,
			Path:     path,
			Revision: l.Annotations[modelspec.AnnotationSourceRevision],
		}
		if origin := l.Annotations[modelspec.AnnotationOriginSHA256]; origin != "" {
			al.Published = "sha256:" + origin
		}
		layers = append(layers, al)
	}
	return layers
}

// PushAttestation stores envelope beside target, the way Sign stores a
// signature: an empty config, the envelope as the manifest's single layer,
// target named as its subject so the registry indexes it through the
// referrers API, pushed under the cosign-compatible attestation tag.
func PushAttestation(ctx context.Context, repo *remote.Repository, target ocispec.Descriptor, envelope []byte) (ocispec.Descriptor, error) {
	envDesc := content.NewDescriptorFromBytes(ArtifactTypeAttestation, envelope)
	if err := push(ctx, repo, envDesc, envelope); err != nil {
		return ocispec.Descriptor{}, err
	}

	// cosign uses an empty JSON config blob.
	cfg := []byte("{}")
	cfgDesc := content.NewDescriptorFromBytes(ocispec.MediaTypeImageConfig, cfg)
	if err := push(ctx, repo, cfgDesc, cfg); err != nil {
		return ocispec.Descriptor{}, err
	}

	manifest := ocispec.Manifest{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: ArtifactTypeAttestation,
		Config:       cfgDesc,
		Layers:       []ocispec.Descriptor{envDesc},
		Subject:      &target,
	}
	manifest.SchemaVersion = 2
	raw, err := json.Marshal(manifest)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	mDesc := content.NewDescriptorFromBytes(manifest.MediaType, raw)
	mDesc.ArtifactType = manifest.ArtifactType
	if err := repo.Manifests().PushReference(ctx, mDesc, bytes.NewReader(raw), AttTag(target.Digest)); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("pushing attestation manifest: %w", err)
	}
	return mDesc, nil
}

// FetchAttestation returns the DSSE envelope attesting to target's sources,
// or attest.ErrNoAttestation when target carries none. The tag is tried
// first, because it is what this package writes by default and what every
// registry supports; only when nothing is tagged does FetchAttestation ask
// for referrers of target, the way signature verification already falls
// back for a signature written by an OCI 1.1 tool with no tag of its own.
func FetchAttestation(ctx context.Context, src oras.ReadOnlyTarget, target ocispec.Descriptor) ([]byte, error) {
	desc, err := src.Resolve(ctx, AttTag(target.Digest))
	switch {
	case err == nil:
		return fetchEnvelope(ctx, src, desc)
	case !hiddenAsAbsent(err):
		return nil, fmt.Errorf("resolving attestation tag: %w", err)
	}

	atts, err := attestationReferrers(ctx, src, target)
	if err != nil {
		return nil, err
	}
	if len(atts) == 0 {
		return nil, fmt.Errorf("%w for %s", attest.ErrNoAttestation, target.Digest)
	}
	return fetchEnvelope(ctx, src, atts[0])
}

// hiddenAsAbsent reports whether err is the class of failure a registry
// that hides missing tags produces: it answered 401 or 403 for a tag or
// referrers index that does not exist, rather than 404. internal/transfer's
// pull path already treats an equally hidden signature tag as no reason to
// fail an otherwise-successful pull (see fetchSignature in
// internal/transfer/pull.go); FetchAttestation applies the same reading, so
// such a registry cannot turn an artifact whose signature verifies
// perfectly into a failed verification merely because it will not confirm
// the attestation tag is absent.
//
// Anything else, a genuine network failure, a server error, or an
// unexpected status, is left as a real error: an outage must not read as
// "no attestation" and pass silently.
func hiddenAsAbsent(err error) bool {
	if errors.Is(err, errdef.ErrNotFound) {
		return true
	}
	var resp *errcode.ErrorResponse
	if errors.As(err, &resp) {
		return resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden
	}
	return false
}

// attestationReferrers lists the attestation manifests attached to target. A
// source that cannot answer for predecessors is not an error: it means the
// tag was the only place an attestation could have been, and it was not
// there. A registry that hides that absence behind 401 or 403, the same way
// it may hide a missing tag, is held to the same reading.
func attestationReferrers(ctx context.Context, src oras.ReadOnlyTarget, target ocispec.Descriptor) ([]ocispec.Descriptor, error) {
	graph, ok := src.(content.ReadOnlyGraphStorage)
	if !ok {
		return nil, nil
	}
	atts, err := registry.Referrers(ctx, graph, target, ArtifactTypeAttestation)
	if err != nil {
		if hiddenAsAbsent(err) || errors.Is(err, errdef.ErrUnsupported) {
			return nil, nil
		}
		return nil, fmt.Errorf("listing referrers of %s: %w", target.Digest, err)
	}
	return atts, nil
}

// fetchEnvelope reads the DSSE envelope out of an attestation manifest.
func fetchEnvelope(ctx context.Context, src oras.ReadOnlyTarget, desc ocispec.Descriptor) ([]byte, error) {
	raw, err := content.FetchAll(ctx, src, desc)
	if err != nil {
		return nil, err
	}
	var manifest ocispec.Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("decoding attestation manifest: %w", err)
	}
	for _, layer := range manifest.Layers {
		if layer.MediaType != ArtifactTypeAttestation {
			continue
		}
		return content.FetchAll(ctx, src, layer)
	}
	return nil, fmt.Errorf("attestation manifest %s carries no %s layer", desc.Digest, ArtifactTypeAttestation)
}
