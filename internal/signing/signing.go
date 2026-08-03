// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

// Package signing implements cosign-compatible, key-based signing of model
// artifacts (see docs/architecture.md, "Security model"). Signatures use
// cosign's simple-signing payload and tag convention
// (sha256-<digest>.sig in the same repository), so `cosign verify --key`
// accepts palan signatures and vice versa.
//
// Verification needs no external service: no transparency log, no certificate
// authority, and no registry once the signature sits in the local store.
// Verify reads from any oras.ReadOnlyTarget, which a remote repository and an
// on-disk OCI layout both satisfy, so the same code checks a signature in a
// registry and one carried across an air gap in a transfer bundle.
//
// Keyless (Fulcio/Rekor) signing is deliberately out of scope for v0.1: it
// needs online transparency infrastructure.
package signing

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	sigoptions "github.com/sigstore/sigstore/pkg/signature/options"
	oras "oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
)

// Cosign wire constants.
const (
	// MediaTypeSimpleSigning is the payload layer media type.
	MediaTypeSimpleSigning = "application/vnd.dev.cosign.simplesigning.v1+json"
	// AnnotationSignature carries the base64 signature on the payload layer.
	AnnotationSignature = "dev.cosignproject.cosign/signature"
	// ArtifactTypeSignature types the signature manifest for the referrers
	// API, and is the value cosign uses for the same purpose. Without it the
	// config media type stands in as the artifact type, which is the generic
	// OCI config type and tells a caller filtering referrers nothing.
	ArtifactTypeSignature = "application/vnd.dev.cosign.artifact.sig.v1+json"
)

// ErrNoSignature marks an unsigned artifact.
var ErrNoSignature = errors.New("no signature found")

// SigTag returns cosign's signature tag for a subject digest. It is the
// reference a repository-scoped target resolves, such as a remote repository.
func SigTag(d digest.Digest) string {
	return strings.Replace(d.String(), ":", "-", 1) + ".sig"
}

// SigRef returns the fully-qualified reference for a signature on d, for
// targets that hold more than one repository. The local store tags everything
// by full reference, so it needs the registry and repository too.
func SigRef(ref registry.Reference, d digest.Digest) string {
	ref.Reference = SigTag(d)
	return ref.String()
}

// IsSigTag reports whether a reference names a cosign signature rather than an
// artifact. Signatures are ordinary tagged manifests, so anything listing or
// removing store contents has to recognise them.
func IsSigTag(ref string) bool {
	tag := ref
	if i := strings.LastIndex(ref, ":"); i >= 0 {
		tag = ref[i+1:]
	}
	return strings.HasPrefix(tag, "sha256-") && strings.HasSuffix(tag, ".sig")
}

// payload is cosign's simple-signing claim document.
type payload struct {
	Critical struct {
		Identity struct {
			DockerReference string `json:"docker-reference"`
		} `json:"identity"`
		Image struct {
			DockerManifestDigest string `json:"docker-manifest-digest"`
		} `json:"image"`
		Type string `json:"type"`
	} `json:"critical"`
	Optional map[string]any `json:"optional"`
}

const payloadType = "cosign container image signature"

// buildPayload creates the canonical claim bytes for a subject.
func buildPayload(repoRef string, target digest.Digest) ([]byte, error) {
	var p payload
	p.Critical.Identity.DockerReference = repoRef
	p.Critical.Image.DockerManifestDigest = target.String()
	p.Critical.Type = payloadType
	return json.Marshal(p)
}

// Sign signs the target and pushes the signature next to it under the cosign
// tag convention, with target named as the manifest's subject so the registry
// also indexes it for the referrers API.
//
// The tag is what cosign reads and stays the form every registry supports. The
// subject is an addition: it costs one field and makes the signature visible to
// anything that discovers artifacts by referrer rather than by guessing a tag.
// oras-go maintains the referrers tag-schema index itself against a registry
// that has no referrers API, so no capability check is needed here.
func Sign(ctx context.Context, repo *remote.Repository, repoRef string, target ocispec.Descriptor, signer signature.Signer) (ocispec.Descriptor, error) {
	pl, err := buildPayload(repoRef, target.Digest)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	sig, err := signer.SignMessage(bytes.NewReader(pl), sigoptions.WithContext(ctx))
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("signing payload: %w", err)
	}

	plDesc := content.NewDescriptorFromBytes(MediaTypeSimpleSigning, pl)
	plDesc.Annotations = map[string]string{
		AnnotationSignature: base64.StdEncoding.EncodeToString(sig),
	}
	if err := push(ctx, repo, plDesc, pl); err != nil {
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
		ArtifactType: ArtifactTypeSignature,
		Config:       cfgDesc,
		Layers:       []ocispec.Descriptor{plDesc},
		Subject:      &target,
	}
	manifest.SchemaVersion = 2
	raw, err := json.Marshal(manifest)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	mDesc := content.NewDescriptorFromBytes(manifest.MediaType, raw)
	mDesc.ArtifactType = manifest.ArtifactType
	if err = repo.Manifests().PushReference(ctx, mDesc, bytes.NewReader(raw), SigTag(target.Digest)); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("pushing signature manifest: %w", err)
	}
	return mDesc, nil
}

// Verify checks that at least one signature on target verifies with the
// given key and binds exactly this digest (cosign semantics). The
// docker-reference claim is compared against repoRef and mismatches are
// rejected: a signature for someone else's repository must not validate.
//
// src supplies the signature manifest and its payload. A remote repository
// and a local OCI layout both satisfy the interface, so an air-gapped host
// verifies a bundle exactly as a connected one verifies a registry. sigRef is
// how the signature is addressed in that source: SigTag for a repository,
// SigRef for a store holding many repositories.
//
// The tag is tried first, because it is what cosign writes by default and
// what every registry supports. Only when nothing is tagged does Verify ask
// for referrers of the target, which is how a signature made by
// `cosign sign --registry-referrers-mode=oci-1-1` is stored: that signature
// has no tag at all, and reporting such a model unsigned would be a wrong
// answer rather than a missing feature.
func Verify(ctx context.Context, src oras.ReadOnlyTarget, sigRef, repoRef string, target ocispec.Descriptor, verifier signature.Verifier) error {
	desc, err := src.Resolve(ctx, sigRef)
	switch {
	case err == nil:
		return verifyManifest(ctx, src, desc, repoRef, target.Digest, verifier)
	case !errors.Is(err, errdef.ErrNotFound):
		return fmt.Errorf("resolving signature tag: %w", err)
	}

	sigs, err := referrers(ctx, src, target)
	if err != nil {
		return err
	}
	lastErr := fmt.Errorf("%w for %s", ErrNoSignature, target.Digest)
	for _, sig := range sigs {
		if err := verifyManifest(ctx, src, sig, repoRef, target.Digest, verifier); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	return lastErr
}

// referrers lists the signature manifests attached to target. A source that
// cannot answer for predecessors is not an error: it means the tag was the
// only place a signature could have been, and it was not there.
func referrers(ctx context.Context, src oras.ReadOnlyTarget, target ocispec.Descriptor) ([]ocispec.Descriptor, error) {
	graph, ok := src.(content.ReadOnlyGraphStorage)
	if !ok {
		return nil, nil
	}
	sigs, err := registry.Referrers(ctx, graph, target, ArtifactTypeSignature)
	if err != nil {
		// Registries that predate the referrers API, and stores that hold the
		// signature but not the model it refers to, both land here. Neither is
		// a verdict on the signature.
		if errors.Is(err, errdef.ErrNotFound) || errors.Is(err, errdef.ErrUnsupported) {
			return nil, nil
		}
		return nil, fmt.Errorf("listing referrers of %s: %w", target.Digest, err)
	}
	return sigs, nil
}

// verifyManifest checks one signature manifest against the key and the
// claims it must carry. Shared by the tag and referrer paths so that a
// signature found either way is held to the same standard.
func verifyManifest(ctx context.Context, src oras.ReadOnlyTarget, desc ocispec.Descriptor, repoRef string, target digest.Digest, verifier signature.Verifier) error {
	raw, err := content.FetchAll(ctx, src, desc)
	if err != nil {
		return err
	}
	var manifest ocispec.Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return fmt.Errorf("decoding signature manifest: %w", err)
	}

	lastErr := ErrNoSignature
	for _, layer := range manifest.Layers {
		if layer.MediaType != MediaTypeSimpleSigning {
			continue
		}
		b64 := layer.Annotations[AnnotationSignature]
		if b64 == "" {
			continue
		}
		sig, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			lastErr = fmt.Errorf("malformed signature annotation: %w", err)
			continue
		}
		pl, err := content.FetchAll(ctx, src, layer)
		if err != nil {
			lastErr = err
			continue
		}
		if err := verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(pl), sigoptions.WithContext(ctx)); err != nil {
			lastErr = fmt.Errorf("signature does not verify: %w", err)
			continue
		}
		var p payload
		if err := json.Unmarshal(pl, &p); err != nil {
			lastErr = fmt.Errorf("malformed payload: %w", err)
			continue
		}
		if p.Critical.Image.DockerManifestDigest != target.String() {
			lastErr = fmt.Errorf("signature binds %s, not %s", p.Critical.Image.DockerManifestDigest, target)
			continue
		}
		if p.Critical.Identity.DockerReference != repoRef {
			lastErr = fmt.Errorf("signature identity is %q, expected %q", p.Critical.Identity.DockerReference, repoRef)
			continue
		}
		return nil // one valid signature suffices
	}
	return lastErr
}

func push(ctx context.Context, repo *remote.Repository, desc ocispec.Descriptor, data []byte) error {
	err := repo.Blobs().Push(ctx, desc, bytes.NewReader(data))
	if err != nil && !errors.Is(err, errdef.ErrAlreadyExists) {
		return fmt.Errorf("pushing %s: %w", desc.MediaType, err)
	}
	return nil
}

// LoadVerifier builds a verifier from a PEM public key (cosign.pub format).
func LoadVerifier(pemBytes []byte) (signature.Verifier, error) {
	pub, err := cryptoutils.UnmarshalPEMToPublicKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}
	return signature.LoadVerifier(pub, crypto.SHA256)
}
