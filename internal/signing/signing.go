// Copyright The moci Authors
// SPDX-License-Identifier: Apache-2.0

// Package signing implements cosign-compatible, key-based signing of model
// artifacts (design §11). Signatures use cosign's simple-signing payload
// and tag convention (sha256-<digest>.sig in the same repository), so
// `cosign verify --key` accepts moci signatures and vice versa — and
// verification works fully offline, which the air gap requires. Keyless
// (Fulcio/Rekor) signing is deliberately out of scope for v0.1: it needs
// online transparency infrastructure.
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
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry/remote"
)

// Cosign wire constants.
const (
	// MediaTypeSimpleSigning is the payload layer media type.
	MediaTypeSimpleSigning = "application/vnd.dev.cosign.simplesigning.v1+json"
	// AnnotationSignature carries the base64 signature on the payload layer.
	AnnotationSignature = "dev.cosignproject.cosign/signature"
)

// ErrNoSignature marks an unsigned artifact.
var ErrNoSignature = errors.New("no signature found")

// SigTag returns cosign's signature tag for a subject digest.
func SigTag(d digest.Digest) string {
	return strings.Replace(d.String(), ":", "-", 1) + ".sig"
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

// Sign signs the target digest and pushes the signature next to it using
// the cosign tag convention.
func Sign(ctx context.Context, repo *remote.Repository, repoRef string, target digest.Digest, signer signature.Signer) (ocispec.Descriptor, error) {
	pl, err := buildPayload(repoRef, target)
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
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    cfgDesc,
		Layers:    []ocispec.Descriptor{plDesc},
	}
	manifest.SchemaVersion = 2
	raw, err := json.Marshal(manifest)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	mDesc := content.NewDescriptorFromBytes(manifest.MediaType, raw)
	if err = repo.Manifests().PushReference(ctx, mDesc, bytes.NewReader(raw), SigTag(target)); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("pushing signature manifest: %w", err)
	}
	return mDesc, nil
}

// Verify checks that at least one signature on target verifies with the
// given key and binds exactly this digest (cosign semantics). The
// docker-reference claim is compared against repoRef and mismatches are
// rejected: a signature for someone else's repository must not validate.
func Verify(ctx context.Context, repo *remote.Repository, repoRef string, target digest.Digest, verifier signature.Verifier) error {
	desc, err := repo.Resolve(ctx, SigTag(target))
	if err != nil {
		if errors.Is(err, errdef.ErrNotFound) {
			return fmt.Errorf("%w for %s", ErrNoSignature, target)
		}
		return fmt.Errorf("resolving signature tag: %w", err)
	}
	raw, err := content.FetchAll(ctx, repo.Manifests(), desc)
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
		pl, err := content.FetchAll(ctx, repo.Blobs(), layer)
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
