// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	oras "oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry"
)

// MediaTypeBundlePrefix is what every version of the Sigstore bundle media
// type begins with. Matching on the prefix rather than on one version is
// what cosign itself does, and it means a bundle written under a later
// version of the format is still found rather than silently overlooked.
const MediaTypeBundlePrefix = "application/vnd.dev.sigstore.bundle"

// ErrNoBundle marks an artifact carrying no keyless signature.
var ErrNoBundle = errors.New("no keyless signature bundle found")

// BundleTag is where palan keeps a keyless signature in its own store.
//
// A bundle arrives from a registry as a referrer with no tag of its own,
// which is how the tools that write one attach it. The local store names
// everything it holds, and pull, save and load move content by name, so a
// bundle that stayed nameless would simply not travel. The tag is palan's
// convention rather than anybody else's; the subject on the manifest is
// what other tools read, and copying preserves it.
func BundleTag(d digest.Digest) string {
	return strings.Replace(d.String(), ":", "-", 1) + ".sigstore"
}

// BundleRef returns the fully-qualified reference for a bundle on d, for
// targets holding more than one repository, the way SigRef does for a
// signature.
func BundleRef(ref registry.Reference, d digest.Digest) string {
	ref.Reference = BundleTag(d)
	return ref.String()
}

// IsBundleTag reports whether a reference names a keyless signature rather
// than a model, so listings and imports can tell them apart. It recognises
// the same reference forms IsSigTag does.
func IsBundleTag(ref string) bool {
	tag := ref
	if i := strings.LastIndex(ref, ":"); i >= 0 {
		tag = ref[i+1:]
	}
	return strings.HasPrefix(tag, "sha256-") && strings.HasSuffix(tag, ".sigstore")
}

// FetchBundle returns the keyless signature attached to target, or
// ErrNoBundle when it carries none.
//
// The tag is tried first, which is where palan's own store keeps one. Only
// then are referrers consulted, which is where a bundle written by a
// keyless signing tool actually lives: such a bundle has no tag at all, so
// reporting the artifact unsigned would be a wrong answer rather than a
// missing feature.
func FetchBundle(ctx context.Context, src oras.ReadOnlyTarget, bundleRef string, target ocispec.Descriptor) ([]byte, error) {
	desc, err := src.Resolve(ctx, bundleRef)
	switch {
	case err == nil:
		return fetchBundleBlob(ctx, src, desc)
	case !hiddenAsAbsent(err):
		return nil, fmt.Errorf("resolving bundle tag: %w", err)
	}

	bundles, err := BundleReferrers(ctx, src, target)
	if err != nil {
		return nil, err
	}
	if len(bundles) == 0 {
		return nil, fmt.Errorf("%w for %s", ErrNoBundle, target.Digest)
	}
	return fetchBundleBlob(ctx, src, bundles[0])
}

// BundleReferrers lists the keyless signatures attached to target.
//
// Referrers are listed unfiltered and then selected by media type prefix,
// because asking the registry to filter would name one version of the
// bundle format and miss every other. A source that cannot answer for
// predecessors has none to offer, which is not a verdict on the artifact.
func BundleReferrers(ctx context.Context, src oras.ReadOnlyTarget, target ocispec.Descriptor) ([]ocispec.Descriptor, error) {
	graph, ok := src.(content.ReadOnlyGraphStorage)
	if !ok {
		return nil, nil
	}
	all, err := registry.Referrers(ctx, graph, target, "")
	if err != nil {
		if hiddenAsAbsent(err) || errors.Is(err, errdef.ErrUnsupported) {
			return nil, nil
		}
		return nil, fmt.Errorf("listing referrers of %s: %w", target.Digest, err)
	}
	var out []ocispec.Descriptor
	for _, d := range all {
		if strings.HasPrefix(d.ArtifactType, MediaTypeBundlePrefix) {
			out = append(out, d)
		}
	}
	return out, nil
}

// fetchBundleBlob reads the bundle out of its manifest.
func fetchBundleBlob(ctx context.Context, src oras.ReadOnlyTarget, desc ocispec.Descriptor) ([]byte, error) {
	raw, err := content.FetchAll(ctx, src, desc)
	if err != nil {
		return nil, err
	}
	var manifest ocispec.Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("decoding bundle manifest: %w", err)
	}
	for _, layer := range manifest.Layers {
		if strings.HasPrefix(layer.MediaType, MediaTypeBundlePrefix) {
			return content.FetchAll(ctx, src, layer)
		}
	}
	return nil, fmt.Errorf("bundle manifest %s carries no %s layer", desc.Digest, MediaTypeBundlePrefix)
}
