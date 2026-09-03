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

// ErrReferrersUnavailable marks a source that cannot say what refers to an
// artifact, as opposed to one saying that nothing does.
//
// The two are worth telling apart. Keyless signatures are found only by
// asking that question, so a source unable to answer it leaves an artifact
// looking unsigned when it may be signed, and a copy made from such a
// source arrives without the one thing that would let it be verified
// later. Reported rather than treated as an absence, so that the answer to
// "did the signature travel" is never silently "there was none".
var ErrReferrersUnavailable = errors.New("cannot list what refers to this artifact")

// BundleTag is the name palan gives a keyless signature inside its own
// store, derived from the bundle's own digest rather than the artifact's.
//
// A bundle arrives from a registry as a referrer with no tag of its own,
// which is how the tools that write one attach it. The local store names
// everything it holds, and pull, save and load move content by name, so a
// bundle that stayed nameless would not travel.
//
// The name is derived from the bundle and not from what it signs because an
// artifact may carry more than one, which is ordinary during a rotation and
// is also what somebody with push access does to shadow the real one.
// Naming them after the artifact would give them all the same name, and
// only one would survive.
//
// Nothing is ever discovered by this name. Discovery asks what refers to
// the artifact, so a tag anybody can create decides nothing.
func BundleTag(d digest.Digest) string {
	return strings.Replace(d.String(), ":", "-", 1) + ".sigstore"
}

// BundleRef returns the fully-qualified reference for the bundle whose own
// digest is d, for targets holding more than one repository, the way SigRef
// does for a signature.
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

// FetchBundles returns every keyless signature attached to target, or
// ErrNoBundle when it carries none.
//
// All of them, not the first. An artifact may legitimately carry more than
// one, and anybody who can push to the repository can attach another, so
// taking whichever the registry happens to list first would let that person
// decide which signature is checked. Checking them all means the worst they
// can do is add one that fails.
func FetchBundles(ctx context.Context, src oras.ReadOnlyTarget, target ocispec.Descriptor) ([][]byte, error) {
	descs, err := BundleReferrers(ctx, src, target)
	if err != nil {
		return nil, err
	}
	if len(descs) == 0 {
		return nil, fmt.Errorf("%w for %s", ErrNoBundle, target.Digest)
	}
	out := make([][]byte, 0, len(descs))
	for _, d := range descs {
		blob, err := fetchBundleBlob(ctx, src, d)
		if err != nil {
			// One unreadable bundle does not make the others unreadable,
			// and refusing here would let a malformed attachment hide a
			// good signature.
			continue
		}
		out = append(out, blob)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w for %s that could be read", ErrNoBundle, target.Digest)
	}
	return out, nil
}

// BundleReferrers lists the keyless signatures attached to target.
//
// Referrers are listed unfiltered and then selected by media type prefix,
// because asking the registry to filter would name one version of the
// bundle format and miss every other.
//
// A source that cannot answer the question returns ErrReferrersUnavailable
// rather than an empty list. Answering "none" for a source that does not
// know is how a signed artifact comes to look unsigned, and how a copy
// comes to be made without the material that would verify it.
func BundleReferrers(ctx context.Context, src oras.ReadOnlyTarget, target ocispec.Descriptor) ([]ocispec.Descriptor, error) {
	graph, ok := src.(content.ReadOnlyGraphStorage)
	if !ok {
		return nil, fmt.Errorf("%w: it keeps no record of predecessors", ErrReferrersUnavailable)
	}
	all, err := registry.Referrers(ctx, graph, target, "")
	if err != nil {
		if hiddenAsAbsent(err) || errors.Is(err, errdef.ErrUnsupported) {
			return nil, fmt.Errorf("%w: %w", ErrReferrersUnavailable, err)
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
