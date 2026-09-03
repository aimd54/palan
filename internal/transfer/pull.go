// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package transfer

import (
	"context"
	"errors"
	"fmt"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sync/errgroup"
	oras "oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/aimd54/palan/internal/signing"
	"github.com/aimd54/palan/internal/store"
)

// Events carries optional progress callbacks. All fields may be nil.
// Callbacks must be safe for concurrent use: blobs transfer in parallel.
type Events struct {
	// OnBlobStart announces a starting blob transfer. resumeOffset > 0 means
	// a partial download is being continued from that byte offset. The
	// returned function (may be nil) receives byte-count deltas as the blob
	// streams.
	OnBlobStart func(desc ocispec.Descriptor, resumeOffset int64) func(delta int64)
	// OnBlobSkip reports content skipped because the destination has it.
	OnBlobSkip func(desc ocispec.Descriptor)
	// OnSignature reports whether a cosign signature travelled with the
	// artifact. False with a nil problem means the registry held none, which
	// is not an error; a non-nil problem means the lookup itself failed and
	// the model was kept anyway.
	OnSignature func(stored bool, problem error)
	// OnAttestation reports whether a source attestation travelled with the
	// artifact, read the same way as OnSignature: false with a nil problem
	// means the registry held none, and a non-nil problem means the lookup
	// or the copy failed while the model itself was kept. Without this the
	// two outcomes are indistinguishable, and an artifact whose provenance
	// was lost to an outage looks exactly like one that never had any.
	OnAttestation func(stored bool, problem error)
	// OnBundle reports whether a keyless signature travelled with the
	// artifact, read the same way as OnSignature. A keyless signature is
	// the only material a disconnected host can check such a signature
	// with, so one lost in transit turns a verifiable model into an
	// unverifiable one, and that has to be said rather than inferred.
	OnBundle func(stored bool, problem error)
}

func (e Events) blobStart(desc ocispec.Descriptor, resumeOffset int64) func(int64) {
	if e.OnBlobStart == nil {
		return nil
	}
	return e.OnBlobStart(desc, resumeOffset)
}

func (e Events) bundle(stored bool, problem error) {
	if e.OnBundle != nil {
		e.OnBundle(stored, problem)
	}
}

func (e Events) blobSkip(desc ocispec.Descriptor) {
	if e.OnBlobSkip != nil {
		e.OnBlobSkip(desc)
	}
}

func (e Events) signature(stored bool, problem error) {
	if e.OnSignature != nil {
		e.OnSignature(stored, problem)
	}
}

func (e Events) attestation(stored bool, problem error) {
	if e.OnAttestation != nil {
		e.OnAttestation(stored, problem)
	}
}

// Pull fetches ref from its registry into the local store and tags it with
// the fully-qualified reference. Large leaf blobs download concurrently with
// cross-restart resume; manifests, config, and tagging go through oras.Copy,
// which skips everything already present.
func (c *Client) Pull(ctx context.Context, st *store.Store, ref registry.Reference, ev Events) (ocispec.Descriptor, error) {
	repo, err := c.Repository(ref)
	if err != nil {
		return ocispec.Descriptor{}, err
	}

	root, err := repo.Resolve(ctx, ref.Reference)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("resolving %s: %w", ref, err)
	}

	leaves, err := collectLeafBlobs(ctx, repo, root)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("walking manifest graph for %s: %w", ref, err)
	}

	ingest, err := st.IngestDir()
	if err != nil {
		return ocispec.Descriptor{}, err
	}

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(c.concurrency())
	for _, desc := range leaves {
		g.Go(func() error {
			exists, err := st.OCI().Exists(gctx, desc)
			if err != nil {
				return err
			}
			if exists {
				ev.blobSkip(desc)
				return nil
			}
			return c.downloadBlob(gctx, repo, ref, desc, st, ingest, ev)
		})
	}
	if err := g.Wait(); err != nil {
		return ocispec.Descriptor{}, err
	}

	copyOpts := oras.CopyOptions{
		CopyGraphOptions: oras.CopyGraphOptions{Concurrency: c.concurrency()},
	}
	desc, err := oras.Copy(ctx, repo, ref.Reference, st.OCI(), ref.String(), copyOpts)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("copying %s into local store: %w", ref, err)
	}

	// A signature is supplementary: the model is already here and verified by
	// digest. Registries differ on what they answer for a tag that is absent
	// or not visible, and some say 401 or 403 rather than 404, so treating
	// anything but a clean miss as fatal would fail ordinary pulls of unsigned
	// models against those registries.
	stored, problem := fetchSignature(ctx, repo, st, ref, desc.Digest)
	ev.signature(stored, problem)

	// An attestation is supplementary the same way: most artifacts carry
	// none, and a lookup failure here must not undo a pull that already
	// succeeded. It is still reported, because a failure that goes unsaid
	// leaves a model whose provenance was lost looking like one that never
	// carried any.
	attested, attProblem := fetchAttestation(ctx, repo, st, ref, desc.Digest)
	ev.attestation(attested, attProblem)

	// A keyless signature travels the same way and for the same reason,
	// independently of whether either of the others exists.
	bundled, bundleProblem := fetchBundles(ctx, repo, st, ref, desc)
	ev.bundle(bundled, bundleProblem)
	return desc, nil
}

// fetchSignature brings a model's cosign signature into the store alongside
// it, so the pair can later be exported together and verified with no
// registry in reach. Signatures are a manifest and a small payload, so they
// go through a plain copy rather than the resumable path built for weights.
//
// An unsigned artifact is the normal case, not a failure: a missing signature
// tag reports false and leaves the pull successful.
func fetchSignature(ctx context.Context, repo *remote.Repository, st *store.Store, ref registry.Reference, d digest.Digest) (bool, error) {
	sigTag := signing.SigTag(d)
	if _, err := repo.Resolve(ctx, sigTag); err != nil {
		if errors.Is(err, errdef.ErrNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("looking for a signature on %s: %w", ref, err)
	}
	if _, err := oras.Copy(ctx, repo, sigTag, st.OCI(), signing.SigRef(ref, d), oras.DefaultCopyOptions); err != nil {
		return false, fmt.Errorf("copying the signature for %s: %w", ref, err)
	}
	return true, nil
}

// fetchAttestation brings a model's source attestation into the store
// alongside it, the same way fetchSignature brings its signature: a plain
// copy of a manifest and a small payload, not the resumable path built for
// weights.
//
// An artifact with no attestation is the normal case, not a failure: a
// missing attestation tag reports false and leaves the pull successful.
func fetchAttestation(ctx context.Context, repo *remote.Repository, st *store.Store, ref registry.Reference, d digest.Digest) (bool, error) {
	attTag := signing.AttTag(d)
	if _, err := repo.Resolve(ctx, attTag); err != nil {
		if errors.Is(err, errdef.ErrNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("looking for an attestation on %s: %w", ref, err)
	}
	if _, err := oras.Copy(ctx, repo, attTag, st.OCI(), signing.AttRef(ref, d), oras.DefaultCopyOptions); err != nil {
		return false, fmt.Errorf("copying the attestation for %s: %w", ref, err)
	}
	return true, nil
}

// fetchBundle brings a model's keyless signature into the store alongside
// it, so it can later be exported and checked with no registry in reach.
//
// Unlike a signature or an attestation, a bundle carries no tag of its own:
// the tools that write one attach it as a referrer and nothing else. It is
// therefore found by asking the registry what refers to the model, and
// given palan's own tag on the way in, because the store names what it
// holds and save and load move content by name.
//
// An artifact with no keyless signature is the normal case, not a failure.
func fetchBundles(ctx context.Context, repo *remote.Repository, st *store.Store, ref registry.Reference, target ocispec.Descriptor) (bool, error) {
	bundles, err := signing.BundleReferrers(ctx, repo, target)
	if err != nil {
		return false, fmt.Errorf("looking for a keyless signature on %s: %w", ref, err)
	}
	if len(bundles) == 0 {
		return false, nil
	}
	// All of them. An artifact may carry more than one, and whoever can
	// push to the repository can add another, so carrying only the first
	// would let that person decide which signature reaches the far side.
	for _, b := range bundles {
		// Copied by digest, since a referrer has no tag to copy from, and
		// named after itself so that two of them do not collide.
		if _, err := oras.Copy(ctx, repo, b.Digest.String(), st.OCI(),
			signing.BundleRef(ref, b.Digest), oras.DefaultCopyOptions); err != nil {
			return false, fmt.Errorf("copying a keyless signature for %s: %w", ref, err)
		}
	}
	return true, nil
}

// manifestMediaTypes are the media types treated as graph-interior nodes.
func isManifestMediaType(mt string) bool {
	switch mt {
	case ocispec.MediaTypeImageManifest,
		ocispec.MediaTypeImageIndex,
		"application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.docker.distribution.manifest.list.v2+json":
		return true
	}
	return false
}

// collectLeafBlobs walks the manifest graph breadth-first and returns the
// non-manifest descriptors (config plus layers).
func collectLeafBlobs(ctx context.Context, fetcher content.Fetcher, root ocispec.Descriptor) ([]ocispec.Descriptor, error) {
	var leaves []ocispec.Descriptor
	seen := map[string]bool{}
	queue := []ocispec.Descriptor{root}
	for len(queue) > 0 {
		d := queue[0]
		queue = queue[1:]
		if seen[d.Digest.String()] {
			continue
		}
		seen[d.Digest.String()] = true
		if !isManifestMediaType(d.MediaType) {
			leaves = append(leaves, d)
			continue
		}
		succ, err := content.Successors(ctx, fetcher, d)
		if err != nil {
			return nil, err
		}
		queue = append(queue, succ...)
	}
	return leaves, nil
}
