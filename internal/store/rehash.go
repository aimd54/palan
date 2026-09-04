// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
)

// RehashReport counts what Rehash actually read, so a caller can say how
// much work was done rather than only that it finished. A report of zero
// blobs alongside a nil error would mean nothing was checked, which is why
// Rehash refuses an artifact whose shape it does not understand instead of
// returning one.
type RehashReport struct {
	// Blobs is every blob read back: the manifest, its config, and each
	// layer.
	Blobs int
	// Bytes is their total size as the manifest records it, which is also
	// the number of bytes read, since a blob of the wrong length is a
	// failure rather than a shorter read.
	Bytes int64
}

// Rehash re-reads every blob an artifact is made of and holds it against
// the digest its manifest records.
//
// A signature covers a manifest and a manifest names its blobs by digest,
// so a signature that still verifies says nothing about a weight file
// replaced on disk afterwards. Reading the bytes back is the only thing
// that closes that gap. It is deliberately not part of signature
// verification: checking a signature is arithmetic over a few hundred
// bytes, while this re-reads whole weight files, so it is asked for
// separately and priced separately.
//
// Intended for a local store. Pointed at a registry it would download every
// byte of the artifact to hash it, which is a pull with the result thrown
// away.
func Rehash(ctx context.Context, fetcher content.Fetcher, desc ocispec.Descriptor) (RehashReport, error) {
	// An artifact whose shape this does not understand is refused rather
	// than walked. Decoding an index as a manifest yields no layers and no
	// error, so it would report a clean result having read nothing, which
	// is the one answer worse than a failure.
	if desc.MediaType != ocispec.MediaTypeImageManifest {
		return RehashReport{}, fmt.Errorf(
			"cannot re-read the blobs of a %s: palan knows how to walk an OCI image manifest and nothing else",
			desc.MediaType)
	}
	if desc.Size <= 0 || desc.Size > maxJSONBlobSize {
		return RehashReport{}, fmt.Errorf(
			"refusing to parse a manifest of size %d (limit %d)", desc.Size, maxJSONBlobSize)
	}
	// FetchAll verifies what it read against desc, so this is the link from
	// the digest the signature covers to the manifest text below.
	raw, err := content.FetchAll(ctx, fetcher, desc)
	if err != nil {
		return RehashReport{}, fmt.Errorf("re-reading the manifest %s: %w", desc.Digest, err)
	}
	var man ocispec.Manifest
	if err := json.Unmarshal(raw, &man); err != nil {
		return RehashReport{}, fmt.Errorf("decoding the manifest %s: %w", desc.Digest, err)
	}

	report := RehashReport{Blobs: 1, Bytes: desc.Size}
	blobs := append([]ocispec.Descriptor{man.Config}, man.Layers...)
	for _, b := range blobs {
		if err := rehashBlob(ctx, fetcher, b); err != nil {
			return RehashReport{}, err
		}
		report.Blobs++
		report.Bytes += b.Size
	}
	return report, nil
}

// rehashBlob streams one blob through a digest verifier. Streamed rather
// than read into memory because a weight layer is measured in gigabytes,
// and bounded at one byte past the recorded length so a blob that grew is
// reported as the wrong length instead of being read to its end.
func rehashBlob(ctx context.Context, fetcher content.Fetcher, desc ocispec.Descriptor) error {
	if err := desc.Digest.Validate(); err != nil {
		return fmt.Errorf("the manifest records an unusable digest for a %s blob: %w", desc.MediaType, err)
	}
	rc, err := fetcher.Fetch(ctx, desc)
	if err != nil {
		return fmt.Errorf("re-reading blob %s: %w", desc.Digest, err)
	}
	defer func() { _ = rc.Close() }()

	verifier := desc.Digest.Verifier()
	n, err := io.Copy(verifier, io.LimitReader(rc, desc.Size+1))
	if err != nil {
		return fmt.Errorf("re-reading blob %s: %w", desc.Digest, err)
	}
	if n != desc.Size {
		return fmt.Errorf(
			"blob %s holds %d bytes on this host, the manifest records %d", desc.Digest, n, desc.Size)
	}
	if !verifier.Verified() {
		return fmt.Errorf(
			"blob %s does not hash to the digest the manifest records, so these are not the bytes that were signed", desc.Digest)
	}
	return nil
}
