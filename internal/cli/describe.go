// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"

	"github.com/aimd54/palan/internal/store"
	"github.com/aimd54/palan/pkg/modelspec"
)

// modelRow is one listing entry, shared by local and remote ls.
type modelRow struct {
	Ref    string `json:"ref"`
	Kind   string `json:"kind"`
	Family string `json:"family,omitempty"`
	Params string `json:"params,omitempty"`
	Quant  string `json:"quantization,omitempty"`
	Format string `json:"format,omitempty"`
	Size   int64  `json:"size"`
	Digest string `json:"digest"`
}

// describeRef builds a listing row by reading the manifest and, for
// ModelPack artifacts, the small config blob (design §7.2: metadata
// questions are answered without touching weights).
func describeRef(ctx context.Context, fetcher content.Fetcher, ref string, desc ocispec.Descriptor) modelRow {
	row := modelRow{Ref: ref, Kind: "unknown", Digest: desc.Digest.String()}

	manifest, err := store.FetchManifest(ctx, fetcher, desc)
	if err != nil {
		return row
	}
	for _, l := range manifest.Layers {
		row.Size += l.Size
	}

	switch {
	case manifest.ArtifactType == modelspec.ArtifactTypeModelManifest ||
		manifest.Config.MediaType == modelspec.MediaTypeModelConfig:
		row.Kind = "model"
		model, err := store.FetchJSON[modelspec.Model](ctx, fetcher, manifest.Config)
		if err != nil {
			return row
		}
		row.Family = model.Descriptor.Family
		row.Params = model.Config.ParamSize
		row.Quant = model.Config.Quantization
		row.Format = model.Config.Format

	case manifest.Config.MediaType == ocispec.MediaTypeImageConfig:
		row.Kind = "image"

	case manifest.ArtifactType != "":
		row.Kind = shortArtifactType(manifest.ArtifactType)
	}
	return row
}

// shortArtifactType compacts a vnd media type for display.
func shortArtifactType(t string) string {
	t = strings.TrimPrefix(t, "application/vnd.")
	if i := strings.IndexByte(t, '+'); i > 0 {
		t = t[:i]
	}
	return t
}
