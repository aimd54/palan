// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package modelspec

import (
	"strings"
)

// LayerKind classifies a ModelPack layer by role, independent of its
// archival/compression variant.
type LayerKind int

const (
	// LayerKindUnknown marks media types this package does not recognize.
	LayerKindUnknown LayerKind = iota
	// LayerKindWeight is model weights (e.g. the GGUF file itself).
	LayerKindWeight
	// LayerKindWeightConfig is weight-adjacent configuration
	// (tokenizer.json, chat templates, …).
	LayerKindWeightConfig
	// LayerKindDoc is documentation (README, LICENSE, …).
	LayerKindDoc
	// LayerKindCode is model-related code.
	LayerKindCode
	// LayerKindDataset is dataset content.
	LayerKindDataset
)

var kindByMediaType = map[string]LayerKind{
	MediaTypeModelWeightRaw:          LayerKindWeight,
	MediaTypeModelWeightTar:          LayerKindWeight,
	MediaTypeModelWeightGzip:         LayerKindWeight,
	MediaTypeModelWeightZstd:         LayerKindWeight,
	MediaTypeModelWeightConfigRaw:    LayerKindWeightConfig,
	MediaTypeModelWeightConfigTar:    LayerKindWeightConfig,
	MediaTypeModelWeightConfigGzip:   LayerKindWeightConfig,
	MediaTypeModelWeightConfigZstd:   LayerKindWeightConfig,
	MediaTypeModelDocRaw:             LayerKindDoc,
	MediaTypeModelDocTar:             LayerKindDoc,
	MediaTypeModelDocGzip:            LayerKindDoc,
	MediaTypeModelDocZstd:            LayerKindDoc,
	MediaTypeModelCodeRaw:            LayerKindCode,
	MediaTypeModelCodeTar:            LayerKindCode,
	MediaTypeModelCodeGzip:           LayerKindCode,
	MediaTypeModelCodeZstd:           LayerKindCode,
	MediaTypeModelDatasetRaw:         LayerKindDataset,
	MediaTypeModelDatasetTar:         LayerKindDataset,
	MediaTypeModelDatasetGzip:        LayerKindDataset,
	MediaTypeModelDatasetZstdVariant: LayerKindDataset,
}

// KindOf returns the layer kind for a media type, or LayerKindUnknown.
// Classification is strict: only exact ModelPack media types are recognized.
func KindOf(mediaType string) LayerKind {
	return kindByMediaType[mediaType]
}

// IsRaw reports whether the media type is a raw (unarchived, uncompressed)
// variant, meaning the stored blob is byte-identical to the packed file.
func IsRaw(mediaType string) bool {
	return KindOf(mediaType) != LayerKindUnknown && strings.HasSuffix(mediaType, ".raw")
}
