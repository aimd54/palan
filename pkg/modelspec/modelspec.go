// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

// Package modelspec is palan's single point of contact with the CNCF
// ModelPack specification (github.com/modelpack/model-spec).
//
// It re-exports the upstream spec types and media types — pinned via go.mod
// so a spec bump is an explicit, reviewable event — and adds the palan-specific
// annotation keys, which per the design (docs/design/oci-llm-distribution.md
// §7.1) are the only sanctioned extension point: custom needs go in
// annotations, never in new media types.
//
// Nothing else in palan may import the upstream spec module directly; this
// package is the isolation layer that keeps ModelPack drift contained
// (ADR-0005).
package modelspec

import (
	specv1 "github.com/modelpack/model-spec/specs-go/v1"
)

// Artifact and media types, re-exported from the pinned ModelPack spec.
const (
	// ArtifactTypeModelManifest identifies a ModelPack model manifest.
	ArtifactTypeModelManifest = specv1.ArtifactTypeModelManifest

	// MediaTypeModelConfig is the media type of the model config blob.
	MediaTypeModelConfig = specv1.MediaTypeModelConfig

	// Raw (unarchived, uncompressed) layer media types. palan packs GGUF
	// weights raw: the blob in the local store is the file llama-server
	// mmaps — no unpack step, no double storage.
	MediaTypeModelWeightRaw       = specv1.MediaTypeModelWeightRaw
	MediaTypeModelWeightConfigRaw = specv1.MediaTypeModelWeightConfigRaw
	MediaTypeModelDocRaw          = specv1.MediaTypeModelDocRaw
	MediaTypeModelCodeRaw         = specv1.MediaTypeModelCodeRaw
	MediaTypeModelDatasetRaw      = specv1.MediaTypeModelDatasetRaw

	// Tar-based variants (produced by other ModelPack tools; palan reads
	// them for interoperability but does not produce them for weights).
	MediaTypeModelWeightTar          = specv1.MediaTypeModelWeight
	MediaTypeModelWeightGzip         = specv1.MediaTypeModelWeightGzip
	MediaTypeModelWeightZstd         = specv1.MediaTypeModelWeightZstd
	MediaTypeModelWeightConfigTar    = specv1.MediaTypeModelWeightConfig
	MediaTypeModelWeightConfigGzip   = specv1.MediaTypeModelWeightConfigGzip
	MediaTypeModelWeightConfigZstd   = specv1.MediaTypeModelWeightConfigZstd
	MediaTypeModelDocTar             = specv1.MediaTypeModelDoc
	MediaTypeModelDocGzip            = specv1.MediaTypeModelDocGzip
	MediaTypeModelDocZstd            = specv1.MediaTypeModelDocZstd
	MediaTypeModelCodeTar            = specv1.MediaTypeModelCode
	MediaTypeModelCodeGzip           = specv1.MediaTypeModelCodeGzip
	MediaTypeModelCodeZstd           = specv1.MediaTypeModelCodeZstd
	MediaTypeModelDatasetTar         = specv1.MediaTypeModelDataset
	MediaTypeModelDatasetGzip        = specv1.MediaTypeModelDatasetGzip
	MediaTypeModelDatasetZstdVariant = specv1.MediaTypeModelDatasetZstd
)

// Spec annotation keys, re-exported.
const (
	// AnnotationFilepath records the file path a layer's content should be
	// materialized at, relative to the model root.
	AnnotationFilepath = specv1.AnnotationFilepath

	// AnnotationFileMetadata carries JSON-encoded FileMetadata for a layer.
	AnnotationFileMetadata = specv1.AnnotationFileMetadata
)

// Config-blob and related types, re-exported.
type (
	// Model is the config blob (application/vnd.cncf.model.config.v1+json).
	Model = specv1.Model
	// ModelDescriptor holds general model information (family, name, licenses…).
	ModelDescriptor = specv1.ModelDescriptor
	// ModelConfig holds execution-relevant properties (format, quantization…).
	ModelConfig = specv1.ModelConfig
	// ModelFS lists layer diff IDs; for raw layers the diff ID equals the
	// layer digest.
	ModelFS = specv1.ModelFS
	// ModelCapabilities describes modalities and abilities of the model.
	ModelCapabilities = specv1.ModelCapabilities
	// Modality is an input/output type such as text, image, or embedding.
	Modality = specv1.Modality
	// FileMetadata is the value type of AnnotationFileMetadata.
	FileMetadata = specv1.FileMetadata
)

// Modalities, re-exported.
const (
	TextModality      = specv1.TextModality
	ImageModality     = specv1.ImageModality
	AudioModality     = specv1.AudioModality
	VideoModality     = specv1.VideoModality
	EmbeddingModality = specv1.EmbeddingModality
	OtherModality     = specv1.OtherModality
)

// ModelFSTypeLayers is the only valid ModelFS.Type value.
const ModelFSTypeLayers = "layers"
