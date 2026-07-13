// Copyright The moci Authors
// SPDX-License-Identifier: Apache-2.0

// Package pack builds ModelPack artifacts from GGUF files.
//
// Packing is reproducible (design §7.4): layer ordering is fixed (weights,
// then weight-configs, then docs — each sorted by artifact path), config
// and manifest JSON contain no timestamps, and identical inputs therefore
// yield identical digests on every run.
//
// Two profiles ship the same content in two envelopes (design §7.2–7.3):
// the primary "artifact" profile (raw GGUF layers, zero-copy servable from
// the store) and the secondary "car" profile (a single-tar-layer OCI image
// for Kubernetes image volumes and KServe modelcars).
package pack

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/errdef"

	"github.com/aimd54/moci/internal/gguf"
	"github.com/aimd54/moci/internal/store"
	"github.com/aimd54/moci/pkg/modelspec"
)

// File is one input to pack.
type File struct {
	// Path is the source file on disk.
	Path string
	// Name is the path recorded in the artifact (org.cncf.model.filepath);
	// defaults to the basename of Path.
	Name string
	// Kind classifies the layer; zero means auto-detect from the name.
	Kind modelspec.LayerKind
}

// Options carries pack-time metadata.
type Options struct {
	// SourceURL becomes org.opencontainers.image.source.
	SourceURL string
	// License (SPDX expression) overrides the GGUF header's general.license.
	License string
	// ServeDefaults, when non-nil, is embedded as io.moci.serve.defaults.
	ServeDefaults *modelspec.ServeDefaults
	// OriginSHA256 records the SHA-256 of the original upstream file
	// (io.moci.origin.sha256); defaults to the primary weight digest, which
	// is identical for raw packing.
	OriginSHA256 string
}

// Model packs files into st as a ModelPack artifact tagged ref and returns
// the manifest descriptor.
func Model(ctx context.Context, st *store.Store, files []File, ref string, opts Options) (ocispec.Descriptor, error) {
	ordered, info, err := prepare(files)
	if err != nil {
		return ocispec.Descriptor{}, err
	}

	// Layer descriptors: digest each file (streaming), then install.
	layers := make([]ocispec.Descriptor, 0, len(ordered))
	diffIDs := make([]digest.Digest, 0, len(ordered))
	for _, f := range ordered {
		desc, err := fileDescriptor(f)
		if err != nil {
			return ocispec.Descriptor{}, err
		}
		if err := pushFile(ctx, st, desc, f.Path); err != nil {
			return ocispec.Descriptor{}, err
		}
		layers = append(layers, desc)
		diffIDs = append(diffIDs, desc.Digest) // raw layers: diffID == digest
	}

	license := opts.License
	if license == "" {
		license = info.License
	}

	model := modelspec.Model{
		Descriptor: modelspec.ModelDescriptor{
			Family: info.Architecture,
			Name:   info.Name,
		},
		ModelFS: modelspec.ModelFS{Type: modelspec.ModelFSTypeLayers, DiffIDs: diffIDs},
		Config: modelspec.ModelConfig{
			Architecture: info.Architecture,
			Format:       "gguf",
			ParamSize:    info.SizeLabel,
			Quantization: info.Quantization,
		},
	}
	if license != "" {
		model.Descriptor.Licenses = []string{license}
	}
	if opts.SourceURL != "" {
		model.Descriptor.SourceURL = opts.SourceURL
	}
	configBytes, err := json.Marshal(model)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("encoding model config: %w", err)
	}
	configDesc := content.NewDescriptorFromBytes(modelspec.MediaTypeModelConfig, configBytes)
	if err := pushBytes(ctx, st, configDesc, configBytes); err != nil {
		return ocispec.Descriptor{}, err
	}

	annotations, err := manifestAnnotations(info, layers, opts, license)
	if err != nil {
		return ocispec.Descriptor{}, err
	}

	manifest := ocispec.Manifest{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: modelspec.ArtifactTypeModelManifest,
		Config:       configDesc,
		Layers:       layers,
		Annotations:  annotations,
	}
	manifest.SchemaVersion = 2
	return pushManifest(ctx, st, manifest, ref)
}

// prepare validates inputs, applies kind auto-detection, and returns files
// in the canonical deterministic order plus the primary weight's GGUF info.
func prepare(files []File) ([]File, *gguf.Info, error) {
	if len(files) == 0 {
		return nil, nil, fmt.Errorf("no input files")
	}
	ordered := make([]File, len(files))
	copy(ordered, files)
	for i := range ordered {
		if ordered[i].Name == "" {
			ordered[i].Name = filepath.Base(ordered[i].Path)
		}
		if ordered[i].Kind == modelspec.LayerKindUnknown {
			ordered[i].Kind = detectKind(ordered[i].Name)
		}
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].Kind != ordered[j].Kind {
			return kindRank(ordered[i].Kind) < kindRank(ordered[j].Kind)
		}
		return ordered[i].Name < ordered[j].Name
	})

	var primary *File
	for i := range ordered {
		if ordered[i].Kind == modelspec.LayerKindWeight {
			primary = &ordered[i]
			break
		}
	}
	if primary == nil {
		return nil, nil, fmt.Errorf("no weight file (.gguf) among inputs")
	}
	info, err := gguf.ReadFile(primary.Path)
	if err != nil {
		return nil, nil, fmt.Errorf("reading GGUF header: %w", err)
	}
	return ordered, info, nil
}

// manifestAnnotations assembles the manifest annotation set (design §7.2).
func manifestAnnotations(info *gguf.Info, layers []ocispec.Descriptor, opts Options, license string) (map[string]string, error) {
	a := map[string]string{}
	if opts.SourceURL != "" {
		a[ocispec.AnnotationSource] = opts.SourceURL
	}
	if license != "" {
		a[ocispec.AnnotationLicenses] = license
	}
	origin := opts.OriginSHA256
	if origin == "" {
		for _, l := range layers {
			if modelspec.KindOf(l.MediaType) == modelspec.LayerKindWeight {
				origin = l.Digest.Encoded()
				break
			}
		}
	}
	a[modelspec.AnnotationOriginSHA256] = origin
	if info.ContextLength > 0 {
		a[modelspec.AnnotationContextLength] = strconv.FormatUint(info.ContextLength, 10)
	}
	if opts.ServeDefaults != nil {
		enc, err := opts.ServeDefaults.Encode()
		if err != nil {
			return nil, err
		}
		a[modelspec.AnnotationServeDefaults] = enc
	}
	return a, nil
}

// detectKind classifies a file by name.
func detectKind(name string) modelspec.LayerKind {
	lower := strings.ToLower(name)
	base := strings.TrimSuffix(lower, filepath.Ext(lower))
	switch {
	case strings.HasSuffix(lower, ".gguf"):
		return modelspec.LayerKindWeight
	case base == "license" || base == "notice" || base == "readme" || strings.HasSuffix(lower, ".md"):
		return modelspec.LayerKindDoc
	default:
		return modelspec.LayerKindWeightConfig
	}
}

func kindRank(k modelspec.LayerKind) int {
	switch k {
	case modelspec.LayerKindWeight:
		return 0
	case modelspec.LayerKindWeightConfig:
		return 1
	case modelspec.LayerKindDoc:
		return 2
	default:
		return 3
	}
}

// rawMediaType maps a layer kind to its raw media type.
func rawMediaType(k modelspec.LayerKind) string {
	switch k {
	case modelspec.LayerKindWeight:
		return modelspec.MediaTypeModelWeightRaw
	case modelspec.LayerKindWeightConfig:
		return modelspec.MediaTypeModelWeightConfigRaw
	case modelspec.LayerKindDoc:
		return modelspec.MediaTypeModelDocRaw
	default:
		return modelspec.MediaTypeModelDocRaw
	}
}

// fileDescriptor streams the file once to compute its descriptor.
func fileDescriptor(f File) (ocispec.Descriptor, error) {
	fh, err := os.Open(f.Path) // #nosec G304 -- user-supplied input path is the point of pack
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	defer func() { _ = fh.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, fh)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("hashing %s: %w", f.Path, err)
	}
	return ocispec.Descriptor{
		MediaType:   rawMediaType(f.Kind),
		Digest:      digest.NewDigest(digest.SHA256, h),
		Size:        n,
		Annotations: map[string]string{modelspec.AnnotationFilepath: f.Name},
	}, nil
}

// pushFile installs a file's content under the precomputed descriptor.
func pushFile(ctx context.Context, st *store.Store, desc ocispec.Descriptor, path string) error {
	fh, err := os.Open(path) // #nosec G304 -- user-supplied input path is the point of pack
	if err != nil {
		return err
	}
	defer func() { _ = fh.Close() }()
	if err := st.OCI().Push(ctx, desc, fh); err != nil && !isAlreadyExists(err) {
		return fmt.Errorf("storing %s: %w", path, err)
	}
	return nil
}

func pushBytes(ctx context.Context, st *store.Store, desc ocispec.Descriptor, data []byte) error {
	if err := st.OCI().Push(ctx, desc, bytes.NewReader(data)); err != nil && !isAlreadyExists(err) {
		return fmt.Errorf("storing %s: %w", desc.MediaType, err)
	}
	return nil
}

// isAlreadyExists reports the benign content-addressed collision.
func isAlreadyExists(err error) bool {
	return errors.Is(err, errdef.ErrAlreadyExists)
}

func pushManifest(ctx context.Context, st *store.Store, manifest ocispec.Manifest, ref string) (ocispec.Descriptor, error) {
	raw, err := json.Marshal(manifest)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("encoding manifest: %w", err)
	}
	desc := content.NewDescriptorFromBytes(manifest.MediaType, raw)
	desc.ArtifactType = manifest.ArtifactType
	if err := pushBytes(ctx, st, desc, raw); err != nil {
		return ocispec.Descriptor{}, err
	}
	if err := st.Tag(ctx, desc, ref); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("tagging %s: %w", ref, err)
	}
	return desc, nil
}
