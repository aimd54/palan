// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

// Package pack builds ModelPack artifacts from GGUF or safetensors weights.
// Either format's metadata lands in one modelmeta.Info record, and the model
// config carries the format for everything downstream (ADR-0012). What depends
// on the format here is the metadata readers, the gathering of the files a
// model consists of, and the refusal of an input set that mixes the two.
//
// Packing is reproducible (see docs/architecture.md, "Artifact format"):
// layer ordering is fixed (weights, then weight-configs, then docs, each
// sorted by artifact path), config and manifest JSON contain no
// timestamps, and identical inputs therefore yield identical digests on
// every run.
//
// Two profiles ship the same content in two envelopes: the primary
// "artifact" profile (raw weight layers, which a GGUF model is served from
// in place in the store) and the secondary "car" profile (a
// single-tar-layer OCI image for Kubernetes image volumes and KServe
// modelcars).
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
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/errdef"

	"github.com/aimd54/palan/internal/gguf"
	"github.com/aimd54/palan/internal/modelmeta"
	"github.com/aimd54/palan/internal/store"
	"github.com/aimd54/palan/pkg/modelspec"
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
	// OriginSHA256 is the SHA-256 the file's publisher released it under,
	// hex, no algorithm prefix. Empty for a file packed from disk, where
	// palan knows the bytes it read and nothing about where they came from.
	OriginSHA256 string
}

// Options carries pack-time metadata.
type Options struct {
	// SourceURL becomes org.opencontainers.image.source.
	SourceURL string
	// License (SPDX expression) overrides the GGUF header's general.license.
	License string
	// ServeDefaults, when non-nil, is embedded as io.palan.serve.defaults.
	ServeDefaults *modelspec.ServeDefaults
	// OriginSHA256 records the SHA-256 of the original upstream file
	// (io.palan.origin.sha256); defaults to the primary weight digest, which
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
			Format:       info.Format,
			ParamSize:    info.SizeLabel,
			Precision:    info.Precision,
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

// splitPart matches llama.cpp's multi-part naming, model-00001-of-00003.gguf.
// The name states how many parts the model has, so a set that is short of that
// count is detectable before anything is packed.
var splitPart = regexp.MustCompile(`^(.*)-(\d{5})-of-(\d{5})(\.gguf)$`)

// gatherSplitParts completes a multi-part GGUF from the directory the named
// part came from. Packing one part alone yields an artifact that carries a
// readable header, describes itself like any other model, and cannot load, so
// the siblings are collected and a part that is nowhere to be found is an
// error rather than a smaller model.
func gatherSplitParts(files []File) ([]File, error) {
	abs := func(p string) string {
		a, err := filepath.Abs(p)
		if err != nil {
			return p
		}
		return a
	}
	have := make(map[string]bool, len(files))
	for _, f := range files {
		have[abs(f.Path)] = true
	}

	out := make([]File, len(files), len(files)+4)
	copy(out, files)
	for _, f := range files {
		m := splitPart.FindStringSubmatch(filepath.Base(f.Path))
		if m == nil {
			continue
		}
		stem, total, ext := m[1], m[3], m[4]
		n, err := strconv.Atoi(total)
		if err != nil || n == 0 {
			continue
		}
		dir := filepath.Dir(f.Path)
		var missing []string
		for i := 1; i <= n; i++ {
			name := fmt.Sprintf("%s-%05d-of-%s%s", stem, i, total, ext)
			p := filepath.Join(dir, name)
			if have[abs(p)] {
				continue
			}
			if _, err := os.Stat(p); err != nil {
				missing = append(missing, name)
				continue
			}
			have[abs(p)] = true
			out = append(out, File{Path: p})
		}
		if len(missing) > 0 {
			return nil, fmt.Errorf("%s belongs to a %d-part model and %d part(s) are not in %s: %s",
				filepath.Base(f.Path), n, len(missing), dir, strings.Join(missing, ", "))
		}
	}
	return out, nil
}

// prepare validates inputs, applies kind auto-detection, and returns files
// in the canonical deterministic order plus the primary weight's metadata.
func prepare(files []File) ([]File, modelmeta.Info, error) {
	if len(files) == 0 {
		return nil, modelmeta.Info{}, fmt.Errorf("no input files")
	}

	files, err := expandDirs(files)
	if err != nil {
		return nil, modelmeta.Info{}, err
	}

	safe := hasSafetensors(files)
	gg := false
	for _, f := range files {
		if isGGUF(f.Path) {
			gg = true
			break
		}
	}
	// The model config records one format, and a runtime loads one format, so
	// an artifact that carried both would describe itself wrongly whichever it
	// claimed.
	if safe && gg {
		return nil, modelmeta.Info{}, fmt.Errorf(
			"inputs mix GGUF and safetensors; pack one weight format per artifact")
	}

	if safe {
		files, err = gatherSafetensorsShards(files)
	} else {
		files, err = gatherSplitParts(files)
	}
	if err != nil {
		return nil, modelmeta.Info{}, err
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
		return nil, modelmeta.Info{}, fmt.Errorf(
			"no weight file (.gguf or .safetensors) among inputs")
	}

	if safe {
		dir := filepath.Dir(primary.Path)
		shards := make([]string, 0, len(ordered))
		for _, f := range ordered {
			if f.Kind == modelspec.LayerKindWeight {
				shards = append(shards, f.Path)
			}
		}
		cfg, hdr, err := safetensorsMeta(dir, shards)
		if err != nil {
			return nil, modelmeta.Info{}, err
		}
		return ordered, modelmeta.FromSafetensors(cfg, hdr, filepath.Base(dir)), nil
	}

	info, err := gguf.ReadFile(primary.Path)
	if err != nil {
		return nil, modelmeta.Info{}, fmt.Errorf("reading GGUF header: %w", err)
	}
	return ordered, modelmeta.FromGGUF(info), nil
}

// manifestAnnotations assembles the manifest annotation set (see
// docs/architecture.md, "Artifact format").
func manifestAnnotations(info modelmeta.Info, layers []ocispec.Descriptor, opts Options, license string) (map[string]string, error) {
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
	case strings.HasSuffix(lower, ".gguf"), strings.HasSuffix(lower, ".safetensors"):
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
	ann := map[string]string{modelspec.AnnotationFilepath: f.Name}
	if f.OriginSHA256 != "" {
		ann[modelspec.AnnotationOriginSHA256] = f.OriginSHA256
	}
	return ocispec.Descriptor{
		MediaType:   rawMediaType(f.Kind),
		Digest:      digest.NewDigest(digest.SHA256, h),
		Size:        n,
		Annotations: ann,
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
