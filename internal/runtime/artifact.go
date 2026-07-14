// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

// Package runtime distributes and supervises inference runtimes.
//
// llama-server builds travel as OCI artifacts through the same registries
// as the models (design §9.1, G8): version-pinned, air-gap friendly, and
// swappable without rebuilding palan (ADR-0003). These are palan's own
// artifacts — not ModelPack models — so they carry vnd.palan media types.
package runtime

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
	"runtime"
	"sort"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/errdef"

	"github.com/aimd54/palan/internal/store"
)

// Media types for runtime artifacts.
const (
	// ArtifactTypeRuntime identifies a palan runtime artifact manifest.
	ArtifactTypeRuntime = "application/vnd.palan.runtime.v1+json"
	// MediaTypeRuntimeConfig is the runtime config blob.
	MediaTypeRuntimeConfig = "application/vnd.palan.runtime.config.v1+json"
	// MediaTypeRuntimeFile is a raw runtime file layer (binary, library…).
	MediaTypeRuntimeFile = "application/vnd.palan.runtime.file.v1.raw"
)

// Config is the runtime artifact's config blob.
type Config struct {
	// Name of the runtime, e.g. "llama-server".
	Name string `json:"name"`
	// Build identifies the upstream build, e.g. "b4567".
	Build string `json:"build"`
	// OS/Arch in GOOS/GOARCH terms.
	OS   string `json:"os"`
	Arch string `json:"arch"`
	// Flavor distinguishes acceleration variants: cpu, cuda12, metal…
	Flavor string `json:"flavor"`
	// Entrypoint names the executable layer file.
	Entrypoint string `json:"entrypoint"`
}

// dirName is the materialization directory for a runtime version.
func (c Config) dirName() string { return c.Build + "-" + c.Flavor }

// PackFile is one file of a runtime artifact.
type PackFile struct {
	Path string // on disk
	Name string // inside the artifact; defaults to basename
}

// Pack stores runtime files as an OCI artifact tagged ref (the publisher
// side the design leaves implicit: something must produce the artifacts
// that `runtime pull` consumes).
func Pack(ctx context.Context, st *store.Store, files []PackFile, cfg Config, ref string) (ocispec.Descriptor, error) {
	if len(files) == 0 {
		return ocispec.Descriptor{}, fmt.Errorf("no runtime files")
	}
	for i := range files {
		if files[i].Name == "" {
			files[i].Name = filepath.Base(files[i].Path)
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })

	entryFound := false
	for _, f := range files {
		if f.Name == cfg.Entrypoint {
			entryFound = true
			break
		}
	}
	if cfg.Entrypoint == "" || !entryFound {
		return ocispec.Descriptor{}, fmt.Errorf("entrypoint %q is not among the packed files", cfg.Entrypoint)
	}

	layers := make([]ocispec.Descriptor, 0, len(files))
	for _, f := range files {
		desc, err := fileDescriptor(f)
		if err != nil {
			return ocispec.Descriptor{}, err
		}
		fh, err := os.Open(f.Path) // #nosec G304 -- user-supplied input path is the point of pack
		if err != nil {
			return ocispec.Descriptor{}, err
		}
		err = st.OCI().Push(ctx, desc, fh)
		_ = fh.Close()
		if err != nil && !isAlreadyExists(err) {
			return ocispec.Descriptor{}, fmt.Errorf("storing %s: %w", f.Path, err)
		}
		layers = append(layers, desc)
	}

	cfgBytes, err := json.Marshal(cfg)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	cfgDesc := content.NewDescriptorFromBytes(MediaTypeRuntimeConfig, cfgBytes)
	if err := st.OCI().Push(ctx, cfgDesc, bytesReader(cfgBytes)); err != nil && !isAlreadyExists(err) {
		return ocispec.Descriptor{}, err
	}

	manifest := ocispec.Manifest{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: ArtifactTypeRuntime,
		Config:       cfgDesc,
		Layers:       layers,
	}
	manifest.SchemaVersion = 2
	raw, err := json.Marshal(manifest)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	mDesc := content.NewDescriptorFromBytes(manifest.MediaType, raw)
	mDesc.ArtifactType = ArtifactTypeRuntime
	if err := st.OCI().Push(ctx, mDesc, bytesReader(raw)); err != nil && !isAlreadyExists(err) {
		return ocispec.Descriptor{}, err
	}
	if err := st.Tag(ctx, mDesc, ref); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("tagging %s: %w", ref, err)
	}
	return mDesc, nil
}

// Ensure materializes the runtime tagged ref from the store and returns the
// absolute path of its executable entrypoint. Materialization is atomic
// (temp dir + rename) and idempotent.
func Ensure(ctx context.Context, st *store.Store, ref string) (string, error) {
	desc, err := st.Resolve(ctx, ref)
	if err != nil {
		return "", fmt.Errorf("runtime %q not in local store (try `palan runtime pull`): %w", ref, err)
	}
	manifest, err := store.FetchManifest(ctx, st.OCI(), desc)
	if err != nil {
		return "", err
	}
	if manifest.ArtifactType != ArtifactTypeRuntime {
		return "", fmt.Errorf("%q is not a runtime artifact (artifact type %q)", ref, manifest.ArtifactType)
	}
	cfg, err := store.FetchJSON[Config](ctx, st.OCI(), manifest.Config)
	if err != nil {
		return "", err
	}
	if cfg.OS != runtime.GOOS || cfg.Arch != runtime.GOARCH {
		return "", fmt.Errorf("runtime %q targets %s/%s, this host is %s/%s", ref, cfg.OS, cfg.Arch, runtime.GOOS, runtime.GOARCH)
	}

	destDir := filepath.Join(st.Root(), "runtimes", cfg.Name, cfg.dirName())
	entry := filepath.Join(destDir, cfg.Entrypoint)
	if _, err := os.Stat(entry); err == nil {
		return entry, nil
	}

	tmpDir := destDir + ".tmp"
	if err := os.RemoveAll(tmpDir); err != nil {
		return "", err
	}
	if err := os.MkdirAll(tmpDir, 0o750); err != nil {
		return "", err
	}
	for _, l := range manifest.Layers {
		name := l.Annotations[ocispec.AnnotationTitle]
		if name == "" || name != filepath.Base(name) {
			return "", fmt.Errorf("runtime layer %s has invalid file name %q", l.Digest, name)
		}
		mode := os.FileMode(0o644)
		if name == cfg.Entrypoint {
			mode = 0o755
		}
		if err := copyBlob(st, l.Digest, filepath.Join(tmpDir, name), mode); err != nil {
			return "", err
		}
	}
	if err := os.Rename(tmpDir, destDir); err != nil {
		return "", err
	}
	return entry, nil
}

// List returns runtime artifacts in the store.
func List(ctx context.Context, st *store.Store) ([]store.Entry, error) {
	entries, err := st.List(ctx)
	if err != nil {
		return nil, err
	}
	var out []store.Entry
	for _, e := range entries {
		manifest, err := store.FetchManifest(ctx, st.OCI(), e.Descriptor)
		if err != nil {
			continue
		}
		if manifest.ArtifactType == ArtifactTypeRuntime {
			out = append(out, e)
		}
	}
	return out, nil
}

func fileDescriptor(f PackFile) (ocispec.Descriptor, error) {
	fh, err := os.Open(f.Path) // #nosec G304 -- user-supplied input path is the point of pack
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	defer func() { _ = fh.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, fh)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	return ocispec.Descriptor{
		MediaType:   MediaTypeRuntimeFile,
		Digest:      digest.NewDigest(digest.SHA256, h),
		Size:        n,
		Annotations: map[string]string{ocispec.AnnotationTitle: f.Name},
	}, nil
}

func copyBlob(st *store.Store, d digest.Digest, dest string, mode os.FileMode) error {
	src, err := st.BlobPath(d)
	if err != nil {
		return err
	}
	in, err := os.Open(src) // #nosec G304 -- digest-derived path inside the store
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode) // #nosec G304 -- dest under the store's runtimes dir
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func isAlreadyExists(err error) bool { return errors.Is(err, errdef.ErrAlreadyExists) }

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }
