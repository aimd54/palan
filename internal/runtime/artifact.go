// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

// Package runtime distributes and supervises inference runtimes.
//
// llama-server builds travel as OCI artifacts through the same registries
// as the models (see docs/architecture.md, "Serving layer"): version-pinned,
// air-gap friendly, and swappable without rebuilding palan (ADR-0003).
// These are palan's own artifacts rather than ModelPack models, so they
// carry vnd.palan media types.
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
	"strings"

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
	// MediaTypeRuntimeFile is a raw runtime file layer (binary, library...).
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
	// Flavor distinguishes acceleration variants: cpu, cuda12, metal...
	Flavor string `json:"flavor"`
	// Entrypoint names the executable layer file.
	Entrypoint string `json:"entrypoint"`
}

// dirName is the materialization directory for a runtime version.
func (c Config) dirName() string { return c.Build + "-" + c.Flavor }

// safePathFields refuses a config whose name, build, flavor or entrypoint
// would turn into anything but a single directory or file component.
//
// These four are read out of the artifact's own config blob, which is
// written by whoever published it, and they are joined into a path that
// Ensure then removes and rewrites. Left unchecked, a name of "../.." is an
// unlink of a directory the publisher chose. filepath.Join cleans the
// traversal into a real path rather than refusing it, so the refusal has to
// happen here.
func (c Config) safePathFields() error {
	for _, f := range []struct{ kind, value string }{
		{"name", c.Name},
		{"build", c.Build},
		{"flavor", c.Flavor},
		{"entrypoint", c.Entrypoint},
	} {
		if f.value == "" {
			return fmt.Errorf("the runtime config names an empty %s", f.kind)
		}
		if f.value != filepath.Base(f.value) || f.value == "." || f.value == ".." ||
			strings.ContainsRune(f.value, '/') || strings.ContainsRune(f.value, filepath.Separator) {
			return fmt.Errorf(
				"the runtime config's %s %q is not a single path component", f.kind, f.value)
		}
	}
	return nil
}

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
	// Refused at packing time as well as at unpacking time. Otherwise a
	// publisher gets a green pack and push, and an artifact every consumer
	// refuses forever, with the traversal-bearing config already on a
	// registry for anyone running an older release to fetch.
	if err := cfg.safePathFields(); err != nil {
		return ocispec.Descriptor{}, err
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
//
// Files already unpacked are held to the digests the manifest records
// before the path is handed back. The unpacked copy is a plain file tree
// outside the content-addressed store, and the entrypoint is executable, so
// treating its presence as sufficient would mean trusting whatever last
// wrote to that path. A signature over the artifact says nothing about a
// file something else replaced afterwards, and this is the one place where
// the object being replaced is code that runs.
//
// A tree that does not match is discarded and unpacked again from the
// store, whose blobs are the checked ones. That is both the repair for an
// extraction that went wrong and the answer to one that was tampered with,
// and it restores the idempotence this function claims: the result depends
// on what the store holds, not on what is already on disk.
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
	if err := cfg.safePathFields(); err != nil {
		return "", fmt.Errorf("runtime %q: %w", ref, err)
	}
	// The entrypoint is the path handed back to be executed, so it has to
	// be one of the files this artifact actually carries rather than any
	// name its config happens to state.
	if !namesLayer(manifest, cfg.Entrypoint) {
		return "", fmt.Errorf(
			"runtime %q names entrypoint %q, which is not one of its files", ref, cfg.Entrypoint)
	}
	if err := validateLayers(manifest); err != nil {
		return "", fmt.Errorf("runtime %q: %w", ref, err)
	}

	destDir := filepath.Join(st.Root(), "runtimes", cfg.Name, cfg.dirName())
	entry := filepath.Join(destDir, cfg.Entrypoint)
	if err := materializedMatches(manifest, destDir); err == nil {
		return entry, nil
	}

	// The replacement is built whole before anything is taken away, so a
	// host whose engine merely failed a check is not left with no engine
	// at all when the unpack cannot finish.
	if err := os.MkdirAll(filepath.Dir(destDir), 0o750); err != nil {
		return "", err
	}
	// A unique staging directory rather than destDir+".tmp". That name is
	// itself a legal destination: a runtime whose flavour ends in ".tmp"
	// resolves to exactly the staging path of another one, so unpacking
	// either would delete the other's engine. A unique name also stops two
	// unpacks running at once from writing into the same place.
	tmpDir, err := os.MkdirTemp(filepath.Dir(destDir), ".unpack-")
	if err != nil {
		return "", err
	}
	// Removed on every path that does not rename it away, and a no-op once
	// it has been. MkdirTemp creates at 0700, which the materialized tree
	// inherits through the rename: it holds an executable and belongs to
	// the user whose store it is, so nothing else needs to walk into it.
	defer func() { _ = os.RemoveAll(tmpDir) }()
	for _, l := range manifest.Layers {
		name := l.Annotations[ocispec.AnnotationTitle]
		mode := os.FileMode(0o644)
		if name == cfg.Entrypoint {
			mode = 0o755
		}
		if err := copyBlob(st, l, filepath.Join(tmpDir, name), mode); err != nil {
			return "", err
		}
	}
	// Removed rather than written over. An unpacked tree carrying a file
	// the manifest does not name is as much of a problem as one whose
	// files were altered, because the dynamic loader is pointed at this
	// directory and will load a library that was added to it.
	if err := os.RemoveAll(destDir); err != nil {
		return "", err
	}
	if err := os.Rename(tmpDir, destDir); err != nil {
		return "", err
	}
	return entry, nil
}

// validateLayers refuses a manifest whose layers this cannot safely act on,
// before anything is read, written or removed.
//
// The digest check is not decoration. Building a verifier for an algorithm
// the binary does not link panics rather than returning an error, so a
// manifest naming one would take down run, serve and runtime pull with a
// stack trace instead of a refusal, and every host that already unpacked
// that build would crash on its next load.
func validateLayers(manifest ocispec.Manifest) error {
	for _, l := range manifest.Layers {
		name := l.Annotations[ocispec.AnnotationTitle]
		if name == "" || name == "." || name == ".." || name != filepath.Base(name) {
			return fmt.Errorf("layer %s has invalid file name %q", l.Digest, name)
		}
		// Validate covers both halves that matter here: a malformed digest
		// and one naming an algorithm this build does not link. The second
		// is the dangerous one, because building a verifier for it panics.
		if err := l.Digest.Validate(); err != nil {
			return fmt.Errorf("layer %q records a digest palan cannot use (%s): %w", name, l.Digest.Algorithm(), err)
		}
	}
	return nil
}

// namesLayer reports whether manifest carries a file called name.
func namesLayer(manifest ocispec.Manifest, name string) bool {
	for _, l := range manifest.Layers {
		if l.Annotations[ocispec.AnnotationTitle] == name {
			return true
		}
	}
	return false
}

// materializedMatches reports whether dir holds exactly the files manifest
// names, with exactly the bytes it records.
//
// Both halves matter. A substituted entrypoint is the obvious case; an
// added file is the quieter one, since palan points the dynamic loader at
// this directory, so a library dropped beside the binary is loaded by it.
func materializedMatches(manifest ocispec.Manifest, dir string) error {
	want := make(map[string]ocispec.Descriptor, len(manifest.Layers))
	for _, l := range manifest.Layers {
		want[l.Annotations[ocispec.AnnotationTitle]] = l
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(entries) != len(want) {
		return fmt.Errorf("%s holds %d files, the manifest names %d", dir, len(entries), len(want))
	}
	for _, e := range entries {
		l, ok := want[e.Name()]
		if !ok {
			return fmt.Errorf("%s holds %s, which the manifest does not name", dir, e.Name())
		}
		if err := fileMatches(filepath.Join(dir, e.Name()), l); err != nil {
			return err
		}
	}
	return nil
}

// fileMatches holds one unpacked file to the digest its layer records.
// Streamed, and bounded at one byte past the recorded length, so a file
// that grew is reported as the wrong length rather than read to its end.
func fileMatches(path string, desc ocispec.Descriptor) error {
	// Lstat rather than Stat, and before the open. A symlink pointing at a
	// file that holds the right bytes passes a check that follows it, and
	// is still a symlink afterwards, so whoever owns the target decides
	// what runs from then on without palan ever looking again.
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is a %s, not a regular file", path, fi.Mode().Type())
	}
	fh, err := os.OpenFile(path, os.O_RDONLY|openNoFollow, 0) // #nosec G304 -- path under the store's runtimes dir
	if err != nil {
		return err
	}
	defer func() { _ = fh.Close() }()
	verifier := desc.Digest.Verifier()
	n, err := io.Copy(verifier, io.LimitReader(fh, desc.Size+1))
	if err != nil {
		return err
	}
	if n != desc.Size {
		return fmt.Errorf("%s holds %d bytes, the manifest records %d", path, n, desc.Size)
	}
	if !verifier.Verified() {
		return fmt.Errorf("%s does not hash to the digest the manifest records", path)
	}
	return nil
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

// copyBlob writes one layer out of the store, holding the bytes to the
// digest the manifest records as they go past.
//
// A store blob is content-addressed by its file name and by nothing else:
// reading one back is a plain file open, so a blob rewritten in place is
// handed over without complaint. Verifying here is what makes the unpacked
// tree trustworthy on the path that creates it, and not only on the path
// that finds it already present.
func copyBlob(st *store.Store, desc ocispec.Descriptor, dest string, mode os.FileMode) error {
	src, err := st.BlobPath(desc.Digest)
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
	verifier := desc.Digest.Verifier()
	n, err := io.Copy(io.MultiWriter(out, verifier), io.LimitReader(in, desc.Size+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n != desc.Size {
		return fmt.Errorf("blob %s holds %d bytes in the store, the manifest records %d", desc.Digest, n, desc.Size)
	}
	if !verifier.Verified() {
		return fmt.Errorf(
			"blob %s does not hash to the digest the manifest records, so the store's copy of %s is not what was signed",
			desc.Digest, filepath.Base(dest))
	}
	return nil
}

func isAlreadyExists(err error) bool { return errors.Is(err, errdef.ErrAlreadyExists) }

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }
