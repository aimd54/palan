// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package pack

import (
	"archive/tar"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/aimd54/palan/internal/gguf/gguftest"
	"github.com/aimd54/palan/internal/store"
	"github.com/aimd54/palan/pkg/modelspec"
)

// writeFixtures materializes a tiny GGUF + template + license in dir.
func writeFixtures(t *testing.T, dir string) []File {
	t.Helper()
	ggufPath := filepath.Join(dir, "tiny-q4_k_m.gguf")
	data := gguftest.TinyModel("llama", "tiny", "15M", 2048, 15, []byte("deterministic-fake-weights"))
	if err := os.WriteFile(ggufPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	tmplPath := filepath.Join(dir, "chat_template.jinja")
	if err := os.WriteFile(tmplPath, []byte("{{ messages }}"), 0o600); err != nil {
		t.Fatal(err)
	}
	licPath := filepath.Join(dir, "LICENSE")
	if err := os.WriteFile(licPath, []byte("Apache License 2.0 text"), 0o600); err != nil {
		t.Fatal(err)
	}
	return []File{{Path: ggufPath}, {Path: tmplPath}, {Path: licPath}}
}

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

var testOpts = Options{
	SourceURL:     "https://example.com/tiny",
	ServeDefaults: &modelspec.ServeDefaults{Ctx: 2048, NGL: 99},
}

// TestModelPackDeterministic: same inputs ⇒ same manifest digest, across
// fresh stores and shuffled input order (design §7.4, M2 acceptance).
func TestModelPackDeterministic(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	files := writeFixtures(t, dir)
	shuffled := []File{files[2], files[0], files[1]}

	d1, err := Model(ctx, openTestStore(t), files, "registry.example/llm/tiny:q4", testOpts)
	if err != nil {
		t.Fatalf("pack 1: %v", err)
	}
	d2, err := Model(ctx, openTestStore(t), shuffled, "registry.example/llm/tiny:q4", testOpts)
	if err != nil {
		t.Fatalf("pack 2: %v", err)
	}
	if d1.Digest != d2.Digest {
		t.Errorf("pack is not deterministic: %s != %s", d1.Digest, d2.Digest)
	}
}

// TestModelPackShape verifies the ModelPack wire format: artifact type,
// media types, layer ordering, filepath annotations, config content, and
// palan annotations.
func TestModelPackShape(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	files := writeFixtures(t, t.TempDir())

	desc, err := Model(ctx, st, files, "registry.example/llm/tiny:q4", testOpts)
	if err != nil {
		t.Fatalf("pack: %v", err)
	}

	manifest, err := store.FetchManifest(ctx, st.OCI(), desc)
	if err != nil {
		t.Fatalf("fetch manifest: %v", err)
	}
	if manifest.ArtifactType != modelspec.ArtifactTypeModelManifest {
		t.Errorf("artifact type: %q", manifest.ArtifactType)
	}
	if manifest.Config.MediaType != modelspec.MediaTypeModelConfig {
		t.Errorf("config media type: %q", manifest.Config.MediaType)
	}

	wantLayers := []struct{ mediaType, name string }{
		{modelspec.MediaTypeModelWeightRaw, "tiny-q4_k_m.gguf"},
		{modelspec.MediaTypeModelWeightConfigRaw, "chat_template.jinja"},
		{modelspec.MediaTypeModelDocRaw, "LICENSE"},
	}
	if len(manifest.Layers) != len(wantLayers) {
		t.Fatalf("layer count %d, want %d", len(manifest.Layers), len(wantLayers))
	}
	for i, want := range wantLayers {
		l := manifest.Layers[i]
		if l.MediaType != want.mediaType || l.Annotations[modelspec.AnnotationFilepath] != want.name {
			t.Errorf("layer %d: %s %q, want %s %q", i, l.MediaType, l.Annotations[modelspec.AnnotationFilepath], want.mediaType, want.name)
		}
	}

	model, err := store.FetchJSON[modelspec.Model](ctx, st.OCI(), manifest.Config)
	if err != nil {
		t.Fatalf("fetch config: %v", err)
	}
	if model.Config.Format != "gguf" || model.Config.Quantization != "Q4_K_M" || model.Config.ParamSize != "15M" {
		t.Errorf("config fields: %+v", model.Config)
	}
	if model.Descriptor.Family != "llama" || model.Descriptor.Name != "tiny" {
		t.Errorf("descriptor fields: %+v", model.Descriptor)
	}
	if len(model.Descriptor.Licenses) != 1 || model.Descriptor.Licenses[0] != "Apache-2.0" {
		t.Errorf("license from GGUF header not applied: %+v", model.Descriptor.Licenses)
	}
	if len(model.ModelFS.DiffIDs) != 3 || model.ModelFS.DiffIDs[0] != manifest.Layers[0].Digest {
		t.Errorf("modelfs diffIDs wrong: %+v", model.ModelFS)
	}

	a := manifest.Annotations
	if a[ocispec.AnnotationSource] != "https://example.com/tiny" {
		t.Errorf("source annotation: %q", a[ocispec.AnnotationSource])
	}
	if a[modelspec.AnnotationContextLength] != "2048" {
		t.Errorf("context length annotation: %q", a[modelspec.AnnotationContextLength])
	}
	if a[modelspec.AnnotationOriginSHA256] != manifest.Layers[0].Digest.Encoded() {
		t.Errorf("origin sha256 should default to the weight digest")
	}
	sd, err := modelspec.ParseServeDefaults(a[modelspec.AnnotationServeDefaults])
	if err != nil || sd.Ctx != 2048 || sd.NGL != 99 {
		t.Errorf("serve defaults annotation: %q (%v)", a[modelspec.AnnotationServeDefaults], err)
	}
}

func TestModelPackRequiresWeights(t *testing.T) {
	dir := t.TempDir()
	lic := filepath.Join(dir, "LICENSE")
	if err := os.WriteFile(lic, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Model(context.Background(), openTestStore(t), []File{{Path: lic}}, "r.example/x:y", Options{})
	if err == nil {
		t.Error("packing without a weight file must fail")
	}
}

// TestCarDeterministicAndShaped: the car profile is a plain OCI image with
// one uncompressed tar layer, deterministic across runs, with zeroed
// timestamps and sorted models/ entries.
func TestCarDeterministicAndShaped(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	files := writeFixtures(t, dir)

	st1 := openTestStore(t)
	d1, err := Car(ctx, st1, files, "registry.example/llm/tiny:q4-car", testOpts)
	if err != nil {
		t.Fatalf("car pack 1: %v", err)
	}
	d2, err := Car(ctx, openTestStore(t), []File{files[1], files[2], files[0]}, "registry.example/llm/tiny:q4-car", testOpts)
	if err != nil {
		t.Fatalf("car pack 2: %v", err)
	}
	if d1.Digest != d2.Digest {
		t.Errorf("car pack is not deterministic: %s != %s", d1.Digest, d2.Digest)
	}

	manifest, err := store.FetchManifest(ctx, st1.OCI(), d1)
	if err != nil {
		t.Fatalf("fetch manifest: %v", err)
	}
	if manifest.ArtifactType != "" {
		t.Errorf("car manifest must be a plain image, got artifact type %q", manifest.ArtifactType)
	}
	if manifest.Config.MediaType != ocispec.MediaTypeImageConfig {
		t.Errorf("car config media type: %q", manifest.Config.MediaType)
	}
	if len(manifest.Layers) != 1 || manifest.Layers[0].MediaType != ocispec.MediaTypeImageLayer {
		t.Fatalf("car layers wrong: %+v", manifest.Layers)
	}

	var img ocispec.Image
	cfgBytes, err := io.ReadAll(mustFetch(t, st1, manifest.Config))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(cfgBytes, &img); err != nil {
		t.Fatal(err)
	}
	if img.Created != nil {
		t.Error("car image config must not contain a creation timestamp")
	}
	if len(img.RootFS.DiffIDs) != 1 || img.RootFS.DiffIDs[0] != manifest.Layers[0].Digest {
		t.Errorf("rootfs diffIDs wrong: %+v", img.RootFS)
	}

	// Walk the tar: entries in canonical order under models/, zero mtimes.
	tr := tar.NewReader(mustFetch(t, st1, manifest.Layers[0]))
	var names []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar: %v", err)
		}
		names = append(names, hdr.Name)
		if !hdr.ModTime.Equal(time.Unix(0, 0)) && !hdr.ModTime.IsZero() {
			t.Errorf("entry %s has nonzero mtime %v", hdr.Name, hdr.ModTime)
		}
	}
	want := []string{"models/", "models/tiny-q4_k_m.gguf", "models/chat_template.jinja", "models/LICENSE"}
	if len(names) != len(want) {
		t.Fatalf("tar entries: %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("tar entry %d: %s, want %s", i, names[i], want[i])
		}
	}
}

func mustFetch(t *testing.T, st *store.Store, desc ocispec.Descriptor) io.Reader {
	t.Helper()
	rc, err := st.OCI().Fetch(context.Background(), desc)
	if err != nil {
		t.Fatalf("fetch %s: %v", desc.Digest, err)
	}
	t.Cleanup(func() { _ = rc.Close() })
	return rc
}
