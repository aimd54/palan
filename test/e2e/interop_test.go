// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package e2e

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/aimd54/palan/internal/safetensors"
	"github.com/aimd54/palan/internal/safetensors/safetensorstest"
	"github.com/aimd54/palan/pkg/modelspec"
)

// TestOrasInterop: the G2 contract in the oras direction. A palan-packed
// artifact must be a plain, spec-compliant OCI artifact for generic tools,
// and a ModelPack artifact produced by oras must be pullable by palan.
func TestOrasInterop(t *testing.T) {
	oras := requireTool(t, "oras")
	host := registryHost(t)
	fx := writeFixtures(t, 256<<10)
	ref := host + "/llm/interop-oras:q4"

	home := t.TempDir()
	packOut := palan(t, home, "pack", fx.ggufPath, fx.licPath, "-t", ref)
	packedDigest := firstDigest(t, packOut)
	palan(t, home, "push", ref)

	// oras must fetch the exact manifest bytes palan pushed.
	manifest := run(t, oras, "manifest", "fetch", "--plain-http", ref)
	sum := sha256.Sum256([]byte(manifest))
	if got := "sha256:" + hex.EncodeToString(sum[:]); got != packedDigest {
		t.Errorf("oras-fetched manifest digest %s, want %s", got, packedDigest)
	}
	var m struct {
		ArtifactType string `json:"artifactType"`
	}
	if err := json.Unmarshal([]byte(manifest), &m); err != nil || m.ArtifactType != modelspec.ArtifactTypeModelManifest {
		t.Errorf("artifactType via oras: %q (%v)", m.ArtifactType, err)
	}

	// Foreign producer: push a ModelPack artifact with oras, pull with palan.
	workDir := t.TempDir()
	cfg := `{"descriptor":{"name":"oras-made"},"modelfs":{"type":"layers","diffIds":[]},"config":{"format":"gguf"}}`
	if err := os.WriteFile(filepath.Join(workDir, "config.json"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "tiny.gguf"), fx.ggufBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	orasRef := host + "/llm/oras-made:v1"
	cmd := exec.Command(oras, "push", "--plain-http",
		"--artifact-type", modelspec.ArtifactTypeModelManifest,
		"--config", "config.json:"+modelspec.MediaTypeModelConfig,
		orasRef,
		"tiny.gguf:"+modelspec.MediaTypeModelWeightRaw)
	cmd.Dir = workDir
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir())
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("oras push: %v\n%s", err, out)
	}

	homeB := t.TempDir()
	palan(t, homeB, "pull", orasRef)
	var rows []struct {
		Ref  string `json:"ref"`
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal([]byte(palan(t, homeB, "ls", "--json")), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Kind != "model" {
		t.Errorf("oras-made artifact not recognized as model: %+v", rows)
	}
}

// safetensorsShards is the shard count of the fixture model, and
// safetensorsDim sizes the one tensor each shard carries.
const (
	safetensorsShards = 3
	safetensorsDim    = 64
)

// writeSafetensorsModel materializes a sharded safetensors model the way a
// repository publishes one: a shard per file, a config, and an index naming
// every shard. It returns the model directory.
func writeSafetensorsModel(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cfg := `{"model_type":"llama","max_position_embeddings":4096,"torch_dtype":"bfloat16"}`
	if err := os.WriteFile(filepath.Join(dir, safetensors.ConfigName), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	weightMap := map[string]string{}
	for i := 1; i <= safetensorsShards; i++ {
		body := safetensorstest.Shard(safetensorstest.Tensor{
			Name:  fmt.Sprintf("t%d", i),
			DType: "BF16",
			Shape: []int64{safetensorsDim, safetensorsDim},
		})
		if err := os.WriteFile(filepath.Join(dir, safetensorsShardName(i)), body, 0o600); err != nil {
			t.Fatal(err)
		}
		weightMap[fmt.Sprintf("t%d", i)] = safetensorsShardName(i)
	}
	// total_size counts tensor bytes; each shard file adds its own header.
	ix, err := json.Marshal(map[string]any{
		"metadata":   map[string]any{"total_size": safetensorsShards * safetensorsDim * safetensorsDim * 2},
		"weight_map": weightMap,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, safetensors.IndexName), ix, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func safetensorsShardName(i int) string {
	return fmt.Sprintf("model-%05d-of-%05d.safetensors", i, safetensorsShards)
}

// TestSafetensorsOrasInterop: a safetensors model travels as the same kind of
// OCI artifact a GGUF one does (ADR-0012). oras reads the manifest and the
// config of a pushed safetensors model: the config states the format, which is
// what tells a consumer which runtime loads these weights, and every shard is
// present as a raw weight layer carrying the bytes from disk.
func TestSafetensorsOrasInterop(t *testing.T) {
	oras := requireTool(t, "oras")
	host := registryHost(t)
	modelDir := writeSafetensorsModel(t)
	ref := host + "/llm/interop-safetensors:bf16"

	home := t.TempDir()
	palan(t, home, "pack", modelDir, "-t", ref, "--license", "Apache-2.0")
	palan(t, home, "push", ref)

	var model modelspec.Model
	cfgBlob := run(t, oras, "manifest", "fetch-config", "--plain-http", ref)
	if err := json.Unmarshal([]byte(cfgBlob), &model); err != nil {
		t.Fatalf("config blob via oras: %v\n%s", err, cfgBlob)
	}
	if model.Config.Format != "safetensors" {
		t.Errorf("config format = %q, want safetensors", model.Config.Format)
	}
	if model.Config.Architecture != "llama" {
		t.Errorf("config architecture = %q, want llama", model.Config.Architecture)
	}

	var m struct {
		ArtifactType string `json:"artifactType"`
		Layers       []struct {
			MediaType   string            `json:"mediaType"`
			Digest      string            `json:"digest"`
			Annotations map[string]string `json:"annotations"`
		} `json:"layers"`
	}
	manifest := run(t, oras, "manifest", "fetch", "--plain-http", ref)
	if err := json.Unmarshal([]byte(manifest), &m); err != nil {
		t.Fatalf("manifest via oras: %v\n%s", err, manifest)
	}
	if m.ArtifactType != modelspec.ArtifactTypeModelManifest {
		t.Errorf("artifactType = %q, want %s", m.ArtifactType, modelspec.ArtifactTypeModelManifest)
	}

	type layer struct{ mediaType, digest string }
	byPath := map[string]layer{}
	for _, l := range m.Layers {
		byPath[l.Annotations[modelspec.AnnotationFilepath]] = layer{l.MediaType, l.Digest}
	}
	// Every shard is its own weight layer, holding the bytes the file holds.
	for i := 1; i <= safetensorsShards; i++ {
		name := safetensorsShardName(i)
		got, ok := byPath[name]
		if !ok {
			t.Errorf("%s is not a layer of the manifest", name)
			continue
		}
		if got.mediaType != modelspec.MediaTypeModelWeightRaw {
			t.Errorf("%s has media type %q, want %s", name, got.mediaType, modelspec.MediaTypeModelWeightRaw)
		}
		body, err := os.ReadFile(filepath.Join(modelDir, name))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(body)
		if want := "sha256:" + hex.EncodeToString(sum[:]); got.digest != want {
			t.Errorf("%s layer digest %s, want %s", name, got.digest, want)
		}
	}
	// config.json and the index describe the weights, so they travel with them.
	for _, name := range []string{safetensors.ConfigName, safetensors.IndexName} {
		got, ok := byPath[name]
		if !ok {
			t.Errorf("%s is not a layer of the manifest", name)
			continue
		}
		if got.mediaType != modelspec.MediaTypeModelWeightConfigRaw {
			t.Errorf("%s has media type %q, want %s", name, got.mediaType, modelspec.MediaTypeModelWeightConfigRaw)
		}
	}
	if want := safetensorsShards + 2; len(m.Layers) != want {
		t.Errorf("manifest carries %d layers, want %d: one per shard plus %s and %s",
			len(m.Layers), want, safetensors.ConfigName, safetensors.IndexName)
	}
}

// TestModctlInterop: modctl (the ModelPack reference implementation) must
// pull and extract a palan-packed artifact intact (M2 acceptance, ADR-0005's
// compliance oracle).
func TestModctlInterop(t *testing.T) {
	modctl := requireTool(t, "modctl")
	host := registryHost(t)
	fx := writeFixtures(t, 256<<10)
	ref := host + "/llm/interop-modctl:q4"

	home := t.TempDir()
	palan(t, home, "pack", fx.ggufPath, fx.licPath, "-t", ref)
	palan(t, home, "push", ref)

	extractDir := t.TempDir()
	run(t, modctl, "pull", "--plain-http", "--extract-from-remote", "--extract-dir", extractDir, ref)

	got, err := os.ReadFile(filepath.Join(extractDir, "tiny.gguf"))
	if err != nil {
		t.Fatalf("modctl did not extract the weight file: %v", err)
	}
	if !bytes.Equal(got, fx.ggufBytes) {
		t.Error("modctl-extracted weights differ from the original")
	}
	if _, err := os.Stat(filepath.Join(extractDir, "LICENSE")); err != nil {
		t.Errorf("modctl did not extract the license: %v", err)
	}
}
