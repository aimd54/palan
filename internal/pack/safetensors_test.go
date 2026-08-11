// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package pack

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aimd54/palan/internal/safetensors"
	"github.com/aimd54/palan/internal/safetensors/safetensorstest"
	"github.com/aimd54/palan/internal/store"
	"github.com/aimd54/palan/pkg/modelspec"
)

// Fixture shards carry one BF16 tensor whose payload dwarfs the header, so a
// declared total taken from the tensor bytes alone stays clearly below the
// size of the files that hold them, as it does for a published model.
const (
	fixtureDim         = 128
	fixtureTensorBytes = fixtureDim * fixtureDim * 2
)

// writeShardedModel materializes an n-shard safetensors model with a config
// and an index that names every shard.
func writeShardedModel(t *testing.T, dir string, n int) []string {
	t.Helper()
	cfg := `{"model_type":"llama","max_position_embeddings":4096,"torch_dtype":"bfloat16"}`
	if err := os.WriteFile(filepath.Join(dir, safetensors.ConfigName), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	weightMap := map[string]string{}
	paths := []string{}
	for i := 1; i <= n; i++ {
		name := fmt.Sprintf("model-%05d-of-%05d.safetensors", i, n)
		body := safetensorstest.Shard(
			safetensorstest.Tensor{
				Name:  fmt.Sprintf("t%d", i),
				DType: "BF16",
				Shape: []int64{fixtureDim, fixtureDim},
			})
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, body, 0o600); err != nil {
			t.Fatal(err)
		}
		weightMap[fmt.Sprintf("t%d", i)] = name
		paths = append(paths, p)
	}
	// total_size counts tensor bytes, not file bytes: each shard adds its own
	// header on top of the figure the index publishes.
	ix, err := json.Marshal(map[string]any{
		"metadata":   map[string]any{"total_size": n * fixtureTensorBytes},
		"weight_map": weightMap,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, safetensors.IndexName), ix, 0o600); err != nil {
		t.Fatal(err)
	}
	return paths
}

func TestShardedModelGathersEveryShardAndItsConfig(t *testing.T) {
	dir := t.TempDir()
	paths := writeShardedModel(t, dir, 3)

	// Naming one shard must pull in the other two, the index and the config.
	ordered, info, err := prepare([]File{{Path: paths[0]}})
	if err != nil {
		t.Fatal(err)
	}
	if info.Format != "safetensors" {
		t.Errorf("Format = %q, want safetensors", info.Format)
	}
	if info.ContextLength != 4096 {
		t.Errorf("ContextLength = %d, want 4096", info.ContextLength)
	}
	if info.Architecture != "llama" {
		t.Errorf("Architecture = %q, want llama", info.Architecture)
	}
	names := map[string]bool{}
	for _, f := range ordered {
		names[filepath.Base(f.Path)] = true
	}
	for _, want := range []string{
		"model-00001-of-00003.safetensors",
		"model-00002-of-00003.safetensors",
		"model-00003-of-00003.safetensors",
		safetensors.IndexName,
		safetensors.ConfigName,
	} {
		if !names[want] {
			t.Errorf("%s missing from the packed set; got %v", want, names)
		}
	}
}

func TestShardedModelRefusesAnIncompleteSet(t *testing.T) {
	dir := t.TempDir()
	paths := writeShardedModel(t, dir, 3)
	if err := os.Remove(paths[2]); err != nil {
		t.Fatal(err)
	}
	_, _, err := prepare([]File{{Path: paths[0]}})
	if err == nil {
		t.Fatal("prepare accepted a model whose index names a shard that is not present")
	}
	if !strings.Contains(err.Error(), "model-00003-of-00003.safetensors") {
		t.Errorf("error does not name the missing shard: %v", err)
	}
}

func TestShardedModelRefusesADeclaredSizeMismatch(t *testing.T) {
	dir := t.TempDir()
	paths := writeShardedModel(t, dir, 2)
	// Cut one shard short inside its payload: every file the index names is
	// present, the header still parses and still claims every tensor, and the
	// bytes on disk no longer add up to what the index declares.
	if err := os.Truncate(paths[1], fixtureTensorBytes/2); err != nil {
		t.Fatal(err)
	}
	_, _, err := prepare([]File{{Path: paths[0]}})
	if err == nil {
		t.Fatal("prepare accepted shards whose total size contradicts the index")
	}
}

// TestShardedModelRefusesAnIndexNamingAPathOutsideItself: the index arrives
// with the download, so its shard names are publisher-supplied text. A name
// that walks out of the model directory would otherwise be hashed, stored and
// pushed as a layer of the model.
func TestShardedModelRefusesAnIndexNamingAPathOutsideItself(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "model")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	paths := writeShardedModel(t, dir, 1)
	if err := os.WriteFile(filepath.Join(root, "secret.pem"), []byte("private key"), 0o600); err != nil {
		t.Fatal(err)
	}
	ix, err := json.Marshal(map[string]any{
		"metadata": map[string]any{"total_size": fixtureTensorBytes},
		"weight_map": map[string]string{
			"t1":     filepath.Base(paths[0]),
			"stolen": "../secret.pem",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, safetensors.IndexName), ix, 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, err = prepare([]File{{Path: paths[0]}})
	if err == nil {
		t.Fatal("prepare followed a path out of the model directory named by the index")
	}
	if !strings.Contains(err.Error(), "secret.pem") {
		t.Errorf("error does not name the rejected entry: %v", err)
	}
}

// TestStrayWeightFileLeavesTheMetadataAlone: recorded metadata must describe
// the layers the artifact carries. An adapter sitting beside a model is not
// part of it, so neither its bytes nor its parameters belong in the artifact.
func TestStrayWeightFileLeavesTheMetadataAlone(t *testing.T) {
	const wantLabel = "16.4K" // one 128x128 tensor
	dir := t.TempDir()
	paths := writeShardedModel(t, dir, 1)

	_, info, err := prepare([]File{{Path: paths[0]}})
	if err != nil {
		t.Fatal(err)
	}
	if info.SizeLabel != wantLabel {
		t.Fatalf("SizeLabel = %q for the model alone, want %q", info.SizeLabel, wantLabel)
	}

	stray := filepath.Join(dir, "adapter_model.safetensors")
	body := safetensorstest.Shard(
		safetensorstest.Tensor{Name: "adapter", DType: "F32", Shape: []int64{512, 512}})
	if err := os.WriteFile(stray, body, 0o600); err != nil {
		t.Fatal(err)
	}

	ordered, info, err := prepare([]File{{Path: paths[0]}})
	if err != nil {
		t.Fatal(err)
	}
	if info.SizeLabel != wantLabel {
		t.Errorf("SizeLabel = %q with an adapter beside the model, want %q", info.SizeLabel, wantLabel)
	}
	for _, f := range ordered {
		if filepath.Base(f.Path) == "adapter_model.safetensors" {
			t.Error("an adapter the index does not name was packed into the artifact")
		}
	}
}

// TestShardedModelRequiresItsConfig drives the gather directly: config.json
// carries the architecture and the context length, and a runtime handed the
// weights without it has nothing to build the model from.
func TestShardedModelRequiresItsConfig(t *testing.T) {
	dir := t.TempDir()
	paths := writeShardedModel(t, dir, 2)
	if err := os.Remove(filepath.Join(dir, safetensors.ConfigName)); err != nil {
		t.Fatal(err)
	}
	_, err := gatherSafetensorsShards([]File{{Path: paths[0]}})
	if err == nil {
		t.Fatal("gather accepted a safetensors model with no config.json")
	}
	if !strings.Contains(err.Error(), safetensors.ConfigName) {
		t.Errorf("error does not name the missing file: %v", err)
	}
}

// TestDirectoryInputPacksTheModelInsideIt: a safetensors model is published as
// a directory of shards rather than as a single file, so the directory is the
// name a user has for the model.
func TestDirectoryInputPacksTheModelInsideIt(t *testing.T) {
	dir := t.TempDir()
	writeShardedModel(t, dir, 3)

	ordered, info, err := prepare([]File{{Path: dir}})
	if err != nil {
		t.Fatal(err)
	}
	if info.Format != "safetensors" {
		t.Errorf("Format = %q, want safetensors", info.Format)
	}
	names := map[string]bool{}
	weights := 0
	for _, f := range ordered {
		names[filepath.Base(f.Path)] = true
		if f.Kind == modelspec.LayerKindWeight {
			weights++
		}
	}
	for _, want := range []string{
		"model-00001-of-00003.safetensors",
		"model-00002-of-00003.safetensors",
		"model-00003-of-00003.safetensors",
		safetensors.IndexName,
		safetensors.ConfigName,
	} {
		if !names[want] {
			t.Errorf("%s missing from the packed set; got %v", want, names)
		}
	}
	if weights != 3 {
		t.Errorf("packed %d weight file(s) from a 3-shard model, want 3", weights)
	}
	if len(ordered) != 5 {
		t.Errorf("packed %d file(s), want 3 shards plus the index and the config", len(ordered))
	}
}

// TestDirectoryInputPacksTheShardsTheIndexNames: the index states which shards
// the model is made of, so a second set of weights in the same directory is a
// different model. Taking every .safetensors file in the directory would pack
// an adapter into the artifact and count its tensors as the model's parameters.
func TestDirectoryInputPacksTheShardsTheIndexNames(t *testing.T) {
	const wantLabel = "32.8K" // two 128x128 tensors
	dir := t.TempDir()
	writeShardedModel(t, dir, 2)
	body := safetensorstest.Shard(
		safetensorstest.Tensor{Name: "adapter", DType: "F32", Shape: []int64{512, 512}})
	if err := os.WriteFile(filepath.Join(dir, "adapter_model.safetensors"), body, 0o600); err != nil {
		t.Fatal(err)
	}

	ordered, info, err := prepare([]File{{Path: dir}})
	if err != nil {
		t.Fatal(err)
	}
	if info.SizeLabel != wantLabel {
		t.Errorf("SizeLabel = %q, want %q for the two shards the index names", info.SizeLabel, wantLabel)
	}
	weights := []string{}
	for _, f := range ordered {
		if f.Kind == modelspec.LayerKindWeight {
			weights = append(weights, filepath.Base(f.Path))
		}
	}
	want := []string{
		"model-00001-of-00002.safetensors",
		"model-00002-of-00002.safetensors",
	}
	if !slices.Equal(weights, want) {
		t.Errorf("weight files = %v, want %v", weights, want)
	}
}

// TestDirectoryInputWithoutWeightsIsRefused: naming a directory is how a
// safetensors model is packed, so a directory holding none says so.
func TestDirectoryInputWithoutWeightsIsRefused(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "tiny.gguf"), []byte("GGUF"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := prepare([]File{{Path: dir}})
	if err == nil {
		t.Fatal("prepare accepted a directory with no safetensors shard in it")
	}
	if !strings.Contains(err.Error(), dir) {
		t.Errorf("error does not name the directory: %v", err)
	}
}

func TestSafetensorsAndGGUFCannotShareAnArtifact(t *testing.T) {
	dir := t.TempDir()
	paths := writeShardedModel(t, dir, 1)
	gg := filepath.Join(dir, "other.gguf")
	if err := os.WriteFile(gg, []byte("GGUF"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := prepare([]File{{Path: paths[0]}, {Path: gg}}); err == nil {
		t.Fatal("prepare accepted a mixed GGUF and safetensors input set")
	}
}

// TestDirectoryHoldingBothFormatsIsRefused: expanding a directory yields its
// safetensors shards, so the GGUF beside them is gone before the mixed-format
// check sees the input set. Packing the shards and leaving the GGUF out gives
// a user an artifact that is missing the file they named the directory for.
func TestDirectoryHoldingBothFormatsIsRefused(t *testing.T) {
	dir := t.TempDir()
	writeShardedModel(t, dir, 2)
	if err := os.WriteFile(filepath.Join(dir, "tiny.gguf"), []byte("GGUF"), 0o600); err != nil {
		t.Fatal(err)
	}

	ordered, _, err := prepare([]File{{Path: dir}})
	if err == nil {
		t.Fatalf("prepare packed %d file(s) from a directory holding both weight formats", len(ordered))
	}
	for _, want := range []string{dir, "GGUF", "safetensors"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not name %q: %v", want, err)
		}
	}
}

// TestSafetensorsConfigRecordsTheDtypeAsPrecision: the ModelPack config keeps
// precision and quantization apart, precision holding a numeric type such as
// bf16 and quantization a scheme such as awq. Writing bfloat16 into
// quantization describes weights that were never quantized as quantized
// everywhere the config is read: ls, describe and any other ModelPack tool.
func TestSafetensorsConfigRecordsTheDtypeAsPrecision(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	writeShardedModel(t, dir, 2)
	st := openTestStore(t)

	desc, err := Model(ctx, st, []File{{Path: dir}}, "registry.example/llm/st:v1", Options{})
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := store.FetchManifest(ctx, st.OCI(), desc)
	if err != nil {
		t.Fatal(err)
	}
	model, err := store.FetchJSON[modelspec.Model](ctx, st.OCI(), manifest.Config)
	if err != nil {
		t.Fatal(err)
	}
	if model.Config.Format != "safetensors" {
		t.Errorf("format = %q, want safetensors", model.Config.Format)
	}
	if model.Config.Precision != "bfloat16" {
		t.Errorf("precision = %q, want the dtype bfloat16", model.Config.Precision)
	}
	if model.Config.Quantization != "" {
		t.Errorf("quantization = %q, want it empty for unquantized weights", model.Config.Quantization)
	}
}

func TestModelDirectoryLicenceTravels(t *testing.T) {
	// A published model ships the licence its weights are released under. A
	// tool that redistributes the weights and drops that file hands the next
	// reader an artifact with no terms attached, so the licence and readme
	// travel as documentation layers.
	dir := t.TempDir()
	paths := writeShardedModel(t, dir, 2)
	for name, body := range map[string]string{
		"LICENSE":   "Apache License, Version 2.0\n",
		"README.md": "# a model\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	ordered, _, err := prepare([]File{{Path: paths[0]}})
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]modelspec.LayerKind{}
	for _, f := range ordered {
		kinds[filepath.Base(f.Path)] = f.Kind
	}
	for _, want := range []string{"LICENSE", "README.md"} {
		kind, ok := kinds[want]
		if !ok {
			t.Errorf("%s is beside the model and was not packed; got %v", want, kinds)
			continue
		}
		if kind != modelspec.LayerKindDoc {
			t.Errorf("%s packed as kind %v, want a documentation layer", want, kind)
		}
	}
}
