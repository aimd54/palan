// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aimd54/palan/internal/gguf/gguftest"
	"github.com/aimd54/palan/internal/pack"
	"github.com/aimd54/palan/internal/safetensors"
	"github.com/aimd54/palan/internal/safetensors/safetensorstest"
	"github.com/aimd54/palan/internal/store"
)

// Fixture shards carry one BF16 tensor whose payload dwarfs the header,
// mirroring internal/pack/safetensors_test.go.
const (
	fixtureDim         = 128
	fixtureTensorBytes = fixtureDim * fixtureDim * 2
)

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// writeShardedModelForServing materializes an n-shard safetensors model with
// a config and an index naming every shard. It mirrors writeShardedModel in
// internal/pack/safetensors_test.go: packing is what turns these files into
// the artifact loadModelInfo is asked to serve.
func writeShardedModelForServing(t *testing.T, dir string, n int) []string {
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

// writeSplitSetForServing materializes n parts of a split GGUF and returns
// their paths in order. It mirrors writeSplitSet in
// internal/pack/split_test.go: only part one carries a readable header,
// which is what llama.cpp does and what makes a lone first part look
// packable.
func writeSplitSetForServing(t *testing.T, dir string, n int) []string {
	t.Helper()
	paths := make([]string, 0, n)
	for i := 1; i <= n; i++ {
		name := filepath.Join(dir, fmt.Sprintf("tiny-%05d-of-%05d.gguf", i, n))
		data := gguftest.TinyModel("llama", "tiny", "15M", 2048, 15,
			[]byte(strings.Repeat("w", i*8)))
		if err := os.WriteFile(name, data, 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, name)
	}
	return paths
}

func TestServingRefusesASafetensorsArtifact(t *testing.T) {
	// Build a safetensors artifact, then ask the serving path to load it.
	// It must refuse, and the message must name the format so the reader is
	// not left looking for a flag.
	ctx := context.Background()
	dir := t.TempDir()
	paths := writeShardedModelForServing(t, dir, 2) // helper mirrors pack's fixture
	st := newTestStore(t)
	desc, err := pack.Model(ctx, st, []pack.File{{Path: paths[0]}}, "llm/st:v1", pack.Options{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = loadModelInfo(ctx, st, "llm/st:v1", desc)
	if err == nil {
		t.Fatal("loadModelInfo accepted a safetensors artifact; llama.cpp cannot load one")
	}
	if !strings.Contains(err.Error(), "safetensors") {
		t.Errorf("error does not name the format: %v", err)
	}
}

func TestServingStillAcceptsASplitGGUFModel(t *testing.T) {
	// The magic-byte check reads only the first weight layer. A split GGUF
	// carries a readable header in part one alone, so this proves the guard
	// did not break the split-model path that already worked.
	ctx := context.Background()
	dir := t.TempDir()
	paths := writeSplitSetForServing(t, dir, 3) // part 1 has the header
	st := newTestStore(t)
	desc, err := pack.Model(ctx, st, []pack.File{{Path: paths[0]}}, "llm/split:v1", pack.Options{})
	if err != nil {
		t.Fatal(err)
	}
	info, err := loadModelInfo(ctx, st, "llm/split:v1", desc)
	if err != nil {
		t.Fatalf("loadModelInfo refused a split GGUF model: %v", err)
	}
	if info.blobPath == "" {
		t.Fatal("loadModelInfo returned no weight blob path")
	}
}

func TestServingRefusesWeightsThatAreNotGGUFBytes(t *testing.T) {
	// An artifact may declare no format at all, since another tool packed it.
	// The bytes decide in that case: overwrite the GGUF magic in the store and
	// the guard must refuse rather than trust the label.
	ctx := context.Background()
	dir := t.TempDir()
	model := filepath.Join(dir, "tiny.gguf")
	if err := os.WriteFile(model, gguftest.TinyModel("llama", "tiny", "15M", 2048, 15, []byte("w")), 0o600); err != nil {
		t.Fatal(err)
	}
	st := newTestStore(t)
	desc, err := pack.Model(ctx, st, []pack.File{{Path: model}}, "llm/tiny:v1", pack.Options{})
	if err != nil {
		t.Fatal(err)
	}
	info, err := loadModelInfo(ctx, st, "llm/tiny:v1", desc)
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt the magic in place, then load again. The store writes blobs
	// read-only (content-addressed, so mutation is not supposed to happen);
	// this test is the one deliberate exception, so it reclaims write
	// permission first.
	if err := os.Chmod(info.blobPath, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(info.blobPath, os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte("XXXX"), 0); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := loadModelInfo(ctx, st, "llm/tiny:v1", desc); err == nil {
		t.Fatal("loadModelInfo accepted a weight blob that is not a GGUF file")
	}
}
