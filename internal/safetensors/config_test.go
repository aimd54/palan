// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package safetensors

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadConfigTakesTheFieldsPackRecords(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ConfigName)
	body := `{"model_type":"llama","architectures":["LlamaForCausalLM"],
	          "max_position_embeddings":4096,"torch_dtype":"bfloat16",
	          "hidden_size":2048}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := ReadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.ModelType != "llama" {
		t.Errorf("ModelType = %q, want llama", c.ModelType)
	}
	if c.MaxPositionEmbeddings != 4096 {
		t.Errorf("MaxPositionEmbeddings = %d, want 4096", c.MaxPositionEmbeddings)
	}
	if c.TorchDType != "bfloat16" {
		t.Errorf("TorchDType = %q, want bfloat16", c.TorchDType)
	}
}

func TestIndexListsEveryDistinctShardOnce(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, IndexName)
	body := `{"metadata":{"total_size":2048},"weight_map":{
	           "a":"model-00001-of-00002.safetensors",
	           "b":"model-00001-of-00002.safetensors",
	           "c":"model-00002-of-00002.safetensors"}}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	ix, err := ReadIndex(p)
	if err != nil {
		t.Fatal(err)
	}
	if ix.TotalSize != 2048 {
		t.Errorf("TotalSize = %d, want 2048", ix.TotalSize)
	}
	got := ix.Shards()
	want := []string{"model-00001-of-00002.safetensors", "model-00002-of-00002.safetensors"}
	if len(got) != len(want) {
		t.Fatalf("Shards() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Shards() = %v, want %v", got, want)
		}
	}
}

func TestReadIndexRejectsAnEmptyWeightMap(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, IndexName)
	if err := os.WriteFile(p, []byte(`{"metadata":{"total_size":0},"weight_map":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadIndex(p); err == nil {
		t.Fatal("ReadIndex accepted an index naming no shards")
	}
}
