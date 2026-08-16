// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package safetensors

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// File names a safetensors model publishes alongside its shards.
const (
	ConfigName = "config.json"
	IndexName  = "model.safetensors.index.json"
	// SingleName is the shard name used when a model is not sharded.
	SingleName = "model.safetensors"
)

// Config is the subset of a Hugging Face config.json that pack records.
type Config struct {
	ModelType             string   `json:"model_type"`
	Architectures         []string `json:"architectures"`
	MaxPositionEmbeddings uint64   `json:"max_position_embeddings"`
	TorchDType            string   `json:"torch_dtype"`
}

// ReadConfig parses a Hugging Face config.json.
func ReadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- caller-supplied model path is the point of this API
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%s: parsing config: %w", path, err)
	}
	return &c, nil
}

// Index is model.safetensors.index.json: the map from tensor name to the shard
// holding it, and the total byte size the publisher declared.
type Index struct {
	TotalSize int64
	WeightMap map[string]string
}

// ReadIndex reads the shard index at path.
func ReadIndex(path string) (*Index, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- caller-supplied model path is the point of this API
	if err != nil {
		return nil, err
	}
	ix, err := ParseIndex(b)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return ix, nil
}

// ParseIndex decodes a shard index. An index fetched over HTTP and one read
// from disk go through here alike, so the two cannot disagree about which
// shards a model consists of.
func ParseIndex(data []byte) (*Index, error) {
	var raw struct {
		Metadata struct {
			TotalSize int64 `json:"total_size"`
		} `json:"metadata"`
		WeightMap map[string]string `json:"weight_map"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing index: %w", err)
	}
	if len(raw.WeightMap) == 0 {
		return nil, fmt.Errorf("index names no shards")
	}
	return &Index{TotalSize: raw.Metadata.TotalSize, WeightMap: raw.WeightMap}, nil
}

// Shards returns each distinct shard file the index requires, sorted.
func (ix *Index) Shards() []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(ix.WeightMap))
	for _, shard := range ix.WeightMap {
		if seen[shard] {
			continue
		}
		seen[shard] = true
		out = append(out, shard)
	}
	sort.Strings(out)
	return out
}
