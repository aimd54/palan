// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package safetensors

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
	ModelType             string
	Architectures         []string
	MaxPositionEmbeddings uint64
	// TorchDType is the dtype the config states, which is the one the model
	// computes in, quantized or not.
	TorchDType string
	// QuantMethod names the quantization scheme, fp8 or awq for example.
	// For a ModelOpt checkpoint it is the algorithm the toolkit ran, when the
	// config states one, and the toolkit's own name otherwise.
	QuantMethod string
}

// nestedConfigs are where a model built from more than one part keeps its
// language model's settings. They are read after the top level.
var nestedConfigs = [][]string{
	{"text_config"}, {"llm_config"}, {"language_config"}, {"thinker_config", "text_config"},
}

// configLevel is what one level of a config states. Each field reads
// leniently, since a value of an unexpected shape costs a description of the
// model rather than the import.
type configLevel struct {
	MaxPositionEmbeddings looseCount      `json:"max_position_embeddings"`
	TorchDType            looseString     `json:"torch_dtype"`
	DType                 looseString     `json:"dtype"`
	Quantization          json.RawMessage `json:"quantization_config"`
}

// ReadConfig parses a Hugging Face config.json, taking each value from the
// top level first and then from each nested config in turn.
func ReadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- caller-supplied model path is the point of this API
	if err != nil {
		return nil, err
	}
	var top struct {
		ModelType     string   `json:"model_type"`
		Architectures []string `json:"architectures"`
	}
	if err := json.Unmarshal(b, &top); err != nil {
		return nil, fmt.Errorf("%s: parsing config: %w", path, err)
	}
	levels := []configLevel{readLevel(b)}
	for _, p := range nestedConfigs {
		if raw := nested(b, p); raw != nil {
			levels = append(levels, readLevel(raw))
		}
	}

	c := &Config{ModelType: top.ModelType, Architectures: top.Architectures}
	for _, l := range levels {
		if c.MaxPositionEmbeddings == 0 {
			c.MaxPositionEmbeddings = uint64(l.MaxPositionEmbeddings)
		}
		for _, d := range []looseString{l.DType, l.TorchDType} {
			if c.TorchDType == "" {
				c.TorchDType = string(d)
			}
		}
		if c.QuantMethod == "" {
			var q struct {
				QuantMethod  looseString     `json:"quant_method"`
				QuantAlgo    looseString     `json:"quant_algo"`
				Quantization json.RawMessage `json:"quantization"`
			}
			if json.Unmarshal(l.Quantization, &q) == nil {
				var inner struct {
					QuantAlgo looseString `json:"quant_algo"`
				}
				if q.QuantAlgo == "" && json.Unmarshal(q.Quantization, &inner) == nil {
					q.QuantAlgo = inner.QuantAlgo
				}
				c.QuantMethod = scheme(string(q.QuantMethod), string(q.QuantAlgo))
			}
		}
	}
	return c, nil
}

// IsModelOpt reports whether a quant_method names NVIDIA's ModelOpt toolkit,
// modelopt or a variant such as modelopt_mixed, whatever scheme it applied.
func IsModelOpt(method string) bool {
	return strings.HasPrefix(strings.ToLower(method), "modelopt")
}

// scheme is the quantization a config names: its method, or the algorithm
// when the method is ModelOpt or absent.
func scheme(method, algo string) string {
	if algo != "" && (method == "" || IsModelOpt(method)) {
		return strings.ToLower(algo)
	}
	return method
}

// readLevel reads what one level of a config states, and nothing when it is
// not an object.
func readLevel(raw []byte) configLevel {
	var l configLevel
	if json.Unmarshal(raw, &l) != nil {
		return configLevel{}
	}
	return l
}

// nested returns the object at path within the config, or nil.
func nested(b []byte, path []string) []byte {
	cur := json.RawMessage(b)
	for _, key := range path {
		var m map[string]json.RawMessage
		if json.Unmarshal(cur, &m) != nil {
			return nil
		}
		next, ok := m[key]
		if !ok {
			return nil
		}
		cur = next
	}
	return cur
}

// looseString holds a JSON string and takes any other value as empty.
type looseString string

func (s *looseString) UnmarshalJSON(b []byte) error {
	var v string
	if json.Unmarshal(b, &v) == nil {
		*s = looseString(v)
	}
	return nil
}

// looseCount holds a whole, non-negative JSON number, written with or without
// a fraction, and takes any other value as zero.
type looseCount uint64

func (n *looseCount) UnmarshalJSON(b []byte) error {
	if v, err := wholeNumber(json.RawMessage(b)); err == nil && v.IsUint64() {
		*n = looseCount(v.Uint64())
	}
	return nil
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
			TotalSize json.RawMessage `json:"total_size"`
		} `json:"metadata"`
		WeightMap map[string]string `json:"weight_map"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing index: %w", err)
	}
	if len(raw.WeightMap) == 0 {
		return nil, fmt.Errorf("index names no shards")
	}
	size, err := byteCount(raw.Metadata.TotalSize)
	if err != nil {
		return nil, fmt.Errorf("parsing index: total_size: %w", err)
	}
	return &Index{TotalSize: size, WeightMap: raw.WeightMap}, nil
}

// byteCount reads a declared byte count. Some writers put it down with a
// fraction, 359999963128.0, which is accepted when it is exactly whole.
// Absent is zero, which the size check reads as nothing declared.
func byteCount(raw json.RawMessage) (int64, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return 0, nil
	}
	v, err := wholeNumber(raw)
	if err != nil {
		return 0, err
	}
	if !v.IsInt64() {
		return 0, fmt.Errorf("%s is too large to be a byte count", raw)
	}
	return v.Int64(), nil
}

// maxNumberText bounds the text of a number before it is parsed, since parsing
// costs time quadratic in its digits. The counts a model states run to about
// 24 characters.
const maxNumberText = 64

// wholeNumber reads a JSON number as an exact non-negative integer, with or
// without a fraction or exponent, and refuses anything else, a quoted
// number included.
func wholeNumber(raw json.RawMessage) (*big.Int, error) {
	text := string(bytes.TrimSpace(raw))
	if len(text) > maxNumberText {
		return nil, fmt.Errorf("a number of %d characters is too long to be a count", len(text))
	}
	r, ok := new(big.Rat).SetString(text)
	switch {
	case !ok:
		return nil, fmt.Errorf("%s is not a number", text)
	case !r.IsInt():
		return nil, fmt.Errorf("%s is not a whole number", text)
	case r.Sign() < 0:
		return nil, fmt.Errorf("%s is negative", text)
	}
	return r.Num(), nil
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

// QuantConfigName is where an NVIDIA ModelOpt checkpoint records its
// quantization. Older checkpoints state none in config.json, and newer ones
// often name only the toolkit there.
const QuantConfigName = "hf_quant_config.json"

// ReadQuantAlgo returns the scheme hf_quant_config.json in dir names, fp8 or
// nvfp4 for example, lower-cased, or nothing when there is no such file.
func ReadQuantAlgo(dir string) string {
	b, err := os.ReadFile(filepath.Join(dir, QuantConfigName)) // #nosec G304 -- a file beside the model being packed
	if err != nil {
		return ""
	}
	var q struct {
		Quantization struct {
			QuantAlgo looseString `json:"quant_algo"`
		} `json:"quantization"`
		QuantAlgo looseString `json:"quant_algo"`
	}
	if json.Unmarshal(b, &q) != nil {
		return ""
	}
	algo := q.Quantization.QuantAlgo
	if algo == "" {
		algo = q.QuantAlgo
	}
	return strings.ToLower(string(algo))
}
