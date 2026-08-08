// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

// Package safetensors reads the metadata a safetensors model publishes: the
// per-file tensor header, the Hugging Face config.json, and the shard index.
// It never reads tensor payload, so cost is independent of model size.
package safetensors

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
)

// maxHeaderLen bounds the JSON header. Real headers are tens of KiB for the
// largest models; this is generous and stops a corrupt length prefix from
// becoming an allocation the size of the file.
const maxHeaderLen = 64 << 20

// TensorInfo is one entry of a safetensors header.
type TensorInfo struct {
	DType       string   `json:"dtype"`
	Shape       []int64  `json:"shape"`
	DataOffsets [2]int64 `json:"data_offsets"`
}

// Header is the parsed header of one .safetensors file.
type Header struct {
	Tensors  map[string]TensorInfo
	Metadata map[string]string
}

// ReadHeader parses the header of the safetensors file at path.
func ReadHeader(path string) (*Header, error) {
	f, err := os.Open(path) // #nosec G304 -- caller-supplied model path is the point of this API
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var n uint64
	if err := binary.Read(f, binary.LittleEndian, &n); err != nil {
		return nil, fmt.Errorf("%s: reading header length: %w", path, err)
	}
	if n == 0 || n > maxHeaderLen {
		return nil, fmt.Errorf("%s: header length %d is not plausible", path, n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(f, buf); err != nil {
		return nil, fmt.Errorf("%s: reading %d header bytes: %w", path, n, err)
	}

	raw := map[string]json.RawMessage{}
	if err := json.Unmarshal(buf, &raw); err != nil {
		return nil, fmt.Errorf("%s: parsing header: %w", path, err)
	}
	h := &Header{Tensors: map[string]TensorInfo{}}
	for name, msg := range raw {
		if name == "__metadata__" {
			if err := json.Unmarshal(msg, &h.Metadata); err != nil {
				return nil, fmt.Errorf("%s: parsing __metadata__: %w", path, err)
			}
			continue
		}
		var ti TensorInfo
		if err := json.Unmarshal(msg, &ti); err != nil {
			return nil, fmt.Errorf("%s: parsing tensor %q: %w", path, name, err)
		}
		h.Tensors[name] = ti
	}
	if len(h.Tensors) == 0 {
		return nil, fmt.Errorf("%s: header declares no tensors", path)
	}
	return h, nil
}

// ParamCount sums the element count of every tensor.
func (h *Header) ParamCount() int64 {
	var total int64
	for _, ti := range h.Tensors {
		n := int64(1)
		for _, d := range ti.Shape {
			n *= d
		}
		total += n
	}
	return total
}

// DominantDType is the dtype holding the most elements, which is what a reader
// means by the precision of the model. Ties break alphabetically so the answer
// is deterministic.
func (h *Header) DominantDType() string {
	byType := map[string]int64{}
	for _, ti := range h.Tensors {
		n := int64(1)
		for _, d := range ti.Shape {
			n *= d
		}
		byType[ti.DType] += n
	}
	types := make([]string, 0, len(byType))
	for k := range byType {
		types = append(types, k)
	}
	sort.Strings(types)
	best, bestN := "", int64(-1)
	for _, k := range types {
		if byType[k] > bestN {
			best, bestN = k, byType[k]
		}
	}
	return best
}
