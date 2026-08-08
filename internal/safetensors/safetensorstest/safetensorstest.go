// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

// Package safetensorstest builds minimal .safetensors files for tests.
package safetensorstest

import (
	"encoding/binary"
	"encoding/json"
)

// Tensor describes one tensor to encode.
type Tensor struct {
	Name  string
	DType string
	Shape []int64
}

// dtypeSize is the byte width of each dtype safetensors names.
var dtypeSize = map[string]int64{
	"F64": 8, "F32": 4, "F16": 2, "BF16": 2,
	"I64": 8, "I32": 4, "I16": 2, "I8": 1, "U8": 1, "BOOL": 1,
	"F8_E4M3": 1, "F8_E5M2": 1,
}

// Shard encodes tensors into the safetensors container format. The payload is
// zero bytes of the length the shapes imply, which is enough for a header
// reader and keeps fixtures small.
func Shard(tensors ...Tensor) []byte {
	hdr := map[string]any{}
	var offset int64
	for _, t := range tensors {
		n := dtypeSize[t.DType]
		for _, d := range t.Shape {
			n *= d
		}
		hdr[t.Name] = map[string]any{
			"dtype":        t.DType,
			"shape":        t.Shape,
			"data_offsets": []int64{offset, offset + n},
		}
		offset += n
	}
	js, err := json.Marshal(hdr)
	if err != nil {
		panic(err) // fixture builder: a bad fixture is a test bug
	}
	out := make([]byte, 8, 8+len(js)+int(offset))
	binary.LittleEndian.PutUint64(out, uint64(len(js)))
	out = append(out, js...)
	return append(out, make([]byte, offset)...)
}
