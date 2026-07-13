// Copyright The moci Authors
// SPDX-License-Identifier: Apache-2.0

// Package gguftest synthesizes valid GGUF byte streams for tests: header
// parsing, pack determinism, and end-to-end flows all need real-shaped GGUF
// files without downloading model weights.
package gguftest

import (
	"bytes"
	"encoding/binary"
)

// Value types mirrored from the GGUF spec (kept unexported in the parser).
const (
	TypeUint32  = 4
	TypeFloat32 = 6
	TypeBool    = 7
	TypeString  = 8
	TypeArray   = 9
	TypeUint64  = 10
)

// KV is one metadata entry.
type KV struct {
	Key   string
	Type  uint32
	Value any // string, uint32, uint64, float32, bool, []string (string array)
}

// Build assembles a GGUF stream with the given version, tensor count,
// metadata, and trailing payload bytes standing in for tensor data.
func Build(version uint32, tensorCount uint64, kvs []KV, payload []byte) []byte {
	var b bytes.Buffer
	b.WriteString("GGUF")
	le := binary.LittleEndian
	_ = binary.Write(&b, le, version)
	_ = binary.Write(&b, le, tensorCount)
	_ = binary.Write(&b, le, uint64(len(kvs)))
	for _, kv := range kvs {
		writeString(&b, kv.Key)
		_ = binary.Write(&b, le, kv.Type)
		switch v := kv.Value.(type) {
		case string:
			writeString(&b, v)
		case uint32:
			_ = binary.Write(&b, le, v)
		case uint64:
			_ = binary.Write(&b, le, v)
		case float32:
			_ = binary.Write(&b, le, v)
		case bool:
			x := byte(0)
			if v {
				x = 1
			}
			b.WriteByte(x)
		case []string:
			_ = binary.Write(&b, le, uint32(TypeString)) // element type
			_ = binary.Write(&b, le, uint64(len(v)))
			for _, s := range v {
				writeString(&b, s)
			}
		default:
			panic("gguftest: unsupported KV value type")
		}
	}
	b.Write(payload)
	return b.Bytes()
}

// TinyModel builds a realistic minimal model file: standard general.* keys,
// a context length, a token array to exercise array skipping, and payload
// bytes as fake weights.
func TinyModel(arch, name, sizeLabel string, ctxLen uint32, fileType uint32, payload []byte) []byte {
	kvs := []KV{
		{Key: "general.architecture", Type: TypeString, Value: arch},
		{Key: "general.name", Type: TypeString, Value: name},
		{Key: "general.size_label", Type: TypeString, Value: sizeLabel},
		{Key: "general.license", Type: TypeString, Value: "Apache-2.0"},
		{Key: "general.file_type", Type: TypeUint32, Value: fileType},
		{Key: arch + ".context_length", Type: TypeUint32, Value: ctxLen},
		{Key: arch + ".block_count", Type: TypeUint32, Value: uint32(2)},
		{Key: "tokenizer.ggml.tokens", Type: TypeArray, Value: []string{"<s>", "</s>", "a", "b"}},
	}
	return Build(3, 4, kvs, payload)
}

func writeString(b *bytes.Buffer, s string) {
	_ = binary.Write(b, binary.LittleEndian, uint64(len(s)))
	b.WriteString(s)
}
