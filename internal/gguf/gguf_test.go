// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package gguf

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aimd54/palan/internal/gguf/gguftest"
)

func TestReadTinyModel(t *testing.T) {
	data := gguftest.TinyModel("llama", "tinytest", "15M", 2048, 15, []byte("fake-weights"))
	info, err := Read(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if info.Version != 3 || info.TensorCount != 4 {
		t.Errorf("header fields wrong: %+v", info)
	}
	if info.Architecture != "llama" || info.Name != "tinytest" || info.SizeLabel != "15M" {
		t.Errorf("general fields wrong: %+v", info)
	}
	if info.License != "Apache-2.0" {
		t.Errorf("license wrong: %q", info.License)
	}
	if info.Quantization != "Q4_K_M" {
		t.Errorf("quantization: got %q, want Q4_K_M", info.Quantization)
	}
	if info.ContextLength != 2048 {
		t.Errorf("context length: got %d, want 2048", info.ContextLength)
	}
	if _, ok := info.Metadata["tokenizer.ggml.tokens"]; ok {
		t.Error("arrays must be skipped, not materialized")
	}
	if _, ok := info.Metadata["llama.block_count"]; !ok {
		t.Error("scalar KVs must be retained in Metadata")
	}
}

func TestReadFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "tiny.gguf")
	if err := os.WriteFile(p, gguftest.TinyModel("qwen2", "q", "0.5B", 4096, 7, nil), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := ReadFile(p)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if info.Quantization != "Q8_0" || info.ContextLength != 4096 {
		t.Errorf("unexpected info: %+v", info)
	}
}

func TestRejectBadMagic(t *testing.T) {
	if _, err := Read(strings.NewReader("NOTGGUFDATA")); err == nil {
		t.Error("bad magic must fail")
	}
}

func TestRejectV1AndUnknownVersions(t *testing.T) {
	for _, v := range []uint32{0, 1, 4, 0x47554747} {
		data := gguftest.Build(v, 0, nil, nil)
		if _, err := Read(bytes.NewReader(data)); err == nil {
			t.Errorf("version %d must be rejected", v)
		}
	}
}

func TestRejectImplausibleKVCount(t *testing.T) {
	var b bytes.Buffer
	b.WriteString(Magic)
	le := binary.LittleEndian
	_ = binary.Write(&b, le, uint32(3))
	_ = binary.Write(&b, le, uint64(0))
	_ = binary.Write(&b, le, uint64(1<<40)) // absurd KV count
	if _, err := Read(bytes.NewReader(b.Bytes())); err == nil || !strings.Contains(err.Error(), "implausible") {
		t.Errorf("absurd KV count must be rejected, got %v", err)
	}
}

func TestRejectOversizedString(t *testing.T) {
	var b bytes.Buffer
	b.WriteString(Magic)
	le := binary.LittleEndian
	_ = binary.Write(&b, le, uint32(3))
	_ = binary.Write(&b, le, uint64(0))
	_ = binary.Write(&b, le, uint64(1))
	// key claiming to be 1 TiB long
	_ = binary.Write(&b, le, uint64(1<<40))
	if _, err := Read(bytes.NewReader(b.Bytes())); err == nil || !strings.Contains(err.Error(), "exceeds limit") {
		t.Errorf("oversized string must be rejected, got %v", err)
	}
}

func TestTruncatedFile(t *testing.T) {
	data := gguftest.TinyModel("llama", "t", "1B", 2048, 2, nil)
	if _, err := Read(bytes.NewReader(data[:20])); err == nil {
		t.Error("truncated header must fail")
	}
}

func TestUnknownFileTypeRendersFallback(t *testing.T) {
	if got := fileTypeName(9999); got != "FT_9999" {
		t.Errorf("fallback name: got %q", got)
	}
}
