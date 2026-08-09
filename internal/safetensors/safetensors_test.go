// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package safetensors

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aimd54/palan/internal/safetensors/safetensorstest"
)

func writeShard(t *testing.T, dir, name string, tensors ...safetensorstest.Tensor) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, safetensorstest.Shard(tensors...), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReadHeaderReportsEveryTensor(t *testing.T) {
	p := writeShard(t, t.TempDir(), "model.safetensors",
		safetensorstest.Tensor{Name: "a", DType: "BF16", Shape: []int64{2, 4}},
		safetensorstest.Tensor{Name: "b", DType: "BF16", Shape: []int64{8}},
	)
	h, err := ReadHeader(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Tensors) != 2 {
		t.Fatalf("got %d tensors, want 2", len(h.Tensors))
	}
	if got := h.Tensors["a"].DType; got != "BF16" {
		t.Errorf("tensor a dtype = %q, want BF16", got)
	}
	if got := h.ParamCount(); got != 16 {
		t.Errorf("ParamCount() = %d, want 16", got)
	}
	if got := h.DominantDType(); got != "BF16" {
		t.Errorf("DominantDType() = %q, want BF16", got)
	}
}

// TestDominantDTypeBreaksATieDeterministically: the tensors live in a map, and
// two dtypes can hold the same number of elements, so the winner has to come
// from the sorted names rather than from iteration order. Identical inputs
// yield identical digests only while every value the config records is stable
// across runs.
func TestDominantDTypeBreaksATieDeterministically(t *testing.T) {
	p := writeShard(t, t.TempDir(), "model.safetensors",
		safetensorstest.Tensor{Name: "a", DType: "F32", Shape: []int64{4, 4}},
		safetensorstest.Tensor{Name: "b", DType: "BF16", Shape: []int64{16}},
	)
	h, err := ReadHeader(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := h.ParamCount(); got != 32 {
		t.Fatalf("ParamCount() = %d, want the two dtypes tied at 16 elements each", got)
	}
	// Map iteration order varies per range, so a tie broken by iteration order
	// shows up as a value that changes between calls on one header.
	for i := range 64 {
		if got := h.DominantDType(); got != "BF16" {
			t.Fatalf("DominantDType() = %q on call %d, want the first of the tied names, BF16", got, i)
		}
	}
}

func TestReadHeaderRejectsATruncatedHeader(t *testing.T) {
	dir := t.TempDir()
	full := safetensorstest.Shard(
		safetensorstest.Tensor{Name: "a", DType: "F32", Shape: []int64{4}})
	p := filepath.Join(dir, "model.safetensors")
	// Keep the length prefix, drop most of the JSON it promises.
	if err := os.WriteFile(p, full[:12], 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadHeader(p); err == nil {
		t.Fatal("ReadHeader accepted a file whose header is shorter than its length prefix")
	}
}
