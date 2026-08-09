// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package modelmeta

import (
	"testing"

	"github.com/aimd54/palan/internal/gguf"
	"github.com/aimd54/palan/internal/safetensors"
)

func TestFromGGUFCarriesEveryFieldPackRecords(t *testing.T) {
	got := FromGGUF(&gguf.Info{
		Architecture:  "llama",
		Name:          "tiny",
		SizeLabel:     "15M",
		Quantization:  "Q4_K_M",
		License:       "Apache-2.0",
		ContextLength: 2048,
	})
	want := Info{
		Architecture:  "llama",
		Name:          "tiny",
		SizeLabel:     "15M",
		Quantization:  "Q4_K_M",
		License:       "Apache-2.0",
		ContextLength: 2048,
		Format:        "gguf",
	}
	if got != want {
		t.Fatalf("FromGGUF() = %+v, want %+v", got, want)
	}
}

func TestFromSafetensorsCarriesEveryFieldPackRecords(t *testing.T) {
	got := FromSafetensors(
		&safetensors.Config{
			ModelType:             "llama",
			MaxPositionEmbeddings: 4096,
			TorchDType:            "bfloat16",
		},
		&safetensors.Header{Tensors: map[string]safetensors.TensorInfo{
			"blk.0": {DType: "BF16", Shape: []int64{2000, 3650}},
		}},
		"tiny",
	)
	want := Info{
		Architecture:  "llama",
		Name:          "tiny",
		SizeLabel:     "7.3M",
		Quantization:  "bfloat16",
		ContextLength: 4096,
		Format:        "safetensors",
	}
	if got != want {
		t.Fatalf("FromSafetensors() = %+v, want %+v", got, want)
	}
	if got.License != "" {
		t.Errorf("License = %q; safetensors publishes none, so only a caller supplies it", got.License)
	}
}

// TestFromSafetensorsFallsBackWhenTheConfigIsSparse: config.json need not name
// a model_type or a torch_dtype, and the shards answer both questions.
func TestFromSafetensorsFallsBackWhenTheConfigIsSparse(t *testing.T) {
	got := FromSafetensors(
		&safetensors.Config{Architectures: []string{"MistralForCausalLM"}},
		&safetensors.Header{Tensors: map[string]safetensors.TensorInfo{
			"big":   {DType: "F16", Shape: []int64{1000, 1000}},
			"small": {DType: "F32", Shape: []int64{10}},
		}},
		"sparse",
	)
	if got.Architecture != "MistralForCausalLM" {
		t.Errorf("Architecture = %q, want MistralForCausalLM", got.Architecture)
	}
	if got.Quantization != "F16" {
		t.Errorf("Quantization = %q, want the dominant shard dtype F16", got.Quantization)
	}
	if got.ContextLength != 0 {
		t.Errorf("ContextLength = %d; an unstated context length must stay unset", got.ContextLength)
	}
}

func TestFormatParamSize(t *testing.T) {
	for _, tc := range []struct {
		n    int64
		want string
	}{
		{-1, ""},
		{0, ""},
		{1, "1"},
		{999, "999"},
		{1000, "1K"},
		{16384, "16.4K"},
		{999999, "1M"},
		{350000000, "350M"},
		{950000000, "950M"},
		{999999999, "1B"},
		{7300000000, "7.3B"},
		{1234567890123, "1234.6B"},
	} {
		if got := FormatParamSize(tc.n); got != tc.want {
			t.Errorf("FormatParamSize(%d) = %q, want %q", tc.n, got, tc.want)
		}
	}
}
