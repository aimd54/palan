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
		Precision:     "bfloat16",
		ContextLength: 4096,
		Format:        "safetensors",
	}
	if got != want {
		t.Fatalf("FromSafetensors() = %+v, want %+v", got, want)
	}
	if got.License != "" {
		t.Errorf("License = %q; safetensors publishes none, so only a caller supplies it", got.License)
	}
	// A dtype is a precision. The ModelPack config reserves quantization for a
	// scheme such as awq or gptq, which unquantized weights do not have.
	if got.Quantization != "" {
		t.Errorf("Quantization = %q; a dtype belongs in Precision", got.Quantization)
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
	// Spelled as a config spells it, so one precision reads one way
	// whichever source it came from.
	if got.Precision != "float16" {
		t.Errorf("Precision = %q, want the dominant shard dtype as float16", got.Precision)
	}
	if got.ContextLength != 0 {
		t.Errorf("ContextLength = %d; an unstated context length must stay unset", got.ContextLength)
	}
}

// TestFromSafetensorsRecordsAQuantizedModel: precision is the dtype the model
// computes in and quantization the scheme, as the ModelPack spec pairs them.
// The shard headers answer only when the config states no dtype, and then
// only their float tensors do. Packed weights give no parameter count.
func TestFromSafetensorsRecordsAQuantizedModel(t *testing.T) {
	tensors := func(packed string) *safetensors.Header {
		return &safetensors.Header{Tensors: map[string]safetensors.TensorInfo{
			"experts": {DType: packed, Shape: []int64{3000, 1000}},
			"norm":    {DType: "BF16", Shape: []int64{1000, 10}},
			"router":  {DType: "F32", Shape: []int64{10, 10}},
		}}
	}
	for _, c := range []struct {
		name       string
		cfg        safetensors.Config
		shards     *safetensors.Header
		prec, quan string
		size       string
	}{
		{"dtype stated", safetensors.Config{TorchDType: "bfloat16", QuantMethod: "fp8"}, tensors("F8_E4M3"), "bfloat16", "fp8", "3M"},
		{"no dtype stated", safetensors.Config{QuantMethod: "fp8"}, tensors("F8_E4M3"), "bfloat16", "fp8", "3M"},
		{"one byte a weight", safetensors.Config{QuantMethod: "compressed-tensors"}, tensors("I8"), "bfloat16", "compressed-tensors", "3M"},
		{"one byte a weight, beside a byte flag", safetensors.Config{QuantMethod: "bitsandbytes"}, &safetensors.Header{Tensors: map[string]safetensors.TensorInfo{
			"w":             {DType: "I8", Shape: []int64{3000, 1000}},
			"weight_format": {DType: "U8", Shape: []int64{1}},
			"scb":           {DType: "F32", Shape: []int64{3000}},
			"norm":          {DType: "BF16", Shape: []int64{1000, 10}},
		}}, "bfloat16", "bitsandbytes", "3M"},
		{"packed into bytes", safetensors.Config{QuantMethod: "mxfp4"}, tensors("U8"), "bfloat16", "mxfp4", ""},
		{"packed into words", safetensors.Config{QuantMethod: "awq"}, tensors("I32"), "bfloat16", "awq", ""},
		{"no float tensor", safetensors.Config{QuantMethod: "bitnet"}, &safetensors.Header{Tensors: map[string]safetensors.TensorInfo{
			"w": {DType: "U8", Shape: []int64{10, 10}},
		}}, "", "bitnet", ""},
	} {
		got := FromSafetensors(&c.cfg, c.shards, "quantized")
		if got.Precision != c.prec || got.Quantization != c.quan || got.SizeLabel != c.size {
			t.Errorf("%s: precision %q, quantization %q, size %q; want %q, %q and %q",
				c.name, got.Precision, got.Quantization, got.SizeLabel, c.prec, c.quan, c.size)
		}
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
