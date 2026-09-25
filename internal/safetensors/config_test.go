// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package safetensors

import (
	"os"
	"path/filepath"
	"strings"
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

// TestParseIndexTakesAWholeSizeWrittenAsAFloat: some indexes write their byte
// count with a fraction, and it is still a byte count.
func TestParseIndexTakesAWholeSizeWrittenAsAFloat(t *testing.T) {
	for written, want := range map[string]int64{
		"359999963128":                            359999963128,
		"359999963128.0":                          359999963128,
		"3.59999963128e11":                        359999963128,
		"9007199254740993.0":                      9007199254740993, // past exact float range
		"9223372036854775807":                     9223372036854775807,
		"359999963128." + strings.Repeat("0", 51): 359999963128, // 64 characters, the most read
	} {
		ix, err := ParseIndex([]byte(`{"metadata":{"total_size":` + written + `},"weight_map":{"a":"model.safetensors"}}`))
		if err != nil {
			t.Errorf("total_size %s: %v", written, err)
			continue
		}
		if ix.TotalSize != want {
			t.Errorf("total_size %s read as %d, want %d", written, ix.TotalSize, want)
		}
	}
}

// TestParseIndexRefusesASizeThatIsNotAByteCount: the declared size is what a
// truncated download is caught against, so it is read exactly or not at all.
func TestParseIndexRefusesASizeThatIsNotAByteCount(t *testing.T) {
	for _, written := range []string{
		"1.5", "-1", "-2.0", "1e300", "9223372036854775808",
		"4503599627370496.5",                      // a fraction a float rounds away
		"359999963128.00001",                      // likewise
		`"359999963128"`,                          // quoted
		"1e" + strings.Repeat("9", 50),            // an exponent too large to evaluate
		"359999963128." + strings.Repeat("0", 52), // 65 characters
	} {
		if _, err := ParseIndex([]byte(`{"metadata":{"total_size":` + written + `},"weight_map":{"a":"model.safetensors"}}`)); err == nil {
			t.Errorf("total_size %s was accepted as a byte count", written)
		}
	}
}

// TestParseIndexRefusesALongNumberCheaply: a number is parsed in time
// quadratic in its digits, so an index cannot make the import spend minutes
// on one, and the refusal does not repeat it.
func TestParseIndexRefusesALongNumberCheaply(t *testing.T) {
	long := strings.Repeat("7", 200_000)
	_, err := ParseIndex([]byte(`{"metadata":{"total_size":` + long + `},"weight_map":{"a":"model.safetensors"}}`))
	if err == nil {
		t.Fatal("a number of 200000 digits was accepted as a byte count")
	}
	if len(err.Error()) > 200 {
		t.Fatalf("the refusal runs to %d bytes", len(err.Error()))
	}
}

// TestReadConfigFindsValuesWhereverTheConfigStatesThem: the dtype may be
// written as dtype or torch_dtype, and a model built from more than one part
// states its language model's values in a nested config. The top level is
// read first.
func TestReadConfigFindsValuesWhereverTheConfigStatesThem(t *testing.T) {
	for _, c := range []struct {
		name, body string
		dtype      string
		ctx        uint64
		quant      string
	}{
		{"dtype at the top", `{"model_type":"qwen3","dtype":"bfloat16","max_position_embeddings":40960}`, "bfloat16", 40960, ""},
		{"under text_config", `{"text_config":{"dtype":"bfloat16","max_position_embeddings":262144}}`, "bfloat16", 262144, ""},
		{"torch_dtype under text_config", `{"text_config":{"torch_dtype":"float16","max_position_embeddings":8192}}`, "float16", 8192, ""},
		{"under llm_config", `{"llm_config":{"torch_dtype":"bfloat16","max_position_embeddings":40960}}`, "bfloat16", 40960, ""},
		{"under language_config", `{"language_config":{"dtype":"bfloat16","max_position_embeddings":32768}}`, "bfloat16", 32768, ""},
		{"under thinker_config", `{"thinker_config":{"text_config":{"dtype":"bfloat16","max_position_embeddings":65536}}}`, "bfloat16", 65536, ""},
		{"the top level first", `{"torch_dtype":"float16","max_position_embeddings":4096,"text_config":{"dtype":"bfloat16","max_position_embeddings":8192}}`, "float16", 4096, ""},
		{"dtype before torch_dtype", `{"torch_dtype":"float16","dtype":"bfloat16"}`, "bfloat16", 0, ""},
		{"a context length written as a float", `{"max_position_embeddings":131072.0}`, "", 131072, ""},
		{"values of another shape", `{"dtype":{"weights":"bf16"},"max_position_embeddings":"long","text_config":"not an object","quantization_config":[]}`, "", 0, ""},
		// A quantized model states the dtype it computes in and the scheme.
		{"quantized", `{"quantization_config":{"quant_method":"fp8"},"text_config":{"dtype":"bfloat16"}}`, "bfloat16", 0, "fp8"},
		{"quantized, dtype at the top", `{"torch_dtype":"float16","quantization_config":{"quant_method":"awq"}}`, "float16", 0, "awq"},
		// ModelOpt states the toolkit as the method and the scheme beside it.
		{"modelopt", `{"quantization_config":{"quant_method":"modelopt","quant_algo":"NVFP4"}}`, "", 0, "nvfp4"},
		{"modelopt naming no scheme", `{"quantization_config":{"quant_method":"modelopt"}}`, "", 0, "modelopt"},
		{"an algorithm with no method", `{"quantization_config":{"quant_algo":"FP8"}}`, "", 0, "fp8"},
		{"another method beside an algorithm", `{"quantization_config":{"quant_method":"awq","quant_algo":"FP8"}}`, "", 0, "awq"},
		{"a variant of the toolkit", `{"quantization_config":{"quant_method":"modelopt_mixed","quant_algo":"MIXED_PRECISION"}}`, "", 0, "mixed_precision"},
		{"a method with a quantization of another shape", `{"quantization_config":{"quant_method":"awq","quantization":"int4"}}`, "", 0, "awq"},
		{"the toolkit capitalised", `{"quantization_config":{"quant_method":"ModelOpt","quant_algo":"FP8"}}`, "", 0, "fp8"},
		{"an algorithm one level down", `{"quantization_config":{"quant_method":"modelopt","quantization":{"quant_algo":"NVFP4"}}}`, "", 0, "nvfp4"},
		// A number too long to read describes nothing, and the import goes on.
		{"a context length too long to read", `{"max_position_embeddings":131072.` + strings.Repeat("0", 58) + `}`, "", 0, ""},
		{"a context length at the longest read", `{"max_position_embeddings":131072.` + strings.Repeat("0", 57) + `}`, "", 131072, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), ConfigName)
			if err := os.WriteFile(p, []byte(c.body), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := ReadConfig(p)
			if err != nil {
				t.Fatalf("ReadConfig: %v", err)
			}
			if got.TorchDType != c.dtype {
				t.Errorf("dtype = %q, want %q", got.TorchDType, c.dtype)
			}
			if got.MaxPositionEmbeddings != c.ctx {
				t.Errorf("context length = %d, want %d", got.MaxPositionEmbeddings, c.ctx)
			}
			if got.QuantMethod != c.quant {
				t.Errorf("quantization = %q, want %q", got.QuantMethod, c.quant)
			}
		})
	}
}

// TestReadQuantAlgoReadsAModelOptCheckpoint: an NVIDIA ModelOpt checkpoint
// records its scheme in hf_quant_config.json.
func TestReadQuantAlgoReadsAModelOptCheckpoint(t *testing.T) {
	dir := t.TempDir()
	if got := ReadQuantAlgo(dir); got != "" {
		t.Fatalf("with no %s: got %q, want nothing", QuantConfigName, got)
	}
	body := `{"producer":{"name":"modelopt"},"quantization":{"quant_algo":"FP8","kv_cache_quant_algo":null}}`
	if err := os.WriteFile(filepath.Join(dir, QuantConfigName), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := ReadQuantAlgo(dir); got != "fp8" {
		t.Fatalf("ReadQuantAlgo = %q, want fp8", got)
	}
	// Some exports write the scheme at the top level instead.
	if err := os.WriteFile(filepath.Join(dir, QuantConfigName), []byte(`{"quant_algo":"NVFP4"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := ReadQuantAlgo(dir); got != "nvfp4" {
		t.Fatalf("ReadQuantAlgo on a flat file = %q, want nvfp4", got)
	}
}
