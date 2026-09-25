// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

// Package modelmeta carries the model metadata pack records in an artifact,
// independently of the weight format it was read from. Distribution is
// format-neutral (ADR-0012); a constructor per format fills this struct, and
// nothing downstream of it reads a weight file.
package modelmeta

import (
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/aimd54/palan/internal/gguf"
	"github.com/aimd54/palan/internal/safetensors"
)

// Format values recorded in the ModelPack config's Format field.
const (
	FormatGGUF        = "gguf"
	FormatSafetensors = "safetensors"
)

// Info is the metadata pack writes into the manifest and the model config.
// Every field is optional except Format: a weight format that cannot supply
// one leaves it empty rather than inventing a value.
type Info struct {
	Architecture string
	Name         string
	SizeLabel    string
	// Precision is the numeric type the model computes in, bfloat16 or
	// float16 for example, and Quantization names a quantization scheme such
	// as awq or fp8. The ModelPack config keeps the two apart, and a
	// quantized model states both.
	Precision     string
	Quantization  string
	License       string
	ContextLength uint64
	Format        string
}

// FromGGUF adapts a parsed GGUF header.
func FromGGUF(g *gguf.Info) Info {
	return Info{
		Architecture:  g.Architecture,
		Name:          g.Name,
		SizeLabel:     g.SizeLabel,
		Quantization:  g.Quantization,
		License:       g.License,
		ContextLength: g.ContextLength,
		Format:        FormatGGUF,
	}
}

// FromSafetensors adapts a Hugging Face config and a shard header. name is
// the model name, which safetensors does not publish; callers pass the source
// directory or repository name. License stays empty for the same reason: a
// safetensors model carries no license field, so only a caller can supply one.
// Precision is the dtype config.json states, which is the one the model
// computes in, or the shard headers' dominant one when it states none, and
// Quantization names the scheme a quantized model's config records.
func FromSafetensors(c *safetensors.Config, h *safetensors.Header, name string) Info {
	arch := c.ModelType
	if arch == "" && len(c.Architectures) > 0 {
		arch = c.Architectures[0]
	}
	prec := c.TorchDType
	switch {
	case prec != "":
	case c.QuantMethod == "":
		prec = safetensors.DTypeName(h.DominantDType())
	default:
		// Quantized weights are packed into integer or 8-bit containers, so
		// only the tensors left in a float type say what the model computes in.
		prec = safetensors.DTypeName(h.DominantDType("BF16", "F16", "F32"))
	}
	// Packed weights hold several parameters to an element, a number that
	// depends on the scheme, so no count is recorded rather than a wrong one.
	size := FormatParamSize(h.ParamCount())
	if c.QuantMethod != "" && slices.Contains(packedDTypes, h.DominantDType(quantizedDTypes...)) {
		size = ""
	}
	return Info{
		Architecture:  arch,
		Name:          name,
		SizeLabel:     size,
		Precision:     prec,
		Quantization:  c.QuantMethod,
		ContextLength: c.MaxPositionEmbeddings,
		Format:        FormatSafetensors,
	}
}

// packedDTypes are the integer types quantized weights are packed into, such
// as AWQ and GPTQ's int32 words and the bytes 4-bit schemes use. int8 holds
// one parameter to an element, and is not among them.
var packedDTypes = []string{"U8", "I16", "U16", "I32", "U32", "I64", "U64"}

// quantizedDTypes are the types quantized weights are stored in, packed or
// not. Whichever holds the most elements says which the weights are.
var quantizedDTypes = append([]string{"I8", "F8_E4M3", "F8_E5M2"}, packedDTypes...)

// magnitudes are the units a parameter count is rendered in, smallest first.
var magnitudes = []struct {
	suffix string
	scale  float64
}{
	{"K", 1e3},
	{"M", 1e6},
	{"B", 1e9},
}

// FormatParamSize renders a parameter count the way GGUF's general.size_label
// does: 7300000000 becomes "7.3B", 350000000 becomes "350M". A count that
// rounds up into the next unit carries that unit, so 999999999 reads "1B" and
// not "1000M". Below a thousand parameters the count is its own label, since
// rounding it to thousands would print it as zero.
func FormatParamSize(n int64) string {
	if n <= 0 {
		return ""
	}
	if n < int64(magnitudes[0].scale) {
		return strconv.FormatInt(n, 10)
	}
	i := 0
	for i+1 < len(magnitudes) && float64(n) >= magnitudes[i+1].scale {
		i++
	}
	if i+1 < len(magnitudes) && math.Round(float64(n)/magnitudes[i].scale*10)/10 >= 1e3 {
		i++
	}
	return trimZero(float64(n)/magnitudes[i].scale) + magnitudes[i].suffix
}

func trimZero(f float64) string {
	s := strconv.FormatFloat(f, 'f', 1, 64)
	return strings.TrimSuffix(s, ".0")
}
