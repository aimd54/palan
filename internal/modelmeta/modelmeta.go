// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

// Package modelmeta carries the model metadata pack records in an artifact,
// independently of the weight format it was read from. Distribution is
// format-neutral (ADR-0012); only the reader that fills this struct is not.
package modelmeta

import (
	"math"
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
	Architecture  string
	Name          string
	SizeLabel     string
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
func FromSafetensors(c *safetensors.Config, h *safetensors.Header, name string) Info {
	arch := c.ModelType
	if arch == "" && len(c.Architectures) > 0 {
		arch = c.Architectures[0]
	}
	quant := c.TorchDType
	if quant == "" {
		quant = h.DominantDType()
	}
	return Info{
		Architecture:  arch,
		Name:          name,
		SizeLabel:     FormatParamSize(h.ParamCount()),
		Quantization:  quant,
		ContextLength: c.MaxPositionEmbeddings,
		Format:        FormatSafetensors,
	}
}

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
