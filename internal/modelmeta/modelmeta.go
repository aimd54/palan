// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

// Package modelmeta carries the model metadata pack records in an artifact,
// independently of the weight format it was read from. Distribution is
// format-neutral (ADR-0012); only the reader that fills this struct is not.
package modelmeta

import "github.com/aimd54/palan/internal/gguf"

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
