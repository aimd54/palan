// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package modelmeta

import (
	"testing"

	"github.com/aimd54/palan/internal/gguf"
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
