// Copyright The moci Authors
// SPDX-License-Identifier: Apache-2.0

package gguf

import "fmt"

// fileTypeName maps llama.cpp's llama_ftype enum (general.file_type) to the
// conventional quantization label. Unknown values render as "FT_<n>" rather
// than failing: the enum grows with llama.cpp releases.
func fileTypeName(ft uint32) string {
	if name, ok := fileTypeNames[ft]; ok {
		return name
	}
	return fmt.Sprintf("FT_%d", ft)
}

var fileTypeNames = map[uint32]string{
	0:  "F32",
	1:  "F16",
	2:  "Q4_0",
	3:  "Q4_1",
	7:  "Q8_0",
	8:  "Q5_0",
	9:  "Q5_1",
	10: "Q2_K",
	11: "Q3_K_S",
	12: "Q3_K_M",
	13: "Q3_K_L",
	14: "Q4_K_S",
	15: "Q4_K_M",
	16: "Q5_K_S",
	17: "Q5_K_M",
	18: "Q6_K",
	19: "IQ2_XXS",
	20: "IQ2_XS",
	21: "Q2_K_S",
	22: "IQ3_XS",
	23: "IQ3_XXS",
	24: "IQ1_S",
	25: "IQ4_NL",
	26: "IQ3_S",
	27: "IQ3_M",
	28: "IQ2_S",
	29: "IQ2_M",
	30: "IQ4_XS",
	31: "IQ1_M",
	32: "BF16",
	36: "TQ1_0",
	37: "TQ2_0",
}
