// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package safetensors

// CompanionNames are the files a served safetensors model wants beside its
// weights. They travel when present; a model without them is still a valid
// artifact, so their absence is not an error.
var CompanionNames = []string{
	"tokenizer.json", "tokenizer_config.json", "special_tokens_map.json",
	"generation_config.json", "tokenizer.model", "vocab.json", "merges.txt",
}

// DocNames are the files stating the terms the weights were released under,
// and the notes published with them. They travel for a different reason than
// the companions above: a redistributed model whose licence stayed behind
// reaches the next reader with no terms attached.
var DocNames = []string{
	"LICENSE", "LICENSE.txt", "LICENSE.md", "LICENCE", "NOTICE", "README.md",
}
