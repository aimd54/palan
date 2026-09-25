// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package safetensors

// CompanionNames are the files a served safetensors model wants beside its
// weights: its tokenizer, its chat template, which may exist only in
// chat_template.jinja, the processor configs a model that reads images or
// video needs, and a ModelOpt checkpoint's quantization config. They travel
// when present, and their absence is no error.
var CompanionNames = []string{
	"tokenizer.json", "tokenizer_config.json", "special_tokens_map.json",
	"generation_config.json", "tokenizer.model", "tiktoken.model", "vocab.json", "merges.txt",
	"added_tokens.json", "chat_template.jinja", "chat_template.json",
	"preprocessor_config.json", "processor_config.json", "video_preprocessor_config.json",
	QuantConfigName,
}

// DocNames are the files stating the terms the weights were released under,
// and the notes published with them. They travel for a different reason than
// the companions above: a redistributed model whose licence stayed behind
// reaches the next reader with no terms attached.
var DocNames = []string{
	"LICENSE", "LICENSE.txt", "LICENSE.md", "LICENCE", "NOTICE", "README.md",
}
