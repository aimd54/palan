// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package safetensors

import (
	"slices"
	"testing"
)

func TestFileSetNamesCoverWhatAModelIsPublishedWith(t *testing.T) {
	// The tokenizer and the licence are what a redistributed model is
	// unusable or unlawful without, so both lists are pinned here rather
	// than left to whichever caller reads them first.
	for _, want := range []string{"tokenizer.json", "tokenizer_config.json", "special_tokens_map.json"} {
		if !slices.Contains(CompanionNames, want) {
			t.Errorf("CompanionNames is missing %q", want)
		}
	}
	for _, want := range []string{"LICENSE", "README.md"} {
		if !slices.Contains(DocNames, want) {
			t.Errorf("DocNames is missing %q", want)
		}
	}
}

func TestParseIndexReadsShardsFromBytes(t *testing.T) {
	data := []byte(`{"metadata":{"total_size":12},"weight_map":{"a":"model-00001-of-00002.safetensors","b":"model-00002-of-00002.safetensors"}}`)
	ix, err := ParseIndex(data)
	if err != nil {
		t.Fatalf("ParseIndex: %v", err)
	}
	shards := ix.Shards()
	want := []string{"model-00001-of-00002.safetensors", "model-00002-of-00002.safetensors"}
	if !slices.Equal(shards, want) {
		t.Fatalf("Shards() = %v, want %v", shards, want)
	}
}
