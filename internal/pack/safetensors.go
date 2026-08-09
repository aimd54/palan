// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package pack

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aimd54/palan/internal/safetensors"
)

// companionNames are the files a served safetensors model wants beside its
// weights. They travel when present; a model without them is still a valid
// artifact, so their absence is not an error.
var companionNames = []string{
	"tokenizer.json", "tokenizer_config.json", "special_tokens_map.json",
	"generation_config.json", "tokenizer.model", "vocab.json", "merges.txt",
}

// hasSafetensors reports whether any input is a safetensors shard.
func hasSafetensors(files []File) bool {
	for _, f := range files {
		if isSafetensors(f.Path) {
			return true
		}
	}
	return false
}

func isSafetensors(path string) bool {
	return strings.HasSuffix(strings.ToLower(path), ".safetensors")
}

// absPath resolves p for identity comparison, falling back to p itself when
// the working directory cannot be read.
func absPath(p string) string {
	a, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return a
}

// gatherSafetensorsShards completes a safetensors input set from the shard
// index beside it, and refuses a set the index says is incomplete.
//
// A sharded model whose shards are partly missing packs cleanly and describes
// correctly: the manifest lists fewer layers, nothing errors, and inference
// fails much later. The index names every shard and declares the total byte
// size, so both are checked here rather than trusted.
func gatherSafetensorsShards(files []File) ([]File, error) {
	var dir string
	for _, f := range files {
		if isSafetensors(f.Path) {
			dir = filepath.Dir(f.Path)
			break
		}
	}
	if dir == "" {
		return files, nil
	}

	have := make(map[string]bool, len(files))
	for _, f := range files {
		have[absPath(f.Path)] = true
	}
	out := make([]File, len(files), len(files)+len(companionNames)+8)
	copy(out, files)

	include := func(p string) {
		a := absPath(p)
		if have[a] {
			return
		}
		have[a] = true
		out = append(out, File{Path: p})
	}
	// addNamed brings in dir/name, reporting why it could not be read.
	addNamed := func(name string) error {
		p := filepath.Join(dir, name)
		if have[absPath(p)] {
			return nil
		}
		if _, err := os.Stat(p); err != nil {
			return err
		}
		include(p)
		return nil
	}

	indexPath := filepath.Join(dir, safetensors.IndexName)
	if _, err := os.Stat(indexPath); err == nil {
		ix, err := safetensors.ReadIndex(indexPath)
		if err != nil {
			return nil, err
		}
		var missing []string
		var onDisk int64
		for _, shard := range ix.Shards() {
			// The index travels with the download, so its shard names are
			// publisher-supplied text. Anything but a plain filename would
			// reach outside the model directory and be hashed, stored and
			// pushed as one of the model's own layers.
			if shard != filepath.Base(shard) || shard == "." || shard == ".." {
				return nil, fmt.Errorf("%s names %q, which is not a file beside it",
					safetensors.IndexName, shard)
			}
			st, err := os.Stat(filepath.Join(dir, shard))
			if err != nil {
				missing = append(missing, shard)
				continue
			}
			onDisk += st.Size()
			include(filepath.Join(dir, shard))
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			return nil, fmt.Errorf("%s names %d shard(s) that are not in %s: %s",
				safetensors.IndexName, len(missing), dir, strings.Join(missing, ", "))
		}
		// The declared total counts tensor bytes, so every shard file is larger
		// than its share of it by the size of its own header. Shards that fall
		// short of the declaration are therefore missing weights, which is the
		// state a truncated download leaves behind with every filename the
		// index names still in place.
		if ix.TotalSize > 0 && onDisk < ix.TotalSize {
			return nil, fmt.Errorf("%s declares %d bytes of weights, the shards in %s hold %d",
				safetensors.IndexName, ix.TotalSize, dir, onDisk)
		}
		if err := addNamed(safetensors.IndexName); err != nil {
			return nil, err
		}
	}

	// config.json is required: without it there is no architecture and no
	// context length, and a served model needs it beside the weights.
	if err := addNamed(safetensors.ConfigName); err != nil {
		return nil, fmt.Errorf("%s is required beside a safetensors model: %w",
			safetensors.ConfigName, err)
	}
	for _, name := range companionNames {
		_ = addNamed(name)
	}
	return out, nil
}

// safetensorsMeta reads the metadata for a gathered safetensors set. shards are
// the weight files the artifact carries, so the parameter count and dtype
// recorded describe the artifact and not whatever else the directory holds: an
// adapter or a second quantization beside a model is no part of that model.
func safetensorsMeta(dir string, shards []string) (*safetensors.Config, *safetensors.Header, error) {
	cfg, err := safetensors.ReadConfig(filepath.Join(dir, safetensors.ConfigName))
	if err != nil {
		return nil, nil, err
	}
	if len(shards) == 0 {
		return nil, nil, fmt.Errorf("%s: no .safetensors file", dir)
	}
	// A parameter count over one shard understates the model, so every shard
	// header contributes its tensors.
	merged := &safetensors.Header{Tensors: map[string]safetensors.TensorInfo{}}
	for _, p := range shards {
		h, err := safetensors.ReadHeader(p)
		if err != nil {
			return nil, nil, err
		}
		maps.Copy(merged.Tensors, h.Tensors)
	}
	return cfg, merged, nil
}
