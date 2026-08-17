// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/aimd54/palan/internal/hf/hftest"
)

// newTestCommand returns a *cobra.Command with output discarded, for tests
// that call a command function directly rather than through Execute.
func newTestCommand(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "test"}
	cmd.SetErr(io.Discard)
	return cmd
}

func TestPackFromARepositoryCarriesEveryFilesPublishedDigest(t *testing.T) {
	hub := hftest.New(t, map[string][]byte{
		"model.safetensors":      []byte("weights-bytes"),
		"config.json":            []byte(`{"architectures":["Qwen3ForCausalLM"],"max_position_embeddings":4096}`),
		"tokenizer.json":         []byte("{}"),
		"generation_config.json": []byte(`{}`),
	})
	// generation_config.json is served inline, the way the real API serves a
	// small file that is not stored in LFS, so it publishes no digest at
	// all. Its content still hashes to something, so if OriginSHA256 were
	// ever recomputed from the downloaded bytes instead of passed through
	// from what the repository published, this file's assertion below is
	// the one that would catch it: every other seeded file's published
	// digest equals its content hash by construction of the fake hub, so
	// only an inline file tells the two apart.
	hub.Inline = map[string]bool{"generation_config.json": true}
	t.Setenv("HF_ENDPOINT", hub.URL())

	files, info, err := resolveSources(t.Context(), newTestCommand(t), []string{"hf://org/repo"})
	if info.tempDir != "" {
		t.Cleanup(func() { _ = os.RemoveAll(info.tempDir) })
	}
	if err != nil {
		t.Fatalf("resolveSources: %v", err)
	}
	if len(files) != 4 {
		t.Fatalf("resolved %d files, want the weights, the config, the tokenizer and the generation config", len(files))
	}
	for _, f := range files {
		if f.Name == "generation_config.json" {
			if f.OriginSHA256 != "" {
				t.Errorf("%s carries OriginSHA256 %q, want empty: the repository serves it inline with no digest", f.Path, f.OriginSHA256)
			}
			continue
		}
		if f.OriginSHA256 == "" {
			t.Errorf("%s reached the packer without the digest the repository published", f.Path)
		}
		if strings.HasPrefix(f.OriginSHA256, "sha256:") {
			t.Errorf("%s carries a prefixed digest %q; the layer annotation is bare hex", f.Path, f.OriginSHA256)
		}
	}
	if info.sourceURL == "" {
		t.Error("the artifact would not record which repository it came from")
	}
}
