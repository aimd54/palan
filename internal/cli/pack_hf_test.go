// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"io"
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
		"model.safetensors": []byte("weights-bytes"),
		"config.json":       []byte(`{"architectures":["Qwen3ForCausalLM"],"max_position_embeddings":4096}`),
		"tokenizer.json":    []byte("{}"),
	})
	t.Setenv("HF_ENDPOINT", hub.URL())

	files, info, err := resolveSources(t.Context(), newTestCommand(t), []string{"hf://org/repo"})
	if err != nil {
		t.Fatalf("resolveSources: %v", err)
	}
	if len(files) != 3 {
		t.Fatalf("resolved %d files, want the weights, the config and the tokenizer", len(files))
	}
	for _, f := range files {
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
