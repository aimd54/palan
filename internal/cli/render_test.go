// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// update rewrites the golden files instead of comparing against them.
// Regenerating is a deliberate act: these files record the exact bytes
// scripts and pipelines parse, so a diff here is a compatibility change
// and should be read as one.
var update = flag.Bool("update", false, "rewrite golden files")

// goldenFixtures are fixed so the output depends on nothing but the
// rendering code: no clock, no store, no registry, no map iteration order
// that is not already sorted by the renderer.
func lsFixture() []modelRow {
	return []modelRow{
		{
			Ref:    "registry.internal/llm/qwen3:8b-q4",
			Kind:   "model",
			Family: "qwen3",
			Params: "8B",
			Quant:  "Q4_K_M",
			Format: "gguf",
			Size:   4_920_000_000,
			Digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		},
		{
			// A short reference next to a long one: the columns have to line
			// up across both, which is what a table is for.
			Ref:    "llm/tiny:v1",
			Kind:   "model",
			Format: "gguf",
			Size:   1_048_576,
			Digest: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
		},
		{
			Ref:    "registry.internal/runtimes/llama-server:b4567-cuda12",
			Kind:   "runtime",
			Size:   87_000_000,
			Digest: "sha256:3333333333333333333333333333333333333333333333333333333333333333",
		},
	}
}

func describeFixture() modelDetail {
	return modelDetail{
		modelRow:     lsFixture()[0],
		ArtifactType: "application/vnd.cncf.model.manifest.v1+json",
		Annotations: map[string]string{
			"org.opencontainers.image.source": "https://example.invalid/models",
			"io.palan.origin.sha256":          "sha256:4444444444444444444444444444444444444444444444444444444444444444",
		},
		Layers: []layerDetail{
			{MediaType: "application/vnd.cncf.model.weight.v1.raw", Size: 4_900_000_000, Digest: "sha256:5555555555555555555555555555555555555555555555555555555555555555"},
			{MediaType: "application/vnd.cncf.model.doc.v1.raw", Size: 11_357, Digest: "sha256:6666666666666666666666666666666666666666666666666666666666666666"},
		},
	}
}

// TestRenderGolden pins the bytes written when the destination is not a
// terminal. This is the compatibility surface: `--json` is parsed by tooling
// and the plain tables are parsed by shell pipelines, so a change here is a
// change to the interface rather than to its appearance.
func TestRenderGolden(t *testing.T) {
	tests := []struct {
		name   string
		golden string
		render func(w *bytes.Buffer) error
	}{
		{
			name:   "ls table",
			golden: "ls.txt",
			render: func(w *bytes.Buffer) error { return renderRows(w, lsFixture(), false) },
		},
		{
			name:   "ls json",
			golden: "ls.json",
			render: func(w *bytes.Buffer) error { return renderRows(w, lsFixture(), true) },
		},
		{
			name:   "ls table empty",
			golden: "ls-empty.txt",
			render: func(w *bytes.Buffer) error { return renderRows(w, nil, false) },
		},
		{
			name:   "describe text",
			golden: "describe.txt",
			render: func(w *bytes.Buffer) error { return renderDetail(w, describeFixture(), false) },
		},
		{
			name:   "describe json",
			golden: "describe.json",
			render: func(w *bytes.Buffer) error { return renderDetail(w, describeFixture(), true) },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tc.render(&buf); err != nil {
				t.Fatalf("render: %v", err)
			}
			path := filepath.Join("testdata", tc.golden)
			if *update {
				if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("reading golden (run with -update to create): %v", err)
			}
			if !bytes.Equal(buf.Bytes(), want) {
				t.Errorf("output changed.\n--- want ---\n%s\n--- got ---\n%s", want, buf.Bytes())
			}
		})
	}
}
