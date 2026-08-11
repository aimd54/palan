// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"charm.land/lipgloss/v2"

	"github.com/aimd54/palan/internal/ui"
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
			// A safetensors model states a precision and no quantization, which
			// is the other half of the encoding column and the only fixture
			// that puts the precision field into the JSON output at all.
			Ref:       "registry.internal/llm/qwen3:8b-bf16",
			Kind:      "model",
			Family:    "qwen2",
			Params:    "8B",
			Precision: "bfloat16",
			Format:    "safetensors",
			Size:      16_400_000_000,
			Digest:    "sha256:4444444444444444444444444444444444444444444444444444444444444444",
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

// TestStyledRenderersKeepEveryValue guards the second renderer. The golden
// tests above only ever exercise the plain path, so a styled path that lost a
// column, or dropped a field, would satisfy all of them.
//
// The assertion is on content rather than on exact bytes: colour codes are the
// styling library's business and would make this brittle, but a value that
// stopped being shown is a defect either way.
func TestStyledRenderersKeepEveryValue(t *testing.T) {
	styles := ui.Styles{
		Header:  lipgloss.NewStyle().Bold(true),
		Key:     lipgloss.NewStyle().Bold(true),
		Dim:     lipgloss.NewStyle().Foreground(lipgloss.BrightBlack),
		Accent:  lipgloss.NewStyle().Foreground(lipgloss.Cyan),
		Success: lipgloss.NewStyle().Foreground(lipgloss.Green),
		Warn:    lipgloss.NewStyle().Foreground(lipgloss.Yellow),
		Error:   lipgloss.NewStyle().Foreground(lipgloss.Red),
	}

	t.Run("ls", func(t *testing.T) {
		var buf bytes.Buffer
		if err := renderRowsStyled(&buf, lsFixture(), styles); err != nil {
			t.Fatal(err)
		}
		got := buf.String()
		for _, want := range lsColumns {
			if !strings.Contains(got, want) {
				t.Errorf("styled listing lost the %q column", want)
			}
		}
		for _, r := range lsFixture() {
			for _, cell := range lsCells(r) {
				if !strings.Contains(got, cell) {
					t.Errorf("styled listing lost the value %q", cell)
				}
			}
		}
	})

	t.Run("describe", func(t *testing.T) {
		var buf bytes.Buffer
		d := describeFixture()
		if err := renderDetailStyled(&buf, d, styles); err != nil {
			t.Fatal(err)
		}
		got := buf.String()
		for _, f := range detailFields(d) {
			if !strings.Contains(got, f[0]) || !strings.Contains(got, f[1]) {
				t.Errorf("styled detail lost the field %q = %q", f[0], f[1])
			}
		}
		for k, v := range d.Annotations {
			if !strings.Contains(got, k) || !strings.Contains(got, v) {
				t.Errorf("styled detail lost the annotation %q", k)
			}
		}
		for _, l := range d.Layers {
			if !strings.Contains(got, l.Digest) {
				t.Errorf("styled detail lost the layer %q", l.Digest)
			}
		}
	})
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
