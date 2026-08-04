// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/table"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"oras.land/oras-go/v2/content"

	"github.com/aimd54/palan/internal/refname"
	"github.com/aimd54/palan/internal/store"
	"github.com/aimd54/palan/internal/ui"
	"github.com/aimd54/palan/pkg/modelspec"
)

// modelRow is one listing entry, shared by local and remote ls.
type modelRow struct {
	Ref    string `json:"ref"`
	Kind   string `json:"kind"`
	Family string `json:"family,omitempty"`
	Params string `json:"params,omitempty"`
	Quant  string `json:"quantization,omitempty"`
	Format string `json:"format,omitempty"`
	Size   int64  `json:"size"`
	Digest string `json:"digest"`
}

// layerDetail is one manifest layer in describe output.
type layerDetail struct {
	MediaType string `json:"mediaType"`
	Size      int64  `json:"size"`
	Digest    string `json:"digest"`
}

// modelDetail is the full describe output: the ls row plus manifest-level
// detail (artifact type, annotations, layers).
type modelDetail struct {
	modelRow
	ArtifactType string            `json:"artifactType,omitempty"`
	Annotations  map[string]string `json:"annotations,omitempty"`
	Layers       []layerDetail     `json:"layers"`
	Source       string            `json:"source"`
}

// describeRef builds a listing row by reading the manifest and, for
// ModelPack artifacts, the small config blob (see docs/architecture.md,
// "Artifact format": metadata questions are answered without touching
// weights).
func describeRef(ctx context.Context, fetcher content.Fetcher, ref string, desc ocispec.Descriptor) modelRow {
	row := modelRow{Ref: ref, Kind: "unknown", Digest: desc.Digest.String()}
	manifest, err := store.FetchManifest(ctx, fetcher, desc)
	if err != nil {
		return row
	}
	fillFromManifest(ctx, fetcher, manifest, &row)
	return row
}

// fillFromManifest populates kind, size, and model metadata from an
// already-fetched manifest.
func fillFromManifest(ctx context.Context, fetcher content.Fetcher, manifest ocispec.Manifest, row *modelRow) {
	for _, l := range manifest.Layers {
		row.Size += l.Size
	}

	switch {
	case manifest.ArtifactType == modelspec.ArtifactTypeModelManifest ||
		manifest.Config.MediaType == modelspec.MediaTypeModelConfig:
		row.Kind = "model"
		model, err := store.FetchJSON[modelspec.Model](ctx, fetcher, manifest.Config)
		if err != nil {
			return
		}
		row.Family = model.Descriptor.Family
		row.Params = model.Config.ParamSize
		row.Quant = model.Config.Quantization
		row.Format = model.Config.Format

	case manifest.Config.MediaType == ocispec.MediaTypeImageConfig:
		row.Kind = "image"

	case manifest.ArtifactType != "":
		row.Kind = shortArtifactType(manifest.ArtifactType)
	}
}

func newDescribeCmd(v *viper.Viper) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "describe REF",
		Short: "Show a model's metadata, annotations, and layer digests",
		Example: `  # Inspect a model without downloading its weights
  palan describe registry.internal/llm/qwen3:8b-q4

  # Machine-readable form
  palan describe llm/qwen3:8b-q4 --json`,
		Long: `Describe answers metadata questions without touching weights: it reads
only the manifest and the small ModelPack config blob. REF is resolved in
the local store first, then on its registry.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			ref, err := refname.Parse(args[0], v.GetString(keyRegistryDefault))
			if err != nil {
				return err
			}

			st, err := openStore(ctx)
			if err != nil {
				return err
			}
			unlock, err := st.RLock(ctx)
			if err != nil {
				return err
			}
			defer unlock()

			var fetcher content.Fetcher
			var desc ocispec.Descriptor
			source := "local"
			if d, lerr := st.Resolve(ctx, ref.String()); lerr == nil {
				desc, fetcher = d, st.OCI()
			} else {
				source = "remote"
				client, err := newTransferClient(v)
				if err != nil {
					return err
				}
				repo, err := client.Repository(ref)
				if err != nil {
					return err
				}
				desc, err = repo.Resolve(ctx, ref.Reference)
				if err != nil {
					return fmt.Errorf("%s: not in the local store and not resolvable on its registry: %w", ref, err)
				}
				fetcher = repo
			}

			manifest, err := store.FetchManifest(ctx, fetcher, desc)
			if err != nil {
				return err
			}
			detail := modelDetail{
				modelRow:     modelRow{Ref: ref.String(), Kind: "unknown", Digest: desc.Digest.String()},
				ArtifactType: manifest.ArtifactType,
				Annotations:  manifest.Annotations,
				Layers:       make([]layerDetail, 0, len(manifest.Layers)),
				Source:       source,
			}
			fillFromManifest(ctx, fetcher, manifest, &detail.modelRow)
			for _, l := range manifest.Layers {
				detail.Layers = append(detail.Layers, layerDetail{MediaType: l.MediaType, Size: l.Size, Digest: l.Digest.String()})
			}
			return renderDetail(cmd.OutOrStdout(), detail, asJSON)
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "output JSON")
	return cmd
}

// detailFields is the key/value block, built once so the styled and plain
// renderers show the same fields in the same order.
func detailFields(d modelDetail) [][2]string {
	fields := [][2]string{
		{"Ref", d.Ref},
		{"Kind", d.Kind},
		{"Family", orDash(d.Family)},
		{"Params", orDash(d.Params)},
		{"Quant", orDash(d.Quant)},
		{"Format", orDash(d.Format)},
		{"Size", humanBytes(d.Size)},
		{"Digest", d.Digest},
	}
	if d.ArtifactType != "" {
		fields = append(fields, [2]string{"Type", d.ArtifactType})
	}
	return append(fields, [2]string{"Source", d.Source})
}

func sortedAnnotationKeys(d modelDetail) []string {
	keys := make([]string, 0, len(d.Annotations))
	for k := range d.Annotations {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// renderDetail writes a model's detail.
//
// Plain output keeps its tabwriter for the reason given on renderRows: it is
// what pipelines read, and a different layout engine would re-flow it.
func renderDetail(w io.Writer, d modelDetail, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(d)
	}
	if s := ui.New(w); ui.Enabled(w) {
		return renderDetailStyled(w, d, s)
	}
	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	for _, f := range detailFields(d) {
		fmt.Fprintf(tw, "%s:\t%s\n", f[0], f[1])
	}
	if len(d.Annotations) > 0 {
		fmt.Fprintln(tw, "Annotations:")
		for _, k := range sortedAnnotationKeys(d) {
			fmt.Fprintf(tw, "  %s:\t%s\n", k, d.Annotations[k])
		}
	}
	fmt.Fprintln(tw)
	fmt.Fprintln(tw, "LAYER\tSIZE\tDIGEST")
	for _, l := range d.Layers {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", shortArtifactType(l.MediaType), humanBytes(l.Size), l.Digest)
	}
	return tw.Flush()
}

func renderDetailStyled(w io.Writer, d modelDetail, s ui.Styles) error {
	// The key column is padded here rather than by a tabwriter, because the
	// styled keys carry escape sequences that a byte-counting writer would
	// mistake for width.
	width := 0
	for _, f := range detailFields(d) {
		if n := len(f[0]) + 1; n > width {
			width = n
		}
	}
	for _, f := range detailFields(d) {
		label := s.Key.Render(f[0] + ":")
		fmt.Fprintf(w, "%s%s%s\n", label, strings.Repeat(" ", width+1-len(f[0])), f[1])
	}
	if len(d.Annotations) > 0 {
		fmt.Fprintln(w, s.Key.Render("Annotations:"))
		for _, k := range sortedAnnotationKeys(d) {
			fmt.Fprintf(w, "  %s %s\n", s.Dim.Render(k+":"), d.Annotations[k])
		}
	}

	fmt.Fprintln(w)
	t := table.New().
		Border(lipgloss.HiddenBorder()).
		BorderTop(false).BorderBottom(false).BorderLeft(false).BorderRight(false).
		BorderHeader(false).BorderColumn(false).BorderRow(false).
		Headers("LAYER", "SIZE", "DIGEST").
		StyleFunc(func(row, col int) lipgloss.Style {
			switch {
			case row == table.HeaderRow:
				return s.Header.PaddingRight(2)
			case col == 2:
				return s.Dim.PaddingRight(2)
			default:
				return lipgloss.NewStyle().PaddingRight(2)
			}
		})
	for _, l := range d.Layers {
		t.Row(shortArtifactType(l.MediaType), humanBytes(l.Size), l.Digest)
	}
	_, err := fmt.Fprintln(w, t.Render())
	return err
}

// shortArtifactType compacts a vnd media type for display.
func shortArtifactType(t string) string {
	t = strings.TrimPrefix(t, "application/vnd.")
	if i := strings.IndexByte(t, '+'); i > 0 {
		t = t[:i]
	}
	return t
}
