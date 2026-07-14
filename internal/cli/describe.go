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

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"oras.land/oras-go/v2/content"

	"github.com/aimd54/palan/internal/refname"
	"github.com/aimd54/palan/internal/store"
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
// ModelPack artifacts, the small config blob (design §7.2: metadata
// questions are answered without touching weights).
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

func renderDetail(w io.Writer, d modelDetail, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(d)
	}
	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "Ref:\t%s\n", d.Ref)
	fmt.Fprintf(tw, "Kind:\t%s\n", d.Kind)
	fmt.Fprintf(tw, "Family:\t%s\n", orDash(d.Family))
	fmt.Fprintf(tw, "Params:\t%s\n", orDash(d.Params))
	fmt.Fprintf(tw, "Quant:\t%s\n", orDash(d.Quant))
	fmt.Fprintf(tw, "Format:\t%s\n", orDash(d.Format))
	fmt.Fprintf(tw, "Size:\t%s\n", humanBytes(d.Size))
	fmt.Fprintf(tw, "Digest:\t%s\n", d.Digest)
	if d.ArtifactType != "" {
		fmt.Fprintf(tw, "Type:\t%s\n", d.ArtifactType)
	}
	fmt.Fprintf(tw, "Source:\t%s\n", d.Source)
	if len(d.Annotations) > 0 {
		fmt.Fprintln(tw, "Annotations:")
		keys := make([]string, 0, len(d.Annotations))
		for k := range d.Annotations {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
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

// shortArtifactType compacts a vnd media type for display.
func shortArtifactType(t string) string {
	t = strings.TrimPrefix(t, "application/vnd.")
	if i := strings.IndexByte(t, '+'); i > 0 {
		t = t[:i]
	}
	return t
}
