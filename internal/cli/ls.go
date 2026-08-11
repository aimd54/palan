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
	"sync"
	"text/tabwriter"

	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/table"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/sync/errgroup"

	"github.com/aimd54/palan/internal/signing"
	"github.com/aimd54/palan/internal/transfer"
	"github.com/aimd54/palan/internal/ui"
)

func newLsCmd(v *viper.Viper) *cobra.Command {
	var remoteHost string
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List models in the local store or a remote registry",
		Example: `  # Models held locally
  palan ls

  # Models on a registry, as JSON
  palan ls --remote registry.internal --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			var rows []modelRow
			var err error
			if remoteHost != "" {
				rows, err = listRemote(ctx, v, remoteHost)
			} else {
				rows, err = listLocal(ctx)
			}
			if err != nil {
				return err
			}
			sort.Slice(rows, func(i, j int) bool { return rows[i].Ref < rows[j].Ref })
			return renderRows(cmd.OutOrStdout(), rows, asJSON)
		},
	}
	cmd.Flags().StringVar(&remoteHost, "remote", "", "list a remote registry (host[:port]) instead of the local store")
	cmd.Flags().BoolVar(&asJSON, "json", false, "output JSON")
	return cmd
}

func listLocal(ctx context.Context) ([]modelRow, error) {
	st, err := openStore(ctx)
	if err != nil {
		return nil, err
	}
	unlock, err := st.RLock(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()

	entries, err := st.List(ctx)
	if err != nil {
		return nil, err
	}
	rows := make([]modelRow, 0, len(entries))
	for _, e := range entries {
		// Signatures are tagged manifests like anything else, but they are
		// attached to a model rather than being one, so listing them as
		// models would be noise.
		if signing.IsSigTag(e.Ref) {
			continue
		}
		rows = append(rows, describeRef(ctx, st.OCI(), e.Ref, e.Descriptor))
	}
	return rows, nil
}

func listRemote(ctx context.Context, v *viper.Viper, host string) ([]modelRow, error) {
	client, err := newTransferClient(v)
	if err != nil {
		return nil, err
	}
	reg, err := client.Registry(host)
	if err != nil {
		return nil, err
	}

	var repos []string
	if err := reg.Repositories(ctx, "", func(page []string) error {
		repos = append(repos, page...)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("listing repositories on %s (does the registry expose the catalog API?): %w", host, err)
	}

	var mu sync.Mutex
	var rows []modelRow
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(transfer.DefaultConcurrency)
	for _, repoName := range repos {
		g.Go(func() error {
			repo, err := reg.Repository(gctx, repoName)
			if err != nil {
				return err
			}
			return repo.Tags(gctx, "", func(tags []string) error {
				for _, tag := range tags {
					desc, err := repo.Resolve(gctx, tag)
					if err != nil {
						continue // tag vanished or unsupported manifest; skip
					}
					row := describeRef(gctx, repo, host+"/"+repoName+":"+tag, desc)
					mu.Lock()
					rows = append(rows, row)
					mu.Unlock()
				}
				return nil
			})
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return rows, nil
}

// lsColumns is the listing's shape, shared by both renderers so the styled
// and plain forms cannot drift into showing different things.
var lsColumns = []string{"REF", "KIND", "FAMILY", "PARAMS", "ENCODING", "FORMAT", "SIZE", "DIGEST"}

func lsCells(r modelRow) []string {
	digest := r.Digest
	if len(digest) > 19 { // "sha256:" + 12 hex
		digest = digest[:19]
	}
	return []string{
		r.Ref, r.Kind, orDash(r.Family), orDash(r.Params),
		orDash(encoding(r)), orDash(r.Format), humanBytes(r.Size), digest,
	}
}

// encoding is how the weights are stored: a quantization scheme when the model
// names one, the numeric type otherwise. A model states one or the other, so a
// single column reports both without losing anything, and a listing of GGUF
// models is not left with a column that is always empty.
func encoding(r modelRow) string {
	if r.Quant != "" {
		return r.Quant
	}
	return r.Precision
}

// renderRows writes the listing.
//
// Two renderers, deliberately. tabwriter measures a column in bytes, so an
// escape sequence anywhere but the last column silently destroys alignment,
// and a table library that measures displayed width is the only way to colour
// the middle of a row. Plain output keeps the tabwriter it has always used
// rather than being re-flowed by a different layout engine, because that
// output is what pipelines parse (see render_test.go).
func renderRows(w io.Writer, rows []modelRow, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(rows)
	}
	if s := ui.New(w); ui.Enabled(w) {
		return renderRowsStyled(w, rows, s)
	}

	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	fmt.Fprintln(tw, strings.Join(lsColumns, "\t"))
	for _, r := range rows {
		fmt.Fprintln(tw, strings.Join(lsCells(r), "\t"))
	}
	return tw.Flush()
}

func renderRowsStyled(w io.Writer, rows []modelRow, s ui.Styles) error {
	t := table.New().
		Border(lipgloss.HiddenBorder()).
		BorderTop(false).BorderBottom(false).BorderLeft(false).BorderRight(false).
		BorderHeader(false).BorderColumn(false).BorderRow(false).
		Headers(lsColumns...).
		StyleFunc(func(row, col int) lipgloss.Style {
			switch {
			case row == table.HeaderRow:
				return s.Header.PaddingRight(2)
			case col == 0:
				return s.Accent.PaddingRight(2)
			case col == len(lsColumns)-1:
				return s.Dim.PaddingRight(2)
			default:
				return lipgloss.NewStyle().PaddingRight(2)
			}
		})
	for _, r := range rows {
		t.Row(lsCells(r)...)
	}
	_, err := fmt.Fprintln(w, t.Render())
	return err
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
