// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"sync"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/sync/errgroup"

	"github.com/aimd54/palan/internal/transfer"
)

func newLsCmd(v *viper.Viper) *cobra.Command {
	var remoteHost string
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List models in the local store or a remote registry",
		Args:  cobra.NoArgs,
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

func renderRows(w io.Writer, rows []modelRow, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(rows)
	}
	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "REF\tKIND\tFAMILY\tPARAMS\tQUANT\tFORMAT\tSIZE\tDIGEST")
	for _, r := range rows {
		digest := r.Digest
		if len(digest) > 19 { // "sha256:" + 12 hex
			digest = digest[:19]
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			r.Ref, r.Kind, orDash(r.Family), orDash(r.Params), orDash(r.Quant), orDash(r.Format), humanBytes(r.Size), digest)
	}
	return tw.Flush()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
