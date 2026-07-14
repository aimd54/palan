// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/aimd54/palan/internal/refname"
	"github.com/aimd54/palan/internal/transfer"
)

func newCpCmd(v *viper.Viper) *cobra.Command {
	return &cobra.Command{
		Use:   "cp SRC DST",
		Short: "Copy a model between registries",
		Long: `cp streams an artifact from one registry to another without touching the
local store — the mirroring workhorse for DMZ-to-air-gap promotion.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			src, err := refname.Parse(args[0], v.GetString(keyRegistryDefault))
			if err != nil {
				return err
			}
			dst, err := refname.Parse(args[1], v.GetString(keyRegistryDefault))
			if err != nil {
				return err
			}
			client, err := newTransferClient(v)
			if err != nil {
				return err
			}
			pr := newProgress(v.GetBool("quiet"))
			desc, err := client.Copy(ctx, src, dst, pr.events())
			pr.close(err)
			if err != nil {
				return err
			}
			pr.report()
			fmt.Fprintf(cmd.OutOrStdout(), "Copied %s -> %s\nDigest: %s\n", src, dst, desc.Digest)
			return nil
		},
	}
}

func newSaveCmd() *cobra.Command {
	var output string
	cmd := &cobra.Command{
		Use:   "save REF... -o FILE",
		Short: "Export models to a tar bundle for offline transfer",
		Long: `save writes the given references (with all their blobs, deduplicated)
as a tar of a standard OCI image layout. "-o -" writes to stdout.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			st, err := openStore(ctx)
			if err != nil {
				return err
			}
			unlock, err := st.RLock(ctx)
			if err != nil {
				return err
			}
			defer unlock()

			w := cmd.OutOrStdout()
			if output != "-" {
				f, err := os.Create(output) // #nosec G304 -- user-chosen output path is the point
				if err != nil {
					return err
				}
				defer func() { _ = f.Close() }()
				w = f
			}
			if err := transfer.Save(ctx, st, args, w); err != nil {
				return err
			}
			if output != "-" {
				fmt.Fprintf(cmd.ErrOrStderr(), "Saved %d reference(s) to %s\n", len(args), output)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", "", "output file (- for stdout)")
	must(cmd.MarkFlagRequired("output"))
	return cmd
}

func newLoadCmd() *cobra.Command {
	var input string
	cmd := &cobra.Command{
		Use:   "load -i FILE",
		Short: "Import models from a tar bundle",
		Long:  `load imports every tagged reference from a bundle created by save (or any tar'd OCI image layout). "-i -" reads from stdin.`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			st, err := openStore(ctx)
			if err != nil {
				return err
			}
			unlock, err := st.Lock(ctx)
			if err != nil {
				return err
			}
			defer unlock()

			r := cmd.InOrStdin()
			if input != "-" {
				f, err := os.Open(input) // #nosec G304 -- user-chosen input path is the point
				if err != nil {
					return err
				}
				defer func() { _ = f.Close() }()
				r = f
			}
			refs, err := transfer.Load(ctx, st, r)
			if err != nil {
				return err
			}
			for _, ref := range refs {
				fmt.Fprintf(cmd.OutOrStdout(), "Loaded %s\n", ref)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&input, "input", "i", "", "input file (- for stdin)")
	must(cmd.MarkFlagRequired("input"))
	return cmd
}
