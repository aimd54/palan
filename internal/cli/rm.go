// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm REF...",
		Short: "Unlink model references from the local store",
		Long:  "rm removes references; blob content stays on disk until `palan gc` reclaims it.",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
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

			for _, ref := range args {
				if err := st.Remove(ctx, ref); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Removed %s\n", ref)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Run `palan gc` to reclaim disk space.")
			return nil
		},
	}
}
