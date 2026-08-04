// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/aimd54/palan/internal/refname"
	"github.com/aimd54/palan/internal/signing"
)

func newRmCmd(v *viper.Viper) *cobra.Command {
	return &cobra.Command{
		Use:   "rm REF...",
		Short: "Unlink model references from the local store",
		Example: `  # Unlink a model, then reclaim its blobs
  palan rm llm/qwen3:8b-q4
  palan gc`,
		Long: "rm removes references; blob content stays on disk until `palan gc` reclaims it.",
		// At a terminal, no reference opens the store to choose from; anywhere
		// else it stays an error, so a script cannot hang waiting for input.
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			// Picked before the store is locked for writing: the picker reads
			// the store itself, and would deadlock against an exclusive lock.
			if len(args) == 0 {
				chosen, err := refOrPick(ctx, cmd, args, "Remove which model?")
				if err != nil {
					return err
				}
				args = []string{chosen}
			}
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
				// Resolve before unlinking: the signature is addressed by the
				// model's digest, which is unreachable once the tag is gone.
				desc, resolveErr := st.Resolve(ctx, ref)
				if err := st.Remove(ctx, ref); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Removed %s\n", ref)

				// A signature left behind would pin its blobs forever, since
				// gc reclaims only what no tag references.
				if resolveErr != nil {
					continue
				}
				parsed, err := refname.Parse(ref, v.GetString(keyRegistryDefault))
				if err != nil {
					continue
				}
				sigRef := signing.SigRef(parsed, desc.Digest)
				if err := st.Remove(ctx, sigRef); err == nil {
					fmt.Fprintf(cmd.OutOrStdout(), "Removed %s\n", sigRef)
				}
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Run `palan gc` to reclaim disk space.")
			return nil
		},
	}
}
