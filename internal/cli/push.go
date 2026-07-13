// Copyright The moci Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/aimd54/moci/internal/refname"
)

func newPushCmd(v *viper.Viper) *cobra.Command {
	return &cobra.Command{
		Use:   "push REF",
		Short: "Push a locally-stored model to its registry",
		Long: `Push uploads the model tagged REF in the local store to its registry.
Blobs the registry already has are skipped, and where supported, blobs known
from sibling repositories are mounted server-side instead of re-uploaded.`,
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

			client, err := newTransferClient(v)
			if err != nil {
				return err
			}
			pr := newProgress(v.GetBool("quiet"))
			desc, err := client.Push(ctx, st, ref, pr.events())
			pr.close(err)
			if err != nil {
				return err
			}
			pr.report()
			fmt.Fprintf(cmd.OutOrStdout(), "Pushed %s\nDigest: %s\n", ref, desc.Digest)
			return nil
		},
	}
}
