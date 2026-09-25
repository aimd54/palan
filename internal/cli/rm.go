// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"oras.land/oras-go/v2/errdef"

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
		Long: `rm removes references; blob content stays on disk until ` + "`palan gc`" + ` reclaims it.

A model's signature and attestation go with it unless the store still
holds the model: while another tag names it, while an index or other
tagged content holds it, or while the store keeps the model it was derived
from.

A signature, attestation or other description removed by its own
reference loses only that reference when another names it too. Otherwise
it is deleted together with every tagged description of it under every
name, and theirs in turn, such as an attestation over a signature, and
each is listed. The removal is refused while other content in the store
refers to any of them.`,
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

			taken := map[string]bool{}
			for _, ref := range args {
				// Already reported as taken with an earlier argument.
				if taken[ref] {
					continue
				}
				// Resolve before unlinking: the signature is addressed by the
				// model's digest, which is unreachable once the tag is gone.
				desc, resolveErr := st.Resolve(ctx, ref)
				along, err := st.RemoveReporting(ctx, ref)
				reportRemoved(cmd.OutOrStdout(), taken, along...)
				if err != nil {
					return err
				}
				reportRemoved(cmd.OutOrStdout(), taken, ref)

				// What is attached to the model goes with it, unless the
				// store still holds the model.
				if resolveErr != nil {
					continue
				}
				parsed, err := refname.Parse(ref, v.GetString(keyRegistryDefault))
				if err != nil {
					continue
				}
				// A signature and an attestation belong to the model's digest,
				// so they stay for as long as the store holds the model.
				attachedRefs := []string{
					signing.SigRef(parsed, desc.Digest),
					signing.AttRef(parsed, desc.Digest),
				}
				held, err := st.Held(ctx, desc)
				if err != nil {
					return err
				}
				if held {
					for _, attached := range attachedRefs {
						if _, err := st.Resolve(ctx, attached); err == nil {
							fmt.Fprintf(cmd.OutOrStdout(), "Kept %s: the store still holds what it describes\n", attached)
						}
					}
					continue
				}
				// Refused only when the model's manifest is missing and
				// something still lists its signature, which is reported.
				for _, attached := range attachedRefs {
					along, err := st.RemoveReporting(ctx, attached)
					reportRemoved(cmd.OutOrStdout(), taken, along...)
					switch {
					case errors.Is(err, errdef.ErrNotFound):
						continue
					case err != nil:
						return fmt.Errorf("removing %s with %s: %w", attached, ref, err)
					}
					reportRemoved(cmd.OutOrStdout(), taken, attached)
				}
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Run `palan gc` to reclaim disk space.")
			return nil
		},
	}
}

// reportRemoved prints each reference removed and records it as taken.
func reportRemoved(w io.Writer, taken map[string]bool, refs ...string) {
	for _, r := range refs {
		taken[r] = true
		fmt.Fprintf(w, "Removed %s\n", r)
	}
}
