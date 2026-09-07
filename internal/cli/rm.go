// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"

	"github.com/opencontainers/go-digest"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/aimd54/palan/internal/refname"
	"github.com/aimd54/palan/internal/signing"
	"github.com/aimd54/palan/internal/store"
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

				// Anything left attached would pin its blobs forever, since
				// gc reclaims only what no tag references.
				if resolveErr != nil {
					continue
				}
				parsed, err := refname.Parse(ref, v.GetString(keyRegistryDefault))
				if err != nil {
					continue
				}
				// A signature and an attestation are addressed by the
				// model's digest rather than by its tag, so they belong to
				// every reference that resolves to it. Another tag still
				// naming this digest means the model is here under a
				// different name, and taking away what vouches for it would
				// leave that name unverifiable.
				held, err := digestStillTagged(ctx, st, desc.Digest)
				if err != nil {
					return err
				}
				if held {
					continue
				}
				// The attestation goes the same way as the signature. Both
				// are manifests naming the model as their subject, and one
				// left behind holds the model's blobs on disk just as the
				// other would.
				for _, attached := range []string{
					signing.SigRef(parsed, desc.Digest),
					signing.AttRef(parsed, desc.Digest),
				} {
					if err := st.Remove(ctx, attached); err == nil {
						fmt.Fprintf(cmd.OutOrStdout(), "Removed %s\n", attached)
					}
				}
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Run `palan gc` to reclaim disk space.")
			return nil
		},
	}
}

// digestStillTagged reports whether any reference in the store resolves to
// d. A signature and an attestation carry their own digests, so neither
// answers this about the model they are attached to.
func digestStillTagged(ctx context.Context, st *store.Store, d digest.Digest) (bool, error) {
	entries, err := st.List(ctx)
	if err != nil {
		return false, err
	}
	for _, e := range entries {
		if e.Descriptor.Digest == d {
			return true, nil
		}
	}
	return false, nil
}
