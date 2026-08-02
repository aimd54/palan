// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	oras "oras.land/oras-go/v2"

	"github.com/aimd54/palan/internal/refname"
	"github.com/aimd54/palan/internal/signing"
	"github.com/aimd54/palan/internal/transfer"
)

func newCpCmd(v *viper.Viper) *cobra.Command {
	return &cobra.Command{
		Use:   "cp SRC DST",
		Short: "Copy a model between registries",
		Long: `cp streams an artifact from one registry to another without touching the
local store: the mirroring workhorse for moving artifacts from a connected
registry into an offline one.`,
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
			signatures, err := transfer.Save(ctx, st, args, w)
			if err != nil {
				return err
			}
			if output != "-" {
				fmt.Fprintf(cmd.ErrOrStderr(), "Saved %d reference(s) to %s\n", len(args), output)
				if signatures > 0 {
					fmt.Fprintf(cmd.ErrOrStderr(), "Included %d signature(s)\n", signatures)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", "", "output file (- for stdout)")
	must(cmd.MarkFlagRequired("output"))
	return cmd
}

func newLoadCmd(v *viper.Viper) *cobra.Command {
	var (
		input     string
		doVerify  bool
		verifyKey string
	)
	cmd := &cobra.Command{
		Use:   "load -i FILE",
		Short: "Import models from a tar bundle",
		Long: `load imports every tagged reference from a bundle created by save (or any tar'd OCI image layout). "-i -" reads from stdin.

With --verify, or with verify.required set in the config, every model in the
bundle must carry a valid signature before anything is imported. A bundle is
whatever a courier handed over, so this is the moment its provenance is worth
deciding. Verification reads the bundle itself and needs no registry.`,
		Args: cobra.NoArgs,
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

			var opts []transfer.LoadOption
			if doVerify || v.GetBool(keyVerifyRequired) {
				opts = append(opts, transfer.WithBeforeImport(bundleVerifier(v, verifyKey, cmd.ErrOrStderr())))
			}
			refs, err := transfer.Load(ctx, st, r, opts...)
			if err != nil {
				return err
			}
			for _, ref := range refs {
				if signing.IsSigTag(ref) {
					continue // travelled with its model; not a model itself
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Loaded %s\n", ref)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&input, "input", "i", "", "input file (- for stdin)")
	cmd.Flags().BoolVar(&doVerify, "verify", false, "require a valid signature on every model in the bundle before importing")
	cmd.Flags().StringVar(&verifyKey, "verify-key", "", "public key for --verify (default: verify.key from the config)")
	must(cmd.MarkFlagRequired("input"))
	return cmd
}

// bundleVerifier checks every model in a bundle against the configured key,
// reading the bundle's own layout so no registry is involved. Returning an
// error from here aborts the import, which is why the check runs before any
// content reaches the store: a bundle that fails leaves nothing behind.
//
// A bundle is attacker-controlled, so nothing may be excused from the check on
// the strength of its name alone. Signature-shaped references are skipped in
// the first pass and then required, in the second, to be the signature of a
// model that just verified. Without that, tagging a model
// `...:sha256-<64 hex>.sig` would carry it past verification untouched.
func bundleVerifier(v *viper.Viper, keyPath string, out io.Writer) func(context.Context, oras.ReadOnlyTarget, []string) error {
	return func(ctx context.Context, bundle oras.ReadOnlyTarget, refs []string) error {
		expectedSignatures := make(map[string]struct{}, len(refs))
		for _, raw := range refs {
			if signing.IsSigTag(raw) {
				continue
			}
			ref, err := refname.Parse(raw, "")
			if err != nil {
				return fmt.Errorf("bundle reference %q: %w", raw, err)
			}
			desc, err := bundle.Resolve(ctx, raw)
			if err != nil {
				return err
			}
			src := verifySource{
				target: bundle,
				sigRef: signing.SigRef(ref, desc.Digest),
				digest: desc.Digest,
				name:   "bundle",
			}
			if err := verifyDigest(ctx, v, keyPath, src, ref); err != nil {
				return err
			}
			expectedSignatures[src.sigRef] = struct{}{}
			fmt.Fprintf(out, "Verified %s@%s\n", ref, desc.Digest)
		}

		for _, raw := range refs {
			if !signing.IsSigTag(raw) {
				continue
			}
			if _, ok := expectedSignatures[raw]; !ok {
				return fmt.Errorf(
					"bundle contains %q, which is not the signature of any verified model; refusing to import", raw)
			}
		}
		return nil
	}
}
