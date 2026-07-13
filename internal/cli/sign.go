// Copyright The moci Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/opencontainers/go-digest"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"
	"oras.land/oras-go/v2/registry"

	"github.com/aimd54/moci/internal/refname"
	"github.com/aimd54/moci/internal/signing"
	"github.com/aimd54/moci/internal/transfer"
)

// Config keys for verification policy.
const (
	keyVerifyRequired = "verify.required"
	keyVerifyKey      = "verify.key"
)

func newSignCmd(v *viper.Viper) *cobra.Command {
	var keyPath string
	cmd := &cobra.Command{
		Use:   "sign REF --key FILE",
		Short: "Sign a pushed model with a cosign-compatible key",
		Long: `Sign resolves REF on its registry and attaches a cosign-compatible
signature next to it (the sha256-<digest>.sig tag convention), so
'cosign verify --key' and 'moci verify' both accept it — including fully
offline. Encrypted cosign keys are supported; the password comes from
COSIGN_PASSWORD or an interactive prompt.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			ref, err := refname.Parse(args[0], v.GetString(keyRegistryDefault))
			if err != nil {
				return err
			}
			pemBytes, err := os.ReadFile(keyPath) // #nosec G304 -- user-chosen key file
			if err != nil {
				return err
			}
			signer, err := signing.LoadSigner(pemBytes, passwordFunc())
			if err != nil {
				return err
			}
			client, err := newTransferClient(v)
			if err != nil {
				return err
			}
			repo, err := client.Repository(ref)
			if err != nil {
				return err
			}
			desc, err := repo.Resolve(ctx, ref.Reference)
			if err != nil {
				return fmt.Errorf("resolving %s (sign after push): %w", ref, err)
			}
			if _, err := signing.Sign(ctx, repo, ref.Registry+"/"+ref.Repository, desc.Digest, signer); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Signed %s@%s\n", ref, desc.Digest)
			return nil
		},
	}
	cmd.Flags().StringVar(&keyPath, "key", "", "private key file (cosign.key or PEM; required)")
	must(cmd.MarkFlagRequired("key"))
	return cmd
}

func newVerifyCmd(v *viper.Viper) *cobra.Command {
	var keyPath string
	cmd := &cobra.Command{
		Use:   "verify REF --key FILE",
		Short: "Verify a model's signature against a public key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			ref, err := refname.Parse(args[0], v.GetString(keyRegistryDefault))
			if err != nil {
				return err
			}
			client, err := newTransferClient(v)
			if err != nil {
				return err
			}
			repo, err := client.Repository(ref)
			if err != nil {
				return err
			}
			desc, err := repo.Resolve(ctx, ref.Reference)
			if err != nil {
				return err
			}
			if err := verifyDigest(ctx, v, keyPath, client, ref, desc.Digest); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Verified %s@%s\n", ref, desc.Digest)
			return nil
		},
	}
	cmd.Flags().StringVar(&keyPath, "key", "", "public key file (cosign.pub; default: verify.key from the config)")
	return cmd
}

// verifyDigest runs signature verification for a resolved digest, using the
// explicit key path or the configured verify.key.
func verifyDigest(ctx context.Context, v *viper.Viper, keyPath string, client *transfer.Client, ref registry.Reference, d digest.Digest) error {
	if keyPath == "" {
		keyPath = v.GetString(keyVerifyKey)
	}
	if keyPath == "" {
		return fmt.Errorf("no verification key configured: pass --key or set verify.key in the config")
	}
	pemBytes, err := os.ReadFile(keyPath) // #nosec G304 -- user-chosen key file
	if err != nil {
		return fmt.Errorf("reading verification key: %w", err)
	}
	verifier, err := signing.LoadVerifier(pemBytes)
	if err != nil {
		return err
	}
	repo, err := client.Repository(ref)
	if err != nil {
		return err
	}
	if err := signing.Verify(ctx, repo, ref.Registry+"/"+ref.Repository, d, verifier); err != nil {
		return fmt.Errorf("signature verification FAILED for %s@%s: %w", ref, d, err)
	}
	return nil
}

// passwordFunc sources the key password: COSIGN_PASSWORD, else a prompt on
// a terminal, else no password (unencrypted keys need none).
func passwordFunc() signing.PassFunc {
	if pw, ok := os.LookupEnv("COSIGN_PASSWORD"); ok {
		return func() ([]byte, error) { return []byte(pw), nil }
	}
	if term.IsTerminal(int(os.Stdin.Fd())) {
		return func() ([]byte, error) {
			fmt.Fprint(os.Stderr, "Key password: ")
			b, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			return b, err
		}
	}
	return nil
}
