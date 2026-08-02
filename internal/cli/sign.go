// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/opencontainers/go-digest"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"
	oras "oras.land/oras-go/v2"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry"

	"github.com/aimd54/palan/internal/refname"
	"github.com/aimd54/palan/internal/signing"
	"github.com/aimd54/palan/internal/store"
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
'cosign verify --key' and 'palan verify' both accept it. The signature then
travels with the model through pull, save, and cp, and verifying it needs no
transparency log, no certificate authority, and no registry once it is in the
local store. Encrypted cosign keys are supported; the password comes from
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
		Long: `Verify checks a model's signature against a public key.

A model already in the local store is verified from there, so verification
needs no registry, no transparency log, and no certificate authority. Anything
else is resolved on its registry. The output names the source, since a local
result describes the copy you hold rather than what the registry serves now.`,
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

			src, err := resolveVerifySource(ctx, st, v, ref)
			if err != nil {
				return err
			}
			if err := verifyDigest(ctx, v, keyPath, src, ref); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Verified %s@%s\n  source: %s\n", ref, src.digest, src.name)
			return nil
		},
	}
	cmd.Flags().StringVar(&keyPath, "key", "", "public key file (cosign.pub; default: verify.key from the config)")
	return cmd
}

// verifySource is where an artifact and its signature are read from.
type verifySource struct {
	target oras.ReadOnlyTarget
	sigRef string
	digest digest.Digest
	name   string
}

// resolveVerifySource prefers the local store, so verification works with no
// network whenever the answer is already on disk, and falls back to the
// registry otherwise.
//
// Holding the model locally is not enough: the store must hold its signature
// too. Signing happens after a push, so a model packed locally and signed
// afterwards has its signature only on the registry, and treating the local
// copy as authoritative there would report an artifact as unsigned when it is
// not. Only a genuine miss falls through; a store that fails for any other
// reason is an error rather than a silent trip to the network.
func resolveVerifySource(ctx context.Context, st *store.Store, v *viper.Viper, ref registry.Reference) (verifySource, error) {
	local, localErr := st.Resolve(ctx, ref.String())
	switch {
	case localErr == nil:
		sigRef := signing.SigRef(ref, local.Digest)
		_, sigErr := st.Resolve(ctx, sigRef)
		switch {
		case sigErr == nil:
			return verifySource{
				target: st.OCI(),
				sigRef: sigRef,
				digest: local.Digest,
				name:   "local store",
			}, nil
		case !errors.Is(sigErr, errdef.ErrNotFound):
			return verifySource{}, fmt.Errorf("reading the local store: %w", sigErr)
		}
	case !errors.Is(localErr, errdef.ErrNotFound):
		return verifySource{}, fmt.Errorf("reading the local store: %w", localErr)
	}

	client, err := newTransferClient(v)
	if err != nil {
		return verifySource{}, err
	}
	repo, err := client.Repository(ref)
	if err != nil {
		return verifySource{}, err
	}
	desc, err := repo.Resolve(ctx, ref.Reference)
	if err != nil {
		if localErr == nil {
			// Say what is actually known, rather than reporting a bare
			// network failure for a model that is sitting right here.
			return verifySource{}, fmt.Errorf(
				"no signature for %s in the local store, and the registry could not be reached: %w", ref, err)
		}
		return verifySource{}, err
	}
	return verifySource{
		target: repo,
		sigRef: signing.SigTag(desc.Digest),
		digest: desc.Digest,
		name:   "registry",
	}, nil
}

// verifyGate returns a check that refuses a model whose signature does not
// verify, or nil when neither the flag nor verify.required asks for one.
//
// run and serve share it so that a model is checked at the moment it is about
// to be served, not only when it entered the store. Source selection is left
// to resolveVerifySource, which reads the store when it holds the signature
// and the registry otherwise, so an air-gapped host needs no network and a
// model signed after a local pack still verifies.
func verifyGate(v *viper.Viper, st *store.Store, doVerify bool, keyPath string) func(context.Context, string) error {
	if !doVerify && !v.GetBool(keyVerifyRequired) {
		return nil
	}
	return func(ctx context.Context, raw string) error {
		ref, err := refname.Parse(raw, v.GetString(keyRegistryDefault))
		if err != nil {
			return err
		}
		src, err := resolveVerifySource(ctx, st, v, ref)
		if err != nil {
			return err
		}
		return verifyDigest(ctx, v, keyPath, src, ref)
	}
}

// verifyDigest runs signature verification against an already-resolved
// source, using the explicit key path or the configured verify.key. Callers
// choose the source, so a pre-download gate can insist on the registry while
// an offline check reads the store.
func verifyDigest(ctx context.Context, v *viper.Viper, keyPath string, src verifySource, ref registry.Reference) error {
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
	repoRef := ref.Registry + "/" + ref.Repository
	if err := signing.Verify(ctx, src.target, src.sigRef, repoRef, src.digest, verifier); err != nil {
		return fmt.Errorf("signature verification FAILED for %s@%s: %w", ref, src.digest, err)
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
