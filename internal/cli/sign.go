// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"
	oras "oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry"

	"github.com/aimd54/palan/internal/attest"
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
		Example: `  # Sign after pushing; the signature lands beside the model
  palan push registry.internal/llm/qwen3:8b-q4
  palan sign registry.internal/llm/qwen3:8b-q4 --key cosign.key`,
		Long: `Sign resolves REF on its registry and attaches a cosign-compatible
signature next to it (the sha256-<digest>.sig tag convention), so
'cosign verify --key' and 'palan verify' both accept it. The signature also
names the model as its subject, so the registry indexes it through the
referrers API and tools that look there find it too.

The signature then travels with the model through pull, save, and cp, and
verifying it needs no transparency log, no certificate authority, and no
registry once it is in the local store. Encrypted cosign keys are supported;
the password comes from COSIGN_PASSWORD or an interactive prompt.

Where the layers record where their files were fetched from, sign also
writes a source attestation: a signed statement, stored the same two ways
as the signature, binding each layer to the upstream file it holds. An
artifact packed purely from local disk has no upstream to name, and sign
says so rather than leaving the absence unremarked.`,
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
			if _, err := signing.Sign(ctx, repo, ref.Registry+"/"+ref.Repository, desc, signer); err != nil {
				return err
			}
			// Reported here, before the attestation is attempted, because
			// from this point the signature is on the registry whatever
			// happens next. Saying so only at the end would report total
			// failure for a partial success, and the half that succeeded
			// is the half verification depends on.
			fmt.Fprintf(cmd.OutOrStdout(), "Signed %s@%s\n", ref, desc.Digest)

			// Where the layers record where their files came from, sign
			// also attests to it. An artifact packed purely from local
			// disk has nothing to state, so nothing is written for it.
			raw, err := content.FetchAll(ctx, repo, desc)
			if err != nil {
				return fmt.Errorf("fetching %s to read its layers: %w", ref, err)
			}
			var man ocispec.Manifest
			if err := json.Unmarshal(raw, &man); err != nil {
				return fmt.Errorf("decoding %s manifest: %w", ref, err)
			}
			layers := signing.LayersFromManifest(man)
			if len(layers) > 0 {
				envelope, err := attest.Build(desc, layers, signer)
				if err != nil {
					return attestationNotWritten(ref, desc.Digest, err)
				}
				if _, err := signing.PushAttestation(ctx, repo, desc, envelope); err != nil {
					return attestationNotWritten(ref, desc.Digest, err)
				}
			}
			// Say either way. An artifact whose layers record no source is
			// signed without an attestation, and a reader who is not told
			// so has no way to tell that from one where the statement was
			// written: both exit 0 saying "Signed", and verify later
			// reports no provenance for either.
			// Both outcomes go to stdout, because both describe what this
			// command did and a caller reading one stream must not see a
			// different answer from a caller reading the other. The
			// denominator matters: without it a partly-sourced artifact
			// reads exactly like a fully-sourced one.
			if len(layers) > 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "Attested the source of %d of %d layer(s)\n", len(layers), len(man.Layers))
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "No source attestation written: none of this artifact's layers record an upstream source")
			}
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
		Example: `  # Verify against a registry, or from the local store when it holds the signature
  palan verify registry.internal/llm/qwen3:8b-q4 --key cosign.pub`,
		Long: `Verify checks a model's signature against a public key.

A model already in the local store is verified from there, so verification
needs no registry, no transparency log, and no certificate authority. Anything
else is resolved on its registry. The output names the source, since a local
result describes the copy you hold rather than what the registry serves now.

The signature is looked for under its tag first, then among the referrers of
the model, so a signature written by an OCI 1.1 signing tool is checked even
though it carries no tag.

Where sign also wrote a statement of the model's sources, verify checks it
against the same key and against the model's own layers, and names what the
layers came from. A model with no such statement verifies exactly as it did
before: requiring one is a policy for something else to enforce, not a fact
this command asserts.`,
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
			report, err := checkAttestation(ctx, v, keyPath, src, ref)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Verified %s@%s\n  source: %s\n", ref, src.subject.Digest, src.name)
			for _, p := range report.provenance {
				fmt.Fprintf(cmd.OutOrStdout(), "  provenance: %s\n", p)
			}
			// On the same stream as the result it qualifies: a reader who
			// sees "Verified" and not this line would take the artifact's
			// provenance to have been checked.
			if report.warning != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", report.warning)
			}
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
	// subject is the artifact being verified. The whole descriptor is needed,
	// not just its digest, because a signature may be attached as a referrer
	// of it rather than under a tag.
	subject ocispec.Descriptor
	name    string
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
//
// A signature may be tagged or attached as a referrer, and a bundle imported
// from an OCI 1.1 signing tool carries only the latter, so both count as
// holding it.
func resolveVerifySource(ctx context.Context, st *store.Store, v *viper.Viper, ref registry.Reference) (verifySource, error) {
	local, localErr := st.Resolve(ctx, ref.String())
	switch {
	case localErr == nil:
		sigRef := signing.SigRef(ref, local.Digest)
		held, sigErr := storeHoldsSignature(ctx, st, sigRef, local)
		switch {
		case sigErr != nil:
			return verifySource{}, fmt.Errorf("reading the local store: %w", sigErr)
		case held:
			return verifySource{
				target:  st.OCI(),
				sigRef:  sigRef,
				subject: local,
				name:    "local store",
			}, nil
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
		target:  repo,
		sigRef:  signing.SigTag(desc.Digest),
		subject: desc,
		name:    "registry",
	}, nil
}

// storeHoldsSignature reports whether the store can verify this artifact
// without a network, either from the signature tag or from a signature
// attached to the artifact as a referrer.
func storeHoldsSignature(ctx context.Context, st *store.Store, sigRef string, subject ocispec.Descriptor) (bool, error) {
	switch _, err := st.Resolve(ctx, sigRef); {
	case err == nil:
		return true, nil
	case !errors.Is(err, errdef.ErrNotFound):
		return false, err
	}
	refs, err := registry.Referrers(ctx, st.OCI(), subject, signing.ArtifactTypeSignature)
	if err != nil {
		// The store holds the model but cannot answer for its predecessors.
		// That is not a signature verdict, so fall through to the registry.
		return false, nil //nolint:nilerr // a store that cannot list referrers simply has none to offer
	}
	return len(refs) > 0, nil
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
	verifier, err := resolveVerifyKey(v, keyPath)
	if err != nil {
		return err
	}
	repoRef := ref.Registry + "/" + ref.Repository
	if err := signing.Verify(ctx, src.target, src.sigRef, repoRef, src.subject, verifier); err != nil {
		return fmt.Errorf("signature verification FAILED for %s@%s: %w", ref, src.subject.Digest, err)
	}
	return nil
}

// resolveVerifyKey loads the verifier for keyPath, or for verify.key from
// the config when keyPath is empty. Both the signature check and the
// attestation check apply the same key to the same artifact.
func resolveVerifyKey(v *viper.Viper, keyPath string) (signature.Verifier, error) {
	if keyPath == "" {
		keyPath = v.GetString(keyVerifyKey)
	}
	if keyPath == "" {
		return nil, fmt.Errorf("no verification key configured: pass --key or set verify.key in the config")
	}
	pemBytes, err := os.ReadFile(keyPath) // #nosec G304 -- user-chosen key file
	if err != nil {
		return nil, fmt.Errorf("reading verification key: %w", err)
	}
	return signing.LoadVerifier(pemBytes)
}

// checkAttestation looks for a statement of src's sources and, when one
// exists, verifies it against the same key verifyDigest already checked the
// signature with, then holds every layer it records against the artifact's
// own manifest. It returns one line per distinct source the layers came
// from, for the caller to report.
//
// An absent attestation is not a failure: requiring one is a policy for
// something else to enforce, and reporting the same output as an artifact
// with no such statement at all is the correct answer here, not a missing
// feature.
func checkAttestation(ctx context.Context, v *viper.Viper, keyPath string, src verifySource, ref registry.Reference) (attestationReport, error) {
	envelope, err := signing.FetchAttestation(ctx, src.target, src.subject)
	switch {
	case errors.Is(err, attest.ErrNoAttestation):
		return missingAttestation(ctx, src)
	case err != nil:
		return attestationReport{}, fmt.Errorf("fetching the attestation for %s@%s: %w", ref, src.subject.Digest, err)
	}

	verifier, err := resolveVerifyKey(v, keyPath)
	if err != nil {
		return attestationReport{}, err
	}
	layers, err := attest.Verify(envelope, src.subject, verifier)
	if err != nil {
		return attestationReport{}, fmt.Errorf("attestation verification FAILED for %s@%s: %w", ref, src.subject.Digest, err)
	}

	raw, err := content.FetchAll(ctx, src.target, src.subject)
	if err != nil {
		return attestationReport{}, fmt.Errorf("fetching %s to check its layers: %w", ref, err)
	}
	var man ocispec.Manifest
	if err := json.Unmarshal(raw, &man); err != nil {
		return attestationReport{}, fmt.Errorf("decoding %s manifest: %w", ref, err)
	}
	if err := attestationMatchesManifest(layers, man); err != nil {
		return attestationReport{}, fmt.Errorf("attestation for %s@%s does not match its artifact: %w", ref, src.subject.Digest, err)
	}
	return attestationReport{provenance: provenanceLines(layers)}, nil
}

// attestationReport is what verify learned about an artifact's sources: one
// provenance line per distinct source, and a warning when the artifact
// looks like it should have carried a statement and did not. The two are
// separate because they are not the same claim; a warning printed as a
// provenance line would read as provenance.
type attestationReport struct {
	provenance []string
	warning    string
}

// attestationMatchesManifest holds an attestation's layer records against
// man's actual layers. A record naming a layer the manifest lacks, a layer
// carrying a source annotation with no record, and a record whose fields
// disagree with what the manifest itself records, each refuse, and each
// refusal names what is wrong.
func attestationMatchesManifest(attested []attest.Layer, man ocispec.Manifest) error {
	want := signing.LayersFromManifest(man)

	// Records are matched on the whole record rather than on the digest,
	// and counted rather than merely marked, because two layers can hold
	// byte-identical content from different sources: two repositories
	// shipping the same licence file is ordinary. Keyed by digest alone,
	// one such layer's record would overwrite the other's, and a statement
	// naming only one of them would be accepted as covering both.
	remaining := make(map[layerKey]int, len(want))
	sourced := make(map[string]bool, len(want))
	for _, l := range want {
		remaining[layerOf(l)]++
		sourced[l.Digest] = true
	}
	haveDigest := make(map[string]bool, len(man.Layers))
	for _, l := range man.Layers {
		haveDigest[l.Digest.String()] = true
	}

	for _, a := range attested {
		if k := layerOf(a); remaining[k] > 0 {
			remaining[k]--
			continue
		}
		if !haveDigest[a.Digest] {
			return fmt.Errorf("names layer %s, which this artifact does not have", a.Digest)
		}
		if !sourced[a.Digest] {
			return fmt.Errorf("names layer %s, but the artifact's manifest records no source for it", a.Digest)
		}
		// The artifact does record a source for this digest, so either the
		// fields disagree or the attestation claims that layer more times
		// than the artifact has it. Report against a layer sharing the
		// digest, which is what a reader needs to see the disagreement.
		return unmatchedRecord(a, want)
	}

	// Reported in the manifest's own layer order rather than by walking the
	// map, so that an artifact with more than one unattested layer names the
	// same one on every run.
	for _, w := range want {
		if remaining[layerOf(w)] > 0 {
			return fmt.Errorf("layer %s (%s) carries a source annotation but the attestation has no record for it", w.Digest, w.Path)
		}
	}
	return nil
}

// missingAttestation decides what to say about an artifact that carries no
// statement of its sources. Most carry none and nothing is owed, but an
// artifact whose own layers record where they were fetched from is a
// different case: it was packed from upstream, so a statement should exist
// and does not.
//
// That is the state a failed attestation fetch leaves behind, and the state
// anyone able to write to a store can produce by deleting one tag. Nothing
// is forged and the signature still verifies, so the whole event is silent
// unless it is said out loud. It is reported rather than refused, because
// requiring a statement is a policy question and the artifact is not proven
// wrong by lacking one, only unproven.
//
// This reads the manifest that is already being verified and asks no
// registry anything it was not going to ask.
func missingAttestation(ctx context.Context, src verifySource) (attestationReport, error) {
	// A manifest that cannot be read or decoded is reported, not passed
	// over. Returning nothing here would answer exactly as an artifact that
	// legitimately owes no statement does, and this is the one place where
	// that answer is being decided: someone who can delete a tag to strip an
	// attestation can delete one more file to silence the report of it.
	// The artifact's signature verified, so this is a warning rather than a
	// refusal.
	raw, err := content.FetchAll(ctx, src.target, src.subject)
	if err != nil {
		return attestationReport{warning: fmt.Sprintf(
			"WARNING: no attestation is present, and this artifact's manifest could not be read to say whether one was owed: %v", err)}, nil
	}
	var man ocispec.Manifest
	if err := json.Unmarshal(raw, &man); err != nil {
		return attestationReport{warning: fmt.Sprintf(
			"WARNING: no attestation is present, and this artifact's manifest could not be decoded to say whether one was owed: %v", err)}, nil
	}
	claimed := signing.LayersFromManifest(man)
	if len(claimed) == 0 {
		return attestationReport{}, nil
	}
	return attestationReport{warning: fmt.Sprintf(
		"WARNING: %d layer(s) record an upstream source but no attestation is present, so this model's provenance cannot be checked",
		len(claimed))}, nil
}

// attestationNotWritten explains a failure that leaves the signature
// published and the attestation absent. That pair verifies cleanly and
// reports no provenance, so it is indistinguishable from a model that was
// never packed from an upstream source, and an operator who is not told
// which half landed will either retry a push that already succeeded or
// conclude the model is unsigned when it is not.
func attestationNotWritten(ref registry.Reference, d digest.Digest, err error) error {
	return fmt.Errorf(
		"the signature for %s@%s is on the registry, but its source attestation could not be written, "+
			"so the model verifies with no provenance: %w", ref, d, err)
}

// layerKey is what makes two layer records the same record: which layer it
// is, and everything the statement asserts about where it came from.
//
// Spelled out rather than using attest.Layer itself as the map key, because
// that is the type the statement is encoded from. A field added to it later
// would silently join the matching rule, and every artifact signed by an
// earlier release, whose statement cannot carry the new field, would start
// refusing with no compiler error to say why.
type layerKey struct {
	digest, repo, path, revision, published string
}

func layerOf(l attest.Layer) layerKey {
	return layerKey{
		digest:    l.Digest,
		repo:      l.Repo,
		path:      l.Path,
		revision:  l.Revision,
		published: l.Published,
	}
}

// unmatchedRecord explains why a records nothing in want, given that want
// holds at least one layer of the same digest. It reports the first such
// layer, preferring a difference in the source fields over one in the
// published digest, so the message names the more consequential
// disagreement when both differ.
func unmatchedRecord(a attest.Layer, want []attest.Layer) error {
	// A record identical to one of the artifact's layers is not a
	// disagreement about where that layer came from: the statement simply
	// lists it more times than the artifact contains it. Said any other
	// way, the message sends a reader looking for a source mismatch that
	// does not exist.
	for _, w := range want {
		if layerOf(w) == layerOf(a) {
			return fmt.Errorf("layer %s: the attestation records it more times than this artifact contains it", a.Digest)
		}
	}
	for _, w := range want {
		if w.Digest != a.Digest {
			continue
		}
		if a.Repo != w.Repo || a.Path != w.Path || a.Revision != w.Revision {
			return fmt.Errorf("layer %s: attestation records %s %s@%s, the artifact's manifest records %s %s@%s",
				a.Digest, a.Repo, a.Path, a.Revision, w.Repo, w.Path, w.Revision)
		}
		if a.Published != w.Published {
			return fmt.Errorf("layer %s: attestation records published digest %q, the artifact's manifest records %q",
				a.Digest, a.Published, w.Published)
		}
	}
	// Every layer of this digest matches a record already accounted for, so
	// the attestation claims the layer more times than the artifact has it.
	return fmt.Errorf("layer %s: the attestation records it more times than this artifact contains it", a.Digest)
}

// provenanceLines formats one line per distinct repository and revision an
// attestation's layers record, in the order they first appear.
func provenanceLines(layers []attest.Layer) []string {
	var lines []string
	seen := make(map[string]bool, len(layers))
	for _, l := range layers {
		key := l.Repo + "@" + l.Revision
		if seen[key] {
			continue
		}
		seen[key] = true
		if l.Revision == "" {
			lines = append(lines, l.Repo)
			continue
		}
		lines = append(lines, l.Repo+"@"+l.Revision)
	}
	return lines
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
