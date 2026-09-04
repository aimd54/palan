// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

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
	"github.com/aimd54/palan/internal/keyless"
	"github.com/aimd54/palan/internal/refname"
	"github.com/aimd54/palan/internal/signing"
	"github.com/aimd54/palan/internal/store"
)

// Config keys for verification policy.
const (
	keyVerifyRequired = "verify.required"
	keyVerifyKey      = "verify.key"
	keyVerifyPolicy   = "verify.policy"
	keyVerifySources  = "verify.sources"
	keyVerifyRehash   = "verify.rehash"
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
	var (
		keyPath   string
		doExplain bool
		asJSON    bool
		doRehash  bool
	)
	cmd := &cobra.Command{
		Use:   "verify REF --key FILE",
		Short: "Verify a model's signature against a public key",
		Example: `  # Verify against a registry, or from the local store when it holds the signature
  palan verify registry.internal/llm/qwen3:8b-q4 --key cosign.pub

  # Every link in the chain, including the ones this host cannot prove
  palan verify registry.internal/llm/qwen3:8b-q4 --explain

  # Read the weight blobs back and hold them to the digests the manifest records
  palan verify registry.internal/llm/qwen3:8b-q4 --explain --rehash`,
		Long: `Verify checks a model's signature against a public key, or against the
keyless identities a trust policy names.

A model already in the local store is verified from there, so verification
needs no registry, no transparency log, and no certificate authority. Anything
else is resolved on its registry. The output names the source, since a local
result describes the copy you hold rather than what the registry serves now.

The signature is looked for under its tag first, then among the referrers of
the model, so a signature written by an OCI 1.1 signing tool is checked even
though it carries no tag.

A keyless signature names its signer instead of naming a key. Where a policy
rule lists identities, verify reads the signature bundle that travels with
the model and holds it against the trusted root the rule pins. The
transparency log entry must carry an inclusion proof reaching a log root
that root's key has signed, and a timestamp that same key signed, since a
keyless certificate lives minutes and is checked against the moment the log
recorded the signature rather than the present. An entry carrying no signed
timestamp is refused. All of that material travels with the artifact, so
this too needs no network. The signer is reported, since it is the one thing
the result establishes that the configuration did not already state.

With --explain, the output is the whole chain rather than a verdict: which
reference resolved to which digest, who signed it, what allowed them to,
where the files came from, and whether the bytes on this host were read
back. Every step says whether this host proved it. The steps it could not
prove are printed too, since a chain shown with its gaps removed reads as a
chain with no gaps. --json prints the same chain for a program.

Signature verification reads a manifest, and a manifest names its blobs by
digest, so it says nothing about a weight file replaced on disk afterwards.
--rehash reads those blobs back and holds each to the digest the manifest
records. It is off by default because it re-reads whole weight files.

Where sign also wrote a statement of the model's sources, verify checks it
against the same key and against the model's own layers, and names what the
layers came from. A model with no such statement verifies exactly as it did
before: requiring one is a policy for something else to enforce, not a fact
this command asserts. A source attestation is checked against the key that
signed the model, so a model verified by a keyless signature has its
provenance reported as unchecked rather than checked.`,
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
			verifier, err := verifyDigest(ctx, v, keyPath, src, ref)
			if err != nil {
				return err
			}
			report, err := checkAttestation(ctx, verifier, src, ref)
			if err != nil {
				return err
			}
			rh := rehashOutcome{}
			if rehashRequested(v, doRehash) {
				rh.report, err = rehashStore(ctx, st, ref, src.subject)
				if err != nil {
					return err
				}
				rh.ran = true
			}
			if doExplain || asJSON {
				e := explain(ref.String(), src.subject.Digest.String(), src, verifier, report, rh)
				if asJSON {
					return renderExplanationJSON(cmd.OutOrStdout(), e)
				}
				return renderExplanation(cmd.OutOrStdout(), e)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Verified %s@%s\n  source: %s\n", ref, src.subject.Digest, src.name)
			// Who signed is only worth a line when the answer was not
			// already given on the command line or in the config: a
			// keyless signature names its signer, and that name is what
			// the policy matched.
			if verifier.keyless != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "  signer: %s\n", verifier.keyless)
			}
			for _, p := range report.provenance {
				fmt.Fprintf(cmd.OutOrStdout(), "  provenance: %s\n", p)
			}
			if rh.ran {
				fmt.Fprintf(cmd.OutOrStdout(), "  content: %d blobs re-read (%s), every digest matches\n",
					rh.report.Blobs, humanBytes(rh.report.Bytes))
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
	cmd.Flags().BoolVar(&doExplain, "explain", false, "print every link in the chain, including the ones this host cannot prove")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the chain as JSON")
	cmd.Flags().BoolVar(&doRehash, "rehash", false, "read the artifact's blobs back and hold each to the digest the manifest records")
	return cmd
}

// rehashStore re-reads the blobs this host holds for ref and holds each
// against the digest the manifest records.
//
// The store is read rather than the verification source, which may be the
// registry: the question is what is on this host, and hashing the
// registry's copy would download the whole artifact to prove something
// about bytes that are somewhere else.
//
// A store holding a different digest under the same reference is refused
// rather than re-hashed. Its blobs would hash correctly against their own
// manifest and prove nothing about the artifact whose signature was just
// checked, which is the one answer that would read as a pass while
// establishing nothing.
func rehashStore(
	ctx context.Context, st *store.Store, ref registry.Reference, subject ocispec.Descriptor,
) (store.RehashReport, error) {
	local, err := st.Resolve(ctx, ref.String())
	switch {
	case errors.Is(err, errdef.ErrNotFound):
		return store.RehashReport{}, fmt.Errorf(
			"%s is not in the local store, so there are no blobs here to read back", ref)
	case err != nil:
		return store.RehashReport{}, fmt.Errorf("reading the local store: %w", err)
	case local.Digest != subject.Digest:
		return store.RehashReport{}, fmt.Errorf(
			"%s is %s in the local store and %s where its signature was checked, "+
				"so the blobs on this host are not the ones that verified",
			ref, local.Digest, subject.Digest)
	}
	return store.Rehash(ctx, st.OCI(), local)
}

// verifySource is where an artifact and its signature are read from.
type verifySource struct {
	target oras.ReadOnlyTarget
	sigRef string
	// attRef is the attestation's reference, in the same form as sigRef: a
	// bare tag on a registry, a full reference in the local store. Only the
	// verify command reads it, since the gates at pull, load, run and serve
	// stop at the signature, but every source fills it: a field left empty
	// by some callers is a field the next caller forgets.
	attRef string
	// subject is the artifact being verified. The whole descriptor is needed,
	// not just its digest, because a signature may be attached as a referrer
	// of it rather than under a tag.
	subject ocispec.Descriptor
	name    string
}

// remoteSource names where a registry keeps everything attached to desc.
// A registry holds one repository, so each attachment is a bare tag.
//
// Sources are built here and not by each caller in turn. Every attachment a
// verification may need is named in one place, so adding a fourth kind
// cannot leave one call site addressing it and another leaving it blank,
// which reads downstream as an artifact that carries nothing.
func remoteSource(target oras.ReadOnlyTarget, desc ocispec.Descriptor, name string) verifySource {
	return verifySource{
		target:  target,
		sigRef:  signing.SigTag(desc.Digest),
		attRef:  signing.AttTag(desc.Digest),
		subject: desc,
		name:    name,
	}
}

// layoutSource names where an OCI layout keeps them: by full reference,
// because the local store and a transfer bundle each hold many
// repositories and a bare tag would not say which.
func layoutSource(target oras.ReadOnlyTarget, ref registry.Reference, desc ocispec.Descriptor, name string) verifySource {
	return verifySource{
		target:  target,
		sigRef:  signing.SigRef(ref, desc.Digest),
		attRef:  signing.AttRef(ref, desc.Digest),
		subject: desc,
		name:    name,
	}
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
			return layoutSource(st.OCI(), ref, local, "local store"), nil
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
	return remoteSource(repo, desc, "registry"), nil
}

// storeHoldsSignature reports whether the store can verify this artifact
// without a network, from the signature tag, from a signature attached to
// the artifact as a referrer, or from a keyless signature bundle. A model
// signed only the keyless way would otherwise be sent to the registry for
// a signature it is already holding, which on a disconnected host means
// refusing an artifact it can verify.
func storeHoldsSignature(ctx context.Context, st *store.Store, sigRef string, subject ocispec.Descriptor) (bool, error) {
	switch _, err := st.Resolve(ctx, sigRef); {
	case err == nil:
		return true, nil
	case !errors.Is(err, errdef.ErrNotFound):
		return false, err
	}
	if bundles, err := signing.BundleReferrers(ctx, st.OCI(), subject); err == nil && len(bundles) > 0 {
		return true, nil
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
// verify, or nil when neither the flag nor verify.required asks for one. It
// returns the artifact the signature covered, which is not always the one
// this host holds, so a caller about to load something has to compare.
//
// run and serve share it so that a model is checked at the moment it is about
// to be served, not only when it entered the store. Source selection is left
// to resolveVerifySource, which reads the store when it holds the signature
// and the registry otherwise, so an air-gapped host needs no network and a
// model signed after a local pack still verifies.
func verifyGate(
	v *viper.Viper, st *store.Store, doVerify bool, keyPath string,
) func(context.Context, string) (ocispec.Descriptor, error) {
	if !doVerify && !v.GetBool(keyVerifyRequired) {
		return nil
	}
	return func(ctx context.Context, raw string) (ocispec.Descriptor, error) {
		ref, err := refname.Parse(raw, v.GetString(keyRegistryDefault))
		if err != nil {
			return ocispec.Descriptor{}, err
		}
		src, err := resolveVerifySource(ctx, st, v, ref)
		if err != nil {
			return ocispec.Descriptor{}, err
		}
		if _, err := verifyDigest(ctx, v, keyPath, src, ref); err != nil {
			return ocispec.Descriptor{}, err
		}
		return src.subject, nil
	}
}

// checkLoadedContent holds the copy this host is about to load against the
// artifact whose signature was just checked, and, when asked, reads that
// copy's blobs back.
//
// Two questions are still open once a signature verifies, and neither is
// answered by the signature. The store may hold the model without holding
// its signature, in which case the gate read the registry, so a tag that
// moved leaves this host serving one artifact while vouching for another.
// And a signature covers a manifest, which names blobs by digest and says
// nothing about a file replaced on disk afterwards.
//
// The digest comparison always runs where a signature was checked;
// re-reading the blobs is asked for, because it re-reads whole weight files
// on every load.
//
// A zero verified descriptor means no signature was checked at all, which
// happens when re-reading is asked for on its own. There is then nothing to
// compare against, and the blobs are still read back: the two questions are
// separate, and answering neither because only one was configured is how a
// requested check turns into silence.
func checkLoadedContent(
	ctx context.Context, st *store.Store, ref string, local, verified ocispec.Descriptor, doRehash bool,
) error {
	if verified.Digest != "" && local.Digest != verified.Digest {
		return fmt.Errorf(
			"%s is %s on this host and %s where its signature was checked, "+
				"so what would be loaded is not what verified",
			ref, local.Digest, verified.Digest)
	}
	if !doRehash {
		return nil
	}
	if _, err := store.Rehash(ctx, st.OCI(), local); err != nil {
		return fmt.Errorf("%s: %w", ref, err)
	}
	return nil
}

// rehashRequested reports whether the blobs are to be read back at load,
// from the flag or from the standing configuration.
func rehashRequested(v *viper.Viper, doRehash bool) bool {
	return doRehash || v.GetBool(keyVerifyRehash)
}

// namedVerifier is one identity a policy allows, carried with the name it was
// configured under so a refusal can say which identities were tried.
type namedVerifier struct {
	name     string
	verifier signature.Verifier
}

// allowedSigners is everyone permitted to sign one reference: the keys a
// signature may verify under, and the keyless identities a bundle may name.
// A policy rule can carry either or both, so both travel together and a
// refusal can say what was tried.
type allowedSigners struct {
	verifiers  []namedVerifier
	identities []keyless.Identity
	// trustRoot is the file the identities are checked against. It is read
	// only if a keyless signature is actually tried, so a rule naming keys
	// as well keeps working on a host where the root file is absent.
	trustRoot string
	// admitted names the configured entry these signers came from: a policy
	// rule's pattern, or the key file a flag or the config named. A result
	// says who signed, which is not the same question as who was permitted
	// to, and an operator auditing a host needs the second one too.
	admitted string
}

// resolveVerifiers returns the identities allowed to sign ref.
//
// An explicit --key overrides the policy, since a flag someone typed is a
// deliberate act and the policy is the standing configuration it overrides.
// It also rules out keyless: naming a key file is a statement about how the
// artifact is to be checked, not merely which key to add.
//
// With no policy configured, verify.key is the single allowed identity,
// which is the behaviour that predates policies.
func resolveVerifiers(
	v *viper.Viper, keyPath string, ref registry.Reference,
) (allowedSigners, error) {
	if keyPath != "" {
		nv, err := loadNamedVerifier(keyPath)
		if err != nil {
			return allowedSigners{}, err
		}
		return allowedSigners{
			verifiers: []namedVerifier{nv},
			admitted:  "--key " + keyPath,
		}, nil
	}

	policy, err := loadPolicy(v)
	if err != nil {
		return allowedSigners{}, err
	}
	if policy == nil {
		configured := v.GetString(keyVerifyKey)
		if configured == "" {
			return allowedSigners{}, fmt.Errorf(
				"no verification key configured: pass --key, set %s, or configure %s",
				keyVerifyKey, keyVerifyPolicy)
		}
		nv, err := loadNamedVerifier(configured)
		if err != nil {
			return allowedSigners{}, err
		}
		return allowedSigners{
			verifiers: []namedVerifier{nv},
			admitted:  keyVerifyKey + " " + configured,
		}, nil
	}

	repoRef := ref.Registry + "/" + ref.Repository
	rule, ok := policy.RuleFor(repoRef)
	if !ok {
		return allowedSigners{}, fmt.Errorf(
			"the trust policy names no identity allowed to sign %s; "+
				"its patterns are %s",
			repoRef, strings.Join(policy.Patterns(), ", "))
	}
	out := allowedSigners{
		identities: rule.Identities,
		trustRoot:  rule.TrustRoot,
		admitted:   keyVerifyPolicy + " rule " + rule.Pattern,
	}
	for _, f := range rule.KeyFiles {
		nv, err := loadNamedVerifier(f)
		if err != nil {
			return allowedSigners{}, err
		}
		out.verifiers = append(out.verifiers, nv)
	}
	return out, nil
}

// loadNamedVerifier reads a public key file into a verifier, keeping the path
// as the identity's name so a refusal names a file an operator can go and
// look at.
func loadNamedVerifier(keyPath string) (namedVerifier, error) {
	pemBytes, err := os.ReadFile(keyPath) // #nosec G304 -- user-chosen key file
	if err != nil {
		return namedVerifier{}, fmt.Errorf("reading verification key: %w", err)
	}
	verifier, err := signing.LoadVerifier(pemBytes)
	if err != nil {
		return namedVerifier{}, err
	}
	return namedVerifier{name: keyPath, verifier: verifier}, nil
}

// verifiedBy is the identity that accepted an artifact's signature, and
// what permitted that identity to sign it.
//
// Exactly one of key and keyless is set. The distinction is not cosmetic:
// anything else about the artifact that must be held to the same identity
// needs the verifier, and a keyless signature supplies no such verifier, so
// a caller has to notice rather than carry a nil one.
type verifiedBy struct {
	// key is the verifier that accepted a key-based signature.
	key signature.Verifier
	// keyless is who a keyless signature turned out to name.
	keyless *keyless.Result
	// admitted names the configured entry that allowed this signer.
	admitted string
	// trustRoot is the file a keyless identity was held against, and is
	// empty for a key-based signature, which is checked against no root.
	trustRoot string
}

// verifyDigest runs signature verification against an already-resolved
// source, and returns the identity that accepted it so the caller can hold
// anything else about the artifact to the same identity.
//
// Keys are tried before keyless identities, and only because a key check is
// local arithmetic while a keyless one reads a trusted root off disk. Order
// carries no precedence: a rule naming both accepts a signature of either
// kind, which is what makes a migration between them possible.
func verifyDigest(
	ctx context.Context, v *viper.Viper, keyPath string, src verifySource,
	ref registry.Reference,
) (verifiedBy, error) {
	allowed, err := resolveVerifiers(v, keyPath, ref)
	if err != nil {
		return verifiedBy{}, err
	}
	repoRef := ref.Registry + "/" + ref.Repository
	tried := make([]string, 0, len(allowed.verifiers)+1)
	var lastErr error
	for _, nv := range allowed.verifiers {
		err := signing.Verify(
			ctx, src.target, src.sigRef, repoRef, src.subject, nv.verifier)
		if err == nil {
			return verifiedBy{key: nv.verifier, admitted: allowed.admitted}, nil
		}
		lastErr = err
		tried = append(tried, nv.name)
	}
	if len(allowed.identities) > 0 {
		result, err := verifyKeyless(ctx, src, allowed)
		if err == nil {
			return verifiedBy{
				keyless:   result,
				admitted:  allowed.admitted,
				trustRoot: allowed.trustRoot,
			}, nil
		}
		lastErr = err
		tried = append(tried, describeIdentities(allowed.identities))
	}
	return verifiedBy{}, fmt.Errorf(
		"signature verification FAILED for %s@%s against %s: %w",
		ref, src.subject.Digest, strings.Join(tried, ", "), lastErr)
}

// verifyKeyless checks the keyless signature carried beside the artifact.
//
// Everything it needs is already at hand: the bundle travels with the
// artifact and the trusted root is a file, so this reaches no certificate
// authority and no transparency log.
func verifyKeyless(ctx context.Context, src verifySource, allowed allowedSigners) (*keyless.Result, error) {
	raw, err := os.ReadFile(allowed.trustRoot) // #nosec G304 -- operator-chosen trusted root
	if err != nil {
		return nil, fmt.Errorf("reading the trusted root the policy pins: %w", err)
	}
	root, err := keyless.LoadTrustedRoot(raw)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", allowed.trustRoot, err)
	}
	bundles, err := signing.FetchBundles(ctx, src.target, src.subject)
	if err != nil {
		return nil, err
	}
	// Every one is tried. Anybody who can push to the repository can attach
	// another, so stopping at the first would let that person decide which
	// signature is checked, and a good signature would go unexamined
	// behind a bad one.
	var lastErr error
	for _, b := range bundles {
		result, err := keyless.Verify(b, src.subject.Digest, root, allowed.identities)
		if err == nil {
			return result, nil
		}
		lastErr = err
	}
	if len(bundles) > 1 {
		return nil, fmt.Errorf(
			"none of the %d keyless signatures on this artifact verifies; the last said: %w",
			len(bundles), lastErr)
	}
	return nil, lastErr
}

// describeIdentities names the keyless signers a refusal tried, so the
// message lists them beside the key files rather than saying only that
// something keyless was attempted.
func describeIdentities(ids []keyless.Identity) string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, fmt.Sprintf("%s (via %s)", id.Subject, id.Issuer))
	}
	return strings.Join(out, ", ")
}

// checkAttestation looks for a statement of src's sources and, when one
// exists, verifies it against verifier, the identity that just accepted the
// artifact's signature, then holds every layer it records against the
// artifact's own manifest. It returns one line per distinct source the
// layers came from, for the caller to report.
//
// Using the signature's own verifier is the point rather than a
// convenience: a policy may allow several identities, and a statement
// vouched for by one of them beside a signature vouched for by another is
// two claims about the same bytes with nothing tying them together.
//
// An absent attestation is not a failure: requiring one is a policy for
// something else to enforce, and reporting the same output as an artifact
// with no such statement at all is the correct answer here, not a missing
// feature.
func checkAttestation(ctx context.Context, by verifiedBy, src verifySource, ref registry.Reference) (attestationReport, error) {
	// A source attestation is a statement by whoever signed the artifact,
	// held against that same signer. A keyless signature names an identity
	// rather than supplying a key to check a second statement with, so the
	// statement is left unchecked, and said to be.
	if by.key == nil {
		return uncheckedAttestation(ctx, src)
	}
	verifier := by.key
	envelope, err := signing.FetchAttestation(
		ctx, src.target, src.attRef, src.subject)
	switch {
	case errors.Is(err, attest.ErrNoAttestation):
		return missingAttestation(ctx, src)
	case err != nil:
		return attestationReport{}, fmt.Errorf("fetching the attestation for %s@%s: %w", ref, src.subject.Digest, err)
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

// missingAttestation decides what to say about an artifact carrying no
// statement of its sources. Most owe none; one whose own layers record
// where they were fetched from was packed from upstream and does owe one.
//
// Reported rather than refused: nothing is forged and the signature still
// verifies, so the artifact is unproven rather than wrong, and requiring a
// statement is a policy question.
func missingAttestation(ctx context.Context, src verifySource) (attestationReport, error) {
	// Reported, not passed over: returning nothing here is the same answer
	// an artifact owing no statement gives, so a deleted manifest would
	// hide a deleted attestation.
	claimed, unreadable := claimedSources(ctx, src)
	if unreadable != "" {
		return attestationReport{warning: "WARNING: no attestation is present, and " + unreadable}, nil
	}
	if claimed == 0 {
		return attestationReport{}, nil
	}
	return attestationReport{warning: fmt.Sprintf(
		"WARNING: %d layer(s) record an upstream source but no attestation is present, so this model's provenance cannot be checked",
		claimed)}, nil
}

// uncheckedAttestation says what a keyless verification did not establish.
//
// Silence here would be the same output an artifact with nothing to state
// produces, so a model whose layers name upstream files would read as one
// packed from local disk. The signature is still good; its provenance is
// simply unproven.
func uncheckedAttestation(ctx context.Context, src verifySource) (attestationReport, error) {
	claimed, unreadable := claimedSources(ctx, src)
	if unreadable != "" {
		return attestationReport{warning: "WARNING: the source attestation was not checked, and " + unreadable}, nil
	}
	if claimed == 0 {
		return attestationReport{}, nil
	}
	return attestationReport{warning: fmt.Sprintf(
		"WARNING: %d layer(s) record an upstream source, and a source attestation is checked against the key that signed the model, so a model verified by a keyless signature has its provenance left unchecked",
		claimed)}, nil
}

// claimedSources counts the layers whose annotations record where they were
// fetched from, and says why it could not tell when the manifest cannot be
// read.
func claimedSources(ctx context.Context, src verifySource) (int, string) {
	raw, err := content.FetchAll(ctx, src.target, src.subject)
	if err != nil {
		return 0, fmt.Sprintf(
			"this artifact's manifest could not be read to say whether one was owed: %v", err)
	}
	var man ocispec.Manifest
	if err := json.Unmarshal(raw, &man); err != nil {
		return 0, fmt.Sprintf(
			"this artifact's manifest could not be decoded to say whether one was owed: %v", err)
	}
	return len(signing.LayersFromManifest(man)), ""
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
