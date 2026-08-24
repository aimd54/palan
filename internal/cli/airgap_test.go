// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/viper"
	oras "oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/registry"

	"github.com/aimd54/palan/internal/refname"
	"github.com/aimd54/palan/internal/registrytest"
	"github.com/aimd54/palan/internal/signing"
)

// signedBundle builds what save writes for one signed model: an OCI layout
// holding the model and its signature, each under the fully-qualified
// reference the store addresses it by. It returns the bundle, the parsed
// model reference, the model's descriptor, and the references a load would
// have discovered in it.
func signedBundle(t *testing.T, keyFile string) (*oci.Store, registry.Reference, ocispec.Descriptor, []string) {
	t.Helper()
	ctx := context.Background()

	reg := registrytest.New(t)
	weights := []byte("weights that travel in a bundle")
	reg.PutBlob("llm/tiny", []byte("{}"))
	reg.PutBlob("llm/tiny", weights)
	mDesc := seedModel(t, reg, "llm/tiny", "a", []ocispec.Descriptor{localLayer(weights, "tiny.gguf")})

	modelRef := reg.Host() + "/llm/tiny:a"
	if err := runSign(t, modelRef, keyFile); err != nil {
		t.Fatalf("sign: %v", err)
	}
	parsed, err := refname.Parse(modelRef, "")
	if err != nil {
		t.Fatal(err)
	}

	bundle, err := oci.NewWithContext(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	repo := attestTestRepo(t, reg, "llm/tiny")
	if _, err := oras.Copy(ctx, repo, "a", bundle, parsed.String(), oras.DefaultCopyOptions); err != nil {
		t.Fatalf("copying the model into the bundle: %v", err)
	}
	sigRef := signing.SigRef(parsed, mDesc.Digest)
	if _, err := oras.Copy(ctx, repo, signing.SigTag(mDesc.Digest), bundle, sigRef, oras.DefaultCopyOptions); err != nil {
		t.Fatalf("copying the signature into the bundle: %v", err)
	}
	return bundle, parsed, mDesc, []string{parsed.String(), sigRef}
}

// TestBundleVerifierAcceptsASignedBundle is the control the refusal test
// below depends on: without it, a refusal could be the setup failing rather
// than the defence working.
func TestBundleVerifierAcceptsASignedBundle(t *testing.T) {
	priv, keyFile := attestKeypair(t)
	bundle, _, mDesc, refs := signedBundle(t, keyFile)

	var out bytes.Buffer
	if err := bundleVerifier(viper.New(), attestPubKeyFile(t, priv), &out)(context.Background(), bundle, refs); err != nil {
		t.Fatalf("a correctly signed bundle must verify: %v", err)
	}
	if want := "Verified"; !strings.Contains(out.String(), want) {
		t.Errorf("the verifier reported %q, which does not say a model was verified", out.String())
	}
	if !strings.Contains(out.String(), mDesc.Digest.String()) {
		t.Errorf("the verifier reported %q, which does not name the digest it verified", out.String())
	}
}

// TestBundleVerifierRefusesAStrayAttestationReference: a bundle is whatever
// a courier handed over, so an attestation-shaped tag is not evidence that
// an attestation is what it holds. Tagging a model
// `...:sha256-<64 hex>.att` makes the first pass skip it as supplementary,
// and without the second pass it would then be imported having never been
// verified at all.
func TestBundleVerifierRefusesAStrayAttestationReference(t *testing.T) {
	ctx := context.Background()
	priv, keyFile := attestKeypair(t)
	bundle, parsed, mDesc, refs := signedBundle(t, keyFile)

	// The smuggled entry: the model itself, tagged to look like the
	// attestation of some artifact this bundle does not contain.
	stray := signing.AttRef(parsed, digest.FromString("an artifact that is not in this bundle"))
	if err := bundle.Tag(ctx, mDesc, stray); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	err := bundleVerifier(viper.New(), attestPubKeyFile(t, priv), &out)(ctx, bundle, append(refs, stray))
	if err == nil {
		t.Fatal("a reference that is the attestation of nothing verified must be refused, not imported unchecked")
	}
	if !strings.Contains(err.Error(), stray) {
		t.Errorf("the refusal must name the offending reference, got: %v", err)
	}
}

// TestBundleVerifierAcceptsAGenuineAttestationReference pins the other
// half: the defence must not refuse the attestation of a model that did
// verify, or a bundle carrying real provenance would stop importing.
func TestBundleVerifierAcceptsAGenuineAttestationReference(t *testing.T) {
	ctx := context.Background()
	priv, keyFile := attestKeypair(t)
	bundle, parsed, mDesc, refs := signedBundle(t, keyFile)

	genuine := signing.AttRef(parsed, mDesc.Digest)
	if err := bundle.Tag(ctx, mDesc, genuine); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := bundleVerifier(viper.New(), attestPubKeyFile(t, priv), &out)(ctx, bundle, append(refs, genuine)); err != nil {
		t.Fatalf("the attestation of a verified model must be accepted: %v", err)
	}
}
