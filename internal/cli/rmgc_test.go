// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"io"
	"testing"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/viper"

	"github.com/aimd54/palan/internal/registrytest"
	"github.com/aimd54/palan/internal/signing"
	"github.com/aimd54/palan/internal/store"
)

// signedModelIn seeds a signed model on reg, pulls it into home, and returns
// the reference, the public key it verifies under, and its weight layer.
func signedModelIn(t *testing.T, home, repo string) (ref, pubKey string, weight ocispec.Descriptor, reg *registrytest.Registry) {
	t.Helper()
	reg = registrytest.New(t)
	body := []byte("weights of a model that will be signed and then removed")
	reg.PutBlob(repo, body)
	weight = localLayer(body, "model.gguf")
	seedModel(t, reg, repo, "v1", []ocispec.Descriptor{weight})
	ref = reg.Host() + "/" + repo + ":v1"
	priv, privKey := attestKeypair(t)
	pubKey = attestPubKeyFile(t, priv)
	if err := runSign(t, ref, privKey); err != nil {
		t.Fatalf("signing the fixture: %v", err)
	}
	runPullInto(t, home, ref)
	return ref, pubKey, weight, reg
}

// runRm runs the real rm command against home.
func runRm(t *testing.T, home string, refs ...string) error {
	t.Helper()
	t.Setenv("PALAN_HOME", home)
	v := viper.New()
	v.Set(keyRegistryPlainHTTP, true)
	cmd := newRmCmd(v)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(refs)
	return cmd.Execute()
}

// TestGCReturnsAfterRemovingASignedModel is the sequence from the report:
// pull a signed model, remove it, collect. It used to sit there with no
// output and no error until it was interrupted.
//
// It covers the command sequence and nothing finer. Removal takes the
// signature's manifest away with its tag, so by the time collection runs
// there is no orphan left for it to find, and collection is what reclaims
// the blobs. The sweep that recovers a store which reached the orphaned
// state by some other route is covered in internal/store, where that state
// can be built directly.
func TestGCReturnsAfterRemovingASignedModel(t *testing.T) {
	home := t.TempDir()
	ref, _, weight, _ := signedModelIn(t, home, "llm/tiny")
	if err := runRm(t, home, ref); err != nil {
		t.Fatalf("rm: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		t.Setenv("PALAN_HOME", home)
		cmd := newGCCmd()
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		// Not nil: cobra reads os.Args[1:] when the slice is nil, so the
		// test binary's own flags reach the command and it fails on an
		// unknown argument instead of running.
		cmd.SetArgs([]string{})
		done <- cmd.Execute()
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("gc: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("gc did not return after a signed model was removed")
	}

	// The weights are gone by the end of the sequence, which is what the
	// person who ran it wanted.
	st, err := store.Open(context.Background(), home)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.BlobPath(weight.Digest); err == nil {
		t.Fatal("the removed model's weights are still on disk")
	}
}

// TestRmRemovesTheAttestationWithTheModel: a signature and an attestation
// are both manifests naming the model as their subject, so one left behind
// holds the model's blobs on disk exactly as the other would. Only the
// signature was ever removed.
func TestRmRemovesTheAttestationWithTheModel(t *testing.T) {
	// A source-annotated layer, because signing writes an attestation only
	// for a model that records where its files came from. Seeded with a
	// plain layer this test would find nothing to remove and pass without
	// exercising anything.
	reg := registrytest.New(t)
	body := []byte("weights packed from a named upstream")
	reg.PutBlob("llm/att", body)
	seedModel(t, reg, "llm/att", "v1", []ocispec.Descriptor{
		sourceLayer(body, "huggingface.co/org/repo", "model.gguf", "a1b2c3d", ""),
	})
	ref := reg.Host() + "/llm/att:v1"
	_, privKey := attestKeypair(t)
	if err := runSign(t, ref, privKey); err != nil {
		t.Fatalf("signing the fixture: %v", err)
	}
	home := t.TempDir()
	runPullInto(t, home, ref)

	parsed := mustParseRef(t, ref)
	st, err := store.Open(context.Background(), home)
	if err != nil {
		t.Fatal(err)
	}
	desc, err := st.Resolve(context.Background(), parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	attRef := signing.AttRef(parsed, desc.Digest)
	if _, err := st.Resolve(context.Background(), attRef); err != nil {
		t.Fatalf("the fixture was meant to carry an attestation to remove: %v", err)
	}

	if err := runRm(t, home, ref); err != nil {
		t.Fatalf("rm: %v", err)
	}
	st2, err := store.Open(context.Background(), home)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st2.Resolve(context.Background(), attRef); err == nil {
		t.Fatal("the attestation outlived the model it describes")
	}
}

// TestRmKeepsASignatureAnotherTagStillNeeds: a signature is addressed by the
// model's digest, not by its tag, so it belongs to every reference that
// resolves to that digest. Removing one of two names for one model took the
// signature with it and left the remaining name with nothing local to
// verify against.
//
// Asserted against the store rather than by running verify. Verification
// falls through to the registry when the store holds a model without its
// signature, and the registry still has one, so verify succeeds either way
// and would report a pass over exactly the state this is about.
func TestRmKeepsASignatureAnotherTagStillNeeds(t *testing.T) {
	home := t.TempDir()
	ref, _, _, reg := signedModelIn(t, home, "llm/shared")

	// A second name for the same artifact, pulled into the same store.
	body := []byte("weights of a model that will be signed and then removed")
	reg.PutBlob("llm/shared", body)
	seedModel(t, reg, "llm/shared", "stable", []ocispec.Descriptor{localLayer(body, "model.gguf")})
	second := reg.Host() + "/llm/shared:stable"
	runPullInto(t, home, second)

	ctx := context.Background()
	st, err := store.Open(ctx, home)
	if err != nil {
		t.Fatal(err)
	}
	first := mustParseRef(t, ref)
	firstDesc, err := st.Resolve(ctx, first.String())
	if err != nil {
		t.Fatal(err)
	}
	secondDesc, err := st.Resolve(ctx, mustParseRef(t, second).String())
	if err != nil {
		t.Fatal(err)
	}
	if firstDesc.Digest != secondDesc.Digest {
		t.Fatalf("the fixture gave the two names different artifacts (%s, %s), so nothing here is shared",
			firstDesc.Digest, secondDesc.Digest)
	}
	sigRef := signing.SigRef(first, firstDesc.Digest)
	if _, err := st.Resolve(ctx, sigRef); err != nil {
		t.Fatalf("the fixture carries no signature to keep: %v", err)
	}

	if err := runRm(t, home, ref); err != nil {
		t.Fatalf("rm: %v", err)
	}

	after, err := store.Open(ctx, home)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := after.Resolve(ctx, mustParseRef(t, second).String()); err != nil {
		t.Fatalf("removing one name took the model the other still points at: %v", err)
	}
	if _, err := after.Resolve(ctx, sigRef); err != nil {
		t.Fatalf("removing one name took the signature the other still needs: %v", err)
	}
}
