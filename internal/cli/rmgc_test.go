// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/viper"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/errdef"

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
	_, err := runRmOut(t, home, refs...)
	return err
}

// runRmOut is runRm, returning what the command printed.
func runRmOut(t *testing.T, home string, refs ...string) (string, error) {
	t.Helper()
	t.Setenv("PALAN_HOME", home)
	v := viper.New()
	v.Set(keyRegistryPlainHTTP, true)
	cmd := newRmCmd(v)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(refs)
	err := cmd.Execute()
	return out.String(), err
}

// runGC runs the real gc command against home, failing the test if it does
// not return.
func runGC(t *testing.T, home string) error {
	t.Helper()
	t.Setenv("PALAN_HOME", home)
	done := make(chan error, 1)
	go func() {
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
		return err
	case <-time.After(30 * time.Second):
		t.Fatal("gc did not return")
		return nil
	}
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
	if err := runGC(t, home); err != nil {
		t.Fatalf("gc: %v", err)
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

// tagIndexOver writes an index listing children into the store at home and
// tags it ref.
func tagIndexOver(t *testing.T, home, ref string, children ...ocispec.Descriptor) ocispec.Descriptor {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, home)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(ocispec.Index{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageIndex,
		Manifests: children,
	})
	if err != nil {
		t.Fatal(err)
	}
	index := content.NewDescriptorFromBytes(ocispec.MediaTypeImageIndex, raw)
	if err := st.OCI().Push(ctx, index, bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	if err := st.Tag(ctx, index, ref); err != nil {
		t.Fatal(err)
	}
	return index
}

// signedModelDescs returns a pulled model's manifest and its signature's
// reference and manifest.
func signedModelDescs(t *testing.T, home, ref string) (model ocispec.Descriptor, sigRef string, sig ocispec.Descriptor) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, home)
	if err != nil {
		t.Fatal(err)
	}
	parsed := mustParseRef(t, ref)
	if model, err = st.Resolve(ctx, parsed.String()); err != nil {
		t.Fatal(err)
	}
	sigRef = signing.SigRef(parsed, model.Digest)
	if sig, err = st.Resolve(ctx, sigRef); err != nil {
		t.Fatalf("the fixture carries no signature: %v", err)
	}
	return model, sigRef, sig
}

// TestRmKeepsTheSignatureOfAModelAnIndexHolds: a model an index lists stays
// in the store when its tag is removed, so its signature stays with it
// rather than leaving the model there with nothing to verify it by. Both
// go once the index is removed.
func TestRmKeepsTheSignatureOfAModelAnIndexHolds(t *testing.T) {
	home := t.TempDir()
	ref, _, weight, _ := signedModelIn(t, home, "llm/listed")
	model, sigRef, sig := signedModelDescs(t, home, ref)
	const indexRef = "registry.internal/llm/bundle:v1"
	index := tagIndexOver(t, home, indexRef, model)

	held := map[string]ocispec.Descriptor{"index": index, "model": model, "signature": sig, "weights": weight}
	present := func(stage string, want bool) {
		t.Helper()
		after, err := store.Open(context.Background(), home)
		if err != nil {
			t.Fatal(err)
		}
		for name, d := range held {
			if _, err := content.FetchAll(context.Background(), after.OCI(), d); (err == nil) != want {
				t.Errorf("%s: the %s is present=%v, want %v", stage, name, err == nil, want)
			}
		}
		if _, err := after.Resolve(context.Background(), sigRef); (err == nil) != want {
			t.Errorf("%s: the signature's tag resolves=%v, want %v", stage, err == nil, want)
		}
	}

	out, err := runRmOut(t, home, ref)
	if err != nil {
		t.Fatalf("rm: %v", err)
	}
	if !strings.Contains(out, "Kept "+sigRef) {
		t.Errorf("rm kept the signature without saying so:\n%s", out)
	}
	present("after rm of the model", true)
	if err := runRm(t, home, indexRef); err != nil {
		t.Fatalf("rm: %v", err)
	}
	if err := runGC(t, home); err != nil {
		t.Fatalf("gc: %v", err)
	}
	present("after rm of the index and gc", false)
}

// TestRmRefusesASignatureAnIndexLists: deleting a signature an index lists
// would leave the index naming something the store does not hold, and only
// untagging it would leave it with nothing to name it by, so rm refuses and
// says what holds it.
func TestRmRefusesASignatureAnIndexLists(t *testing.T) {
	home := t.TempDir()
	ref, _, _, _ := signedModelIn(t, home, "llm/bundled")
	model, sigRef, sig := signedModelDescs(t, home, ref)
	const indexRef = "registry.internal/llm/bundle:v1"
	tagIndexOver(t, home, indexRef, model, sig)

	err := runRm(t, home, sigRef)
	if err == nil || !strings.Contains(err.Error(), indexRef) {
		t.Fatalf("removing a signature the index lists returned %v, not a refusal naming the index", err)
	}
	after, err := store.Open(context.Background(), home)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := after.Resolve(context.Background(), sigRef); err != nil || got.Digest != sig.Digest {
		t.Errorf("the refused removal took the signature's tag: %v", err)
	}
}

// TestRmTakesAnAttestationOverASignatureWithIt: a tagged attestation over a
// signature describes nothing once the signature is gone, and collection
// would keep it for good, so removing the signature removes it too and says
// so. The model stays.
func TestRmTakesAnAttestationOverASignatureWithIt(t *testing.T) {
	home := t.TempDir()
	ref, _, weight, _ := signedModelIn(t, home, "llm/attested-sig")
	model, sigRef, sig := signedModelDescs(t, home, ref)
	ctx := context.Background()
	st, err := store.Open(ctx, home)
	if err != nil {
		t.Fatal(err)
	}
	cfg := []byte("{}")
	cfgDesc := content.NewDescriptorFromBytes(ocispec.MediaTypeEmptyJSON, cfg)
	if err := st.OCI().Push(ctx, cfgDesc, bytes.NewReader(cfg)); err != nil && !errors.Is(err, errdef.ErrAlreadyExists) {
		t.Fatal(err)
	}
	raw, err := json.Marshal(ocispec.Manifest{
		Versioned:    specs.Versioned{SchemaVersion: 2},
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: "application/vnd.dsse.envelope.v1+json",
		Config:       cfgDesc,
		Layers:       []ocispec.Descriptor{cfgDesc},
		Subject:      &sig,
	})
	if err != nil {
		t.Fatal(err)
	}
	att := content.NewDescriptorFromBytes(ocispec.MediaTypeImageManifest, raw)
	if err := st.OCI().Push(ctx, att, bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	attRef := strings.TrimSuffix(sigRef, ".sig") + ".sig.att"
	if err := st.Tag(ctx, att, attRef); err != nil {
		t.Fatal(err)
	}

	out, err := runRmOut(t, home, sigRef)
	if err != nil {
		t.Fatalf("rm: %v", err)
	}
	for _, r := range []string{sigRef, attRef} {
		if !strings.Contains(out, "Removed "+r) {
			t.Errorf("rm did not report removing %s:\n%s", r, out)
		}
	}
	if err := runGC(t, home); err != nil {
		t.Fatalf("gc: %v", err)
	}
	after, err := store.Open(ctx, home)
	if err != nil {
		t.Fatal(err)
	}
	for name, d := range map[string]ocispec.Descriptor{"signature": sig, "attestation over it": att} {
		if _, err := content.FetchAll(ctx, after.OCI(), d); err == nil {
			t.Errorf("the %s is still in the store", name)
		}
	}
	for name, d := range map[string]ocispec.Descriptor{"model": model, "weights": weight} {
		if _, err := content.FetchAll(ctx, after.OCI(), d); err != nil {
			t.Errorf("removing the signature took the %s: %v", name, err)
		}
	}
}

// attestOver tags a DSSE-typed manifest over subject at ref in home's store.
func attestOver(t *testing.T, home string, subject ocispec.Descriptor, ref string) ocispec.Descriptor {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, home)
	if err != nil {
		t.Fatal(err)
	}
	layer := []byte("an attestation over " + subject.Digest.String())
	layerDesc := content.NewDescriptorFromBytes("application/octet-stream", layer)
	cfgDesc := content.NewDescriptorFromBytes(ocispec.MediaTypeEmptyJSON, []byte("{}"))
	for _, b := range []struct {
		d   ocispec.Descriptor
		raw []byte
	}{{layerDesc, layer}, {cfgDesc, []byte("{}")}} {
		if err := st.OCI().Push(ctx, b.d, bytes.NewReader(b.raw)); err != nil && !errors.Is(err, errdef.ErrAlreadyExists) {
			t.Fatal(err)
		}
	}
	raw, err := json.Marshal(ocispec.Manifest{
		Versioned:    specs.Versioned{SchemaVersion: 2},
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: "application/vnd.dsse.envelope.v1+json",
		Config:       cfgDesc,
		Layers:       []ocispec.Descriptor{layerDesc},
		Subject:      &subject,
	})
	if err != nil {
		t.Fatal(err)
	}
	desc := content.NewDescriptorFromBytes(ocispec.MediaTypeImageManifest, raw)
	if err := st.OCI().Push(ctx, desc, bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	if err := st.Tag(ctx, desc, ref); err != nil {
		t.Fatal(err)
	}
	return desc
}

// TestRmKeepsNothingCollectionWouldRemove: a signature with a second name
// over a model that is no longer tagged is not kept by collection, so rm of
// one name removes the attestation over it rather than saying it is kept.
func TestRmKeepsNothingCollectionWouldRemove(t *testing.T) {
	home := t.TempDir()
	ref, _, _, _ := signedModelIn(t, home, "llm/renamed")
	_, sigRef, sig := signedModelDescs(t, home, ref)
	ctx := context.Background()
	st, err := store.Open(ctx, home)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Tag(ctx, sig, "registry.internal/mirror/renamed:sig"); err != nil {
		t.Fatal(err)
	}
	if err := st.OCI().Untag(ctx, mustParseRef(t, ref).String()); err != nil {
		t.Fatal(err)
	}
	attRef := signing.AttRef(mustParseRef(t, sigRef), sig.Digest)
	attestOver(t, home, sig, attRef)

	out, err := runRmOut(t, home, sigRef)
	if err != nil {
		t.Fatalf("rm: %v", err)
	}
	if strings.Contains(out, "Kept") || !strings.Contains(out, "Removed "+attRef) {
		t.Errorf("rm did not remove the attestation collection would not keep:\n%s", out)
	}
}

// TestRmAcceptsAnArgumentAnEarlierOneTook: naming a signature and the
// attestation over it removes both, listing each once.
func TestRmAcceptsAnArgumentAnEarlierOneTook(t *testing.T) {
	home := t.TempDir()
	ref, _, _, _ := signedModelIn(t, home, "llm/both-named")
	_, sigRef, sig := signedModelDescs(t, home, ref)
	attRef := sigRef + ".att"
	attestOver(t, home, sig, attRef)

	out, err := runRmOut(t, home, sigRef, attRef)
	if err != nil {
		t.Fatalf("rm: %v", err)
	}
	if n := strings.Count(out, "Removed "+attRef+"\n"); n != 1 {
		t.Errorf("rm listed %s %d times:\n%s", attRef, n, out)
	}
}
