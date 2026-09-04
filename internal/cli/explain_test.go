// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/viper"

	"github.com/aimd54/palan/internal/registrytest"
	"github.com/aimd54/palan/internal/store"
)

// runVerifyIn runs the real verify command against a store the caller
// chooses, so a test can pull first and then ask about what landed.
func runVerifyIn(t *testing.T, home, ref string, args ...string) (string, error) {
	t.Helper()
	t.Setenv("PALAN_HOME", home)
	v := viper.New()
	v.Set(keyRegistryPlainHTTP, true)
	cmd := newVerifyCmd(v)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(append([]string{ref}, args...))
	err := cmd.Execute()
	return out.String(), err
}

// runPullInto runs the real pull command, so the store under test holds
// exactly what a pull leaves behind rather than what a test assembled.
func runPullInto(t *testing.T, home, ref string) {
	t.Helper()
	t.Setenv("PALAN_HOME", home)
	v := viper.New()
	v.Set(keyRegistryPlainHTTP, true)
	cmd := newPullCmd(v)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{ref})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("pull: %v", err)
	}
}

// linkVerdicts reads the chain out of --json, which is the form a test can
// assert on without depending on column widths.
func linkVerdicts(t *testing.T, out string) map[string]link {
	t.Helper()
	var e explanation
	if err := json.Unmarshal([]byte(out), &e); err != nil {
		t.Fatalf("the --json output does not parse (%v), stream was: %q", err, out)
	}
	byName := make(map[string]link, len(e.Links))
	for _, l := range e.Links {
		byName[l.Name] = l
	}
	return byName
}

// signedUpstreamModel seeds a model whose layer records where it came from,
// signs it, and returns its reference and public key file.
func signedUpstreamModel(t *testing.T, reg *registrytest.Registry, weights []byte) (ref, pubKey string, layer ocispec.Descriptor) {
	t.Helper()
	reg.PutBlob("llm/tiny", weights)
	layer = sourceLayer(weights, "huggingface.co/org/repo", "model.gguf", "abc123", strings.Repeat("11", 32))
	seedModel(t, reg, "llm/tiny", "q4", []ocispec.Descriptor{layer})
	priv, privKey := attestKeypair(t)
	pubKey = attestPubKeyFile(t, priv)
	ref = reg.Host() + "/llm/tiny:q4"
	if err := runSign(t, ref, privKey); err != nil {
		t.Fatalf("signing the fixture: %v", err)
	}
	return ref, pubKey, layer
}

func TestExplainNamesEveryLinkIncludingTheOnesItCannotProve(t *testing.T) {
	reg := registrytest.New(t)
	ref, pubKey, _ := signedUpstreamModel(t, reg, []byte("weights"))

	out, err := runVerifyIn(t, t.TempDir(), ref, "--key", pubKey, "--explain")
	if err != nil {
		t.Fatalf("verify --explain: %v", err)
	}
	for _, want := range []string{
		"proven    " + linkReference,
		"proven    " + linkSignature,
		"proven    " + linkPolicy,
		"proven    " + linkSources,
		"unproven  " + linkContent,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the chain does not carry %q; it was:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "huggingface.co/org/repo@abc123") {
		t.Errorf("the provenance link does not name the source; the chain was:\n%s", out)
	}
	if !strings.Contains(out, "--rehash") {
		t.Errorf("the content link does not say what would prove it; the chain was:\n%s", out)
	}
	if !strings.Contains(out, "--key "+pubKey) {
		t.Errorf("the policy link does not name what admitted the signer; the chain was:\n%s", out)
	}
}

func TestExplainAsJSONIsTheWholeStreamAndCarriesTheSameVerdicts(t *testing.T) {
	reg := registrytest.New(t)
	ref, pubKey, _ := signedUpstreamModel(t, reg, []byte("weights"))

	out, err := runVerifyIn(t, t.TempDir(), ref, "--key", pubKey, "--json")
	if err != nil {
		t.Fatalf("verify --json: %v", err)
	}
	links := linkVerdicts(t, out)
	for _, name := range []string{linkReference, linkSignature, linkPolicy, linkSources, linkContent} {
		if _, ok := links[name]; !ok {
			t.Errorf("the JSON chain has no %q link; it was:\n%s", name, out)
		}
	}
	if !links[linkSources].Proven {
		t.Errorf("provenance reads unproven for an artifact whose attestation checked out: %+v", links[linkSources])
	}
	if links[linkContent].Proven {
		t.Errorf("content reads proven though no blob was read back: %+v", links[linkContent])
	}
}

func TestExplainSaysAnArtifactPackedLocallyNamesNoSource(t *testing.T) {
	reg := registrytest.New(t)
	weights := []byte("weights")
	reg.PutBlob("llm/local", weights)
	seedModel(t, reg, "llm/local", "v1", []ocispec.Descriptor{localLayer(weights, "model.gguf")})
	priv, privKey := attestKeypair(t)
	pubKey := attestPubKeyFile(t, priv)
	ref := reg.Host() + "/llm/local:v1"
	if err := runSign(t, ref, privKey); err != nil {
		t.Fatalf("signing the fixture: %v", err)
	}

	out, err := runVerifyIn(t, t.TempDir(), ref, "--key", pubKey, "--json")
	if err != nil {
		t.Fatalf("verify --json: %v", err)
	}
	links := linkVerdicts(t, out)
	if links[linkSources].Proven {
		t.Errorf("an artifact with no upstream reads as having proven provenance: %+v", links[linkSources])
	}
	if !strings.Contains(links[linkSources].Detail, "local disk") {
		t.Errorf("the provenance link does not distinguish a local pack from a missing statement: %+v", links[linkSources])
	}
}

func TestRehashReadsTheBlobsBackAndSaysHowMany(t *testing.T) {
	reg := registrytest.New(t)
	home := t.TempDir()
	ref, pubKey, _ := signedUpstreamModel(t, reg, []byte("weights"))
	runPullInto(t, home, ref)

	out, err := runVerifyIn(t, home, ref, "--key", pubKey, "--json", "--rehash")
	if err != nil {
		t.Fatalf("verify --rehash: %v", err)
	}
	links := linkVerdicts(t, out)
	if !links[linkContent].Proven {
		t.Fatalf("content reads unproven after a re-hash: %+v", links[linkContent])
	}
	// The manifest, its config, and the one weight layer.
	if !strings.Contains(links[linkContent].Detail, "3 blobs") {
		t.Errorf("the content link does not say what was read: %+v", links[linkContent])
	}
}

// TestSignatureVerifiesOverSubstitutedWeightsUntilTheBlobsAreReadBack is the
// gap ADR-0008 deferred, shown from both sides in one test: the same store,
// the same signature, and two different answers depending on whether the
// bytes were read. Asserting only the refusal would leave it unclear that
// there was ever anything to close.
func TestSignatureVerifiesOverSubstitutedWeightsUntilTheBlobsAreReadBack(t *testing.T) {
	reg := registrytest.New(t)
	home := t.TempDir()
	original := []byte("the weights a publisher released")
	ref, pubKey, layer := signedUpstreamModel(t, reg, original)
	runPullInto(t, home, ref)

	st, err := store.Open(context.Background(), home)
	if err != nil {
		t.Fatal(err)
	}
	path, err := st.BlobPath(layer.Digest)
	if err != nil {
		t.Fatalf("the weight blob is not in the store after a pull: %v", err)
	}
	substituted := []byte("the weights an attacker wrote!!!")
	if len(substituted) != len(original) {
		t.Fatalf("the substitution must be the same length, got %d against %d", len(substituted), len(original))
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, substituted, 0o600); err != nil {
		t.Fatal(err)
	}

	// The manifest is untouched, so the signature still verifies. This is
	// the state an operator would read as a verified model.
	if _, err := runVerifyIn(t, home, ref, "--key", pubKey); err != nil {
		t.Fatalf("the signature must still verify over a substituted blob, or this test is not about the gap: %v", err)
	}

	_, err = runVerifyIn(t, home, ref, "--key", pubKey, "--rehash")
	if err == nil {
		t.Fatal("--rehash accepted a substituted weight blob")
	}
	if !strings.Contains(err.Error(), layer.Digest.String()) {
		t.Errorf("the refusal does not name the blob that changed: %v", err)
	}
}

func TestRehashRefusesWhenTheBlobsAreNotOnThisHost(t *testing.T) {
	reg := registrytest.New(t)
	ref, pubKey, _ := signedUpstreamModel(t, reg, []byte("weights"))

	_, err := runVerifyIn(t, t.TempDir(), ref, "--key", pubKey, "--rehash")
	if err == nil {
		t.Fatal("--rehash reported on blobs that are not in the local store")
	}
	if !strings.Contains(err.Error(), "not in the local store") {
		t.Errorf("the refusal does not say why there was nothing to read: %v", err)
	}
}

// TestRehashRefusesWhenTheStoreHoldsADifferentArtifactUnderTheSameTag
// covers the case that would otherwise read as a pass: a tag that moved on
// the registry while this host kept the old copy and never held a
// signature, so the signature is checked against what the registry serves
// now while the blobs here belong to the artifact from before. Re-hashing
// them would succeed against their own manifest and establish nothing
// about the one that was verified.
func TestRehashRefusesWhenTheStoreHoldsADifferentArtifactUnderTheSameTag(t *testing.T) {
	reg := registrytest.New(t)
	home := t.TempDir()
	ref := reg.Host() + "/llm/tiny:q4"

	// The copy this host pulled, before anything was signed, so the store
	// holds the model and no signature for it.
	first := []byte("the weights this host pulled")
	reg.PutBlob("llm/tiny", first)
	seedModel(t, reg, "llm/tiny", "q4", []ocispec.Descriptor{localLayer(first, "model.gguf")})
	runPullInto(t, home, ref)

	// The publisher moves the tag to a new artifact and signs that one.
	second := []byte("the weights the tag points at now")
	reg.PutBlob("llm/tiny", second)
	seedModel(t, reg, "llm/tiny", "q4", []ocispec.Descriptor{localLayer(second, "model.gguf")})
	priv, privKey := attestKeypair(t)
	pubKey := attestPubKeyFile(t, priv)
	if err := runSign(t, ref, privKey); err != nil {
		t.Fatalf("signing the moved tag: %v", err)
	}

	// Without --rehash this verifies: the registry's copy is signed, and
	// nothing has looked at what is on disk here.
	if _, err := runVerifyIn(t, home, ref, "--key", pubKey); err != nil {
		t.Fatalf("the registry's copy is signed and must verify: %v", err)
	}

	_, err := runVerifyIn(t, home, ref, "--key", pubKey, "--rehash")
	if err == nil {
		t.Fatal("--rehash reported on blobs belonging to a different artifact")
	}
	if !strings.Contains(err.Error(), "not the ones that verified") {
		t.Errorf("the refusal does not say the blobs here are not the verified ones: %v", err)
	}
}

// TestExplainNamesWhatDatesAKeylessSignature: a Fulcio certificate lives
// minutes, so the log entry is what supplies a moment to hold it to. A chain
// that reported the signer without saying what dated it would leave the
// reader with no way to look the signature up.
//
// The same fixture covers the gap on the other side. A source attestation is
// checked against the key that signed the model, and a keyless signature
// supplies an identity instead, so these layers name an upstream that
// nothing here vouches for. That has to read as unproven rather than as
// silence.
func TestExplainNamesWhatDatesAKeylessSignature(t *testing.T) {
	reg := registrytest.New(t)
	weights := []byte("weights signed without a key")
	reg.PutBlob("llm/qwen3", weights)
	layer := sourceLayer(weights, "huggingface.co/org/repo", "model.gguf", "abc123", strings.Repeat("11", 32))
	ref, l := seedKeylessModel(t, reg, []ocispec.Descriptor{layer})
	root := writeTrustRootFile(t, l)

	t.Setenv("PALAN_HOME", t.TempDir())
	v := viper.New()
	v.Set(keyRegistryPlainHTTP, true)
	v.Set(keyVerifyPolicy, keylessPolicy(reg.Host(), root, keylessSigner.Subject, keylessSigner.Issuer))
	cmd := newVerifyCmd(v)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{ref, "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("verifying a keyless signature: %v", err)
	}

	links := linkVerdicts(t, out.String())
	log, ok := links[linkLog]
	if !ok {
		t.Fatalf("the chain has no transparency log link; it was:\n%s", out.String())
	}
	if !strings.Contains(log.Detail, "entry ") {
		t.Errorf("the log link does not locate the entry: %+v", log)
	}
	if !strings.Contains(log.Detail, root) {
		t.Errorf("the log link does not name the root its proof was rebuilt against: %+v", log)
	}
	if !strings.Contains(links[linkSignature].Detail, keylessSigner.Subject) {
		t.Errorf("the signature link does not name who signed: %+v", links[linkSignature])
	}
	if links[linkSources].Proven {
		t.Errorf("provenance reads proven beside a keyless signature, which supplies no key to check it with: %+v", links[linkSources])
	}
	if !strings.Contains(links[linkSources].Detail, "upstream source") {
		t.Errorf("the provenance link does not say what was left unchecked: %+v", links[linkSources])
	}
}
