// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/spf13/viper"
	oras "oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/aimd54/palan/internal/attest"
	"github.com/aimd54/palan/internal/refname"
	"github.com/aimd54/palan/internal/registrytest"
	"github.com/aimd54/palan/internal/signing"
	"github.com/aimd54/palan/pkg/modelspec"
)

// attestKeypair generates an ECDSA P-256 key for these tests, and writes
// its private half out as a PEM file for the --key flag the sign and
// verify commands read. The raw key is returned too, for tests that build a
// signature.Signer or signature.Verifier directly against internal/attest
// rather than going through a command's flag.
func attestKeypair(t *testing.T) (priv *ecdsa.PrivateKey, keyFile string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := cryptoutils.MarshalPrivateKeyToPEM(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyFile = filepath.Join(t.TempDir(), "cosign.key")
	if err := os.WriteFile(keyFile, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return priv, keyFile
}

// attestPubKeyFile writes priv's public half out as a PEM file, for the
// verify command's --key flag.
func attestPubKeyFile(t *testing.T, priv *ecdsa.PrivateKey) string {
	t.Helper()
	pemBytes, err := cryptoutils.MarshalPublicKeyToPEM(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "cosign.pub")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// attestTestRepo mirrors internal/signing's own test helper of the same
// shape: a *remote.Repository pointed at a repository on a registrytest
// server, talking plain HTTP.
func attestTestRepo(t *testing.T, reg *registrytest.Registry, name string) *remote.Repository {
	t.Helper()
	repo, err := remote.NewRepository(reg.Host() + "/" + name)
	if err != nil {
		t.Fatal(err)
	}
	repo.PlainHTTP = true
	repo.Client = &auth.Client{Credential: auth.StaticCredential("", auth.EmptyCredential)}
	return repo
}

// sourceLayer builds a layer descriptor the way pack records one fetched
// from a repository: source annotations plus the bare-hex published digest
// the repository reported for it.
func sourceLayer(data []byte, repo, path, revision, originSHA256 string) ocispec.Descriptor {
	d := ocispec.Descriptor{
		MediaType: modelspec.MediaTypeModelWeightRaw,
		Digest:    digest.FromBytes(data),
		Size:      int64(len(data)),
		Annotations: map[string]string{
			modelspec.AnnotationFilepath: path,
		},
	}
	if repo != "" {
		d.Annotations[modelspec.AnnotationSourceRepo] = repo
	}
	if path != "" {
		d.Annotations[modelspec.AnnotationSourcePath] = path
	}
	if revision != "" {
		d.Annotations[modelspec.AnnotationSourceRevision] = revision
	}
	if originSHA256 != "" {
		d.Annotations[modelspec.AnnotationOriginSHA256] = originSHA256
	}
	return d
}

// localLayer builds a layer descriptor the way a purely local pack records
// one: no source annotations at all.
func localLayer(data []byte, path string) ocispec.Descriptor {
	return ocispec.Descriptor{
		MediaType:   modelspec.MediaTypeModelWeightRaw,
		Digest:      digest.FromBytes(data),
		Size:        int64(len(data)),
		Annotations: map[string]string{modelspec.AnnotationFilepath: path},
	}
}

// seedModel plants a manifest carrying layers directly in the registry,
// mirroring what pack would have pushed, without needing to push blob
// content the tests never fetch.
func seedModel(t *testing.T, reg *registrytest.Registry, repo, tag string, layers []ocispec.Descriptor) ocispec.Descriptor {
	t.Helper()
	cfg := []byte("{}")
	reg.PutBlob(repo, cfg)
	manifest := ocispec.Manifest{
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    content.NewDescriptorFromBytes(ocispec.MediaTypeImageConfig, cfg),
		Layers:    layers,
	}
	manifest.SchemaVersion = 2
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	d := reg.PutManifest(repo, tag, ocispec.MediaTypeImageManifest, raw)
	return ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: d, Size: int64(len(raw))}
}

// runSign executes the real sign command against ref, exactly as a caller
// on the command line would.
func runSign(t *testing.T, ref, keyFile string) error {
	t.Helper()
	v := viper.New()
	v.Set(keyRegistryPlainHTTP, true)
	cmd := newSignCmd(v)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{ref, "--key", keyFile})
	return cmd.Execute()
}

// runVerify executes the real verify command against ref, in a store
// isolated to a fresh temporary directory so it never touches a real one.
func runVerify(t *testing.T, ref, keyFile string) error {
	t.Helper()
	_, err := runVerifyCapture(t, ref, keyFile)
	return err
}

// runVerifyCapture is runVerify plus the command's stdout, for tests that
// need to check what verify actually reported rather than only whether it
// refused.
func runVerifyCapture(t *testing.T, ref, keyFile string) (string, error) {
	t.Helper()
	t.Setenv("PALAN_HOME", t.TempDir())
	v := viper.New()
	v.Set(keyRegistryPlainHTTP, true)
	cmd := newVerifyCmd(v)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{ref, "--key", keyFile})
	err := cmd.Execute()
	return out.String(), err
}

// readAttestation fetches and verifies the attestation sign wrote for ref,
// the way a caller inspecting provenance directly would, without going
// through the verify command (which reports pass/fail, not the layers).
func readAttestation(t *testing.T, ref string, pubKey signature.Verifier) ([]attest.Layer, error) {
	t.Helper()
	parsed, err := refname.Parse(ref, "")
	if err != nil {
		t.Fatal(err)
	}
	v := viper.New()
	v.Set(keyRegistryPlainHTTP, true)
	client, err := newTransferClient(v)
	if err != nil {
		t.Fatal(err)
	}
	repo, err := client.Repository(parsed)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	desc, err := repo.Resolve(ctx, parsed.Reference)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := signing.FetchAttestation(
		ctx, repo, signing.AttTag(desc.Digest), desc)
	if err != nil {
		return nil, err
	}
	return attest.Verify(envelope, desc, pubKey)
}

func TestSignWritesAnAttestationVerifyReadsIt(t *testing.T) {
	// Pack an artifact whose layers carry source annotations, push it to a
	// fake registry, sign it, then verify. The attestation must come back
	// naming the same repository and path the layers record.
	reg := registrytest.New(t)
	layer := sourceLayer([]byte("weights"), "huggingface.co/org/repo", "model.gguf", "abc123", strings.Repeat("11", 32))
	seedModel(t, reg, "llm/tiny", "q4", []ocispec.Descriptor{layer})
	priv, privKey := attestKeypair(t)
	pubKey, err := signature.LoadVerifier(&priv.PublicKey, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	ref := reg.Host() + "/llm/tiny:q4"

	if err := runSign(t, ref, privKey); err != nil {
		t.Fatalf("sign: %v", err)
	}
	layers, err := readAttestation(t, ref, pubKey)
	if err != nil {
		t.Fatalf("reading the attestation sign wrote: %v", err)
	}
	if len(layers) == 0 {
		t.Fatal("sign wrote an attestation covering no layers")
	}
	if layers[0].Repo != "huggingface.co/org/repo" {
		t.Errorf("layer repo = %q, want the source the layer records", layers[0].Repo)
	}
}

func TestSignWritesNoAttestationForALocalPack(t *testing.T) {
	// An artifact whose layers carry no source annotations gets a signature
	// and nothing else: there is nothing to attest to.
	reg := registrytest.New(t)
	layer := localLayer([]byte("weights"), "model.gguf")
	target := seedModel(t, reg, "llm/tiny", "q4", []ocispec.Descriptor{layer})
	priv, privKey := attestKeypair(t)
	pubKey, err := signature.LoadVerifier(&priv.PublicKey, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	ref := reg.Host() + "/llm/tiny:q4"

	if err := runSign(t, ref, privKey); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !reg.HasManifest("llm/tiny", signing.SigTag(target.Digest)) {
		t.Error("sign did not write a signature for an artifact with no source to state")
	}
	if _, err := readAttestation(t, ref, pubKey); !errors.Is(err, attest.ErrNoAttestation) {
		t.Fatalf("err = %v, want ErrNoAttestation: a local pack has no source to state", err)
	}
}

func TestVerifyRefusesAnAttestationNamingALayerTheArtifactLacks(t *testing.T) {
	// Build an attestation over a layer digest the manifest does not have,
	// push it, and verify: the mismatch must refuse.
	reg := registrytest.New(t)
	layer := sourceLayer([]byte("weights"), "huggingface.co/org/repo", "model.gguf", "abc123", "")
	target := seedModel(t, reg, "llm/tiny", "q4", []ocispec.Descriptor{layer})
	priv, privKey := attestKeypair(t)
	pubKey := attestPubKeyFile(t, priv)
	ref := reg.Host() + "/llm/tiny:q4"

	if err := runSign(t, ref, privKey); err != nil {
		t.Fatalf("sign: %v", err)
	}

	signer, err := signature.LoadSigner(priv, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	bogus := []attest.Layer{{
		Digest: "sha256:" + strings.Repeat("ab", 32),
		Repo:   "huggingface.co/org/repo",
		Path:   "model.gguf",
	}}
	envelope, err := attest.Build(target, bogus, signer)
	if err != nil {
		t.Fatal(err)
	}
	attestRepo := attestTestRepo(t, reg, "llm/tiny")
	if _, err := signing.PushAttestation(context.Background(), attestRepo, target, envelope); err != nil {
		t.Fatal(err)
	}

	err = runVerify(t, ref, pubKey)
	if err == nil {
		t.Fatal("verified an attestation about layers this artifact does not have")
	}
}

// TestVerifySucceedsAndNamesTheSourceItAttestedTo is the passing path none
// of the refusal tests exercise: a model signed with a source-carrying
// attestation must verify cleanly, and the report must name the actual
// repository and revision the layers record, not merely say something
// passed.
func TestVerifySucceedsAndNamesTheSourceItAttestedTo(t *testing.T) {
	reg := registrytest.New(t)
	layer := sourceLayer([]byte("weights"), "huggingface.co/org/repo", "model.gguf", "abc123", strings.Repeat("11", 32))
	seedModel(t, reg, "llm/tiny", "q4", []ocispec.Descriptor{layer})
	priv, privKey := attestKeypair(t)
	pubKey := attestPubKeyFile(t, priv)
	ref := reg.Host() + "/llm/tiny:q4"

	if err := runSign(t, ref, privKey); err != nil {
		t.Fatalf("sign: %v", err)
	}

	out, err := runVerifyCapture(t, ref, pubKey)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	want := "  provenance: huggingface.co/org/repo@abc123\n"
	if !strings.Contains(out, want) {
		t.Errorf("verify output = %q, want it to contain %q", out, want)
	}
}

// TestVerifySurvivesARegistryThatHidesMissingAttestationTags: some
// registries answer 401 or 403 for a tag that does not exist rather than
// 404. The model's own signature verifies cleanly here; the registry only
// hides whether the attestation tag exists. That must not turn a perfectly
// signed artifact into a failed verification.
func TestVerifySurvivesARegistryThatHidesMissingAttestationTags(t *testing.T) {
	reg := registrytest.New(t)
	layer := localLayer([]byte("weights"), "model.gguf")
	seedModel(t, reg, "llm/tiny", "q4", []ocispec.Descriptor{layer})
	priv, privKey := attestKeypair(t)
	pubKey := attestPubKeyFile(t, priv)
	ref := reg.Host() + "/llm/tiny:q4"

	if err := runSign(t, ref, privKey); err != nil {
		t.Fatalf("sign: %v", err)
	}
	reg.SetMissingManifestStatus(http.StatusUnauthorized)

	out, err := runVerifyCapture(t, ref, pubKey)
	if err != nil {
		t.Fatalf("verify must succeed against a registry that hides a missing attestation tag: %v", err)
	}
	want := "Verified " + ref
	if !strings.Contains(out, want) {
		t.Errorf("verify output = %q, want it to contain %q", out, want)
	}
}

// TestSignAndVerifyTwoSourcesSharingOneFilesBytes: two repositories that
// ship a byte-identical file, an Apache-2.0 LICENSE being the ordinary
// case, produce two layers with one digest and two different sources.
// Records keyed by digest alone collapse into one, and palan then refuses
// its own freshly signed artifact.
func TestSignAndVerifyTwoSourcesSharingOneFilesBytes(t *testing.T) {
	reg := registrytest.New(t)
	shared := []byte("Apache License, Version 2.0")
	fromA := sourceLayer(shared, "huggingface.co/org/a", "LICENSE", "aaaa111", "")
	fromB := sourceLayer(shared, "huggingface.co/org/b", "LICENSE", "bbbb222", "")
	if fromA.Digest != fromB.Digest {
		t.Fatalf("fixture is not exercising the case: %s != %s", fromA.Digest, fromB.Digest)
	}
	seedModel(t, reg, "llm/tiny", "q4", []ocispec.Descriptor{fromA, fromB})
	priv, privKey := attestKeypair(t)
	pubKey := attestPubKeyFile(t, priv)
	ref := reg.Host() + "/llm/tiny:q4"

	if err := runSign(t, ref, privKey); err != nil {
		t.Fatalf("sign: %v", err)
	}
	out, err := runVerifyCapture(t, ref, pubKey)
	if err != nil {
		t.Fatalf("palan must verify an artifact it signed itself: %v", err)
	}
	// Both sources must be reported. One line would mean one record stood
	// in for both, which is the collapse this test exists to catch.
	for _, want := range []string{
		"  provenance: huggingface.co/org/a@aaaa111\n",
		"  provenance: huggingface.co/org/b@bbbb222\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("verify output = %q, want it to contain %q", out, want)
		}
	}
}

// TestVerifyRefusesAnAttestationCoveringOnlyOneOfTwoIdenticalLayers is the
// converse: a statement that names one of two same-digest layers must not
// be accepted as vouching for the other, whose source it never mentions.
func TestVerifyRefusesAnAttestationCoveringOnlyOneOfTwoIdenticalLayers(t *testing.T) {
	shared := []byte("Apache License, Version 2.0")
	fromA := sourceLayer(shared, "huggingface.co/org/a", "LICENSE", "aaaa111", "")
	fromB := sourceLayer(shared, "huggingface.co/org/b", "LICENSE", "bbbb222", "")
	man := ocispec.Manifest{Layers: []ocispec.Descriptor{fromA, fromB}}

	onlyB := []attest.Layer{{
		Digest:   fromB.Digest.String(),
		Repo:     "huggingface.co/org/b",
		Path:     "LICENSE",
		Revision: "bbbb222",
	}}
	if err := attestationMatchesManifest(onlyB, man); err == nil {
		t.Error("a statement naming one of two same-digest layers must not be accepted as covering both")
	}

	// The honest statement, naming both, must still pass.
	both := append(onlyB, attest.Layer{
		Digest:   fromA.Digest.String(),
		Repo:     "huggingface.co/org/a",
		Path:     "LICENSE",
		Revision: "aaaa111",
	})
	if err := attestationMatchesManifest(both, man); err != nil {
		t.Errorf("a statement naming both layers must be accepted: %v", err)
	}
}

// TestSignSaysWhetherItWroteAnAttestation: a model whose layers record no
// source is signed without one, and a model whose layers do record one is
// signed with it. Both exit 0 saying "Signed", and verify later reports no
// provenance for either, so sign is the only place that can distinguish
// them for a reader. Silence here is the shape this project treats as a
// defect: a command exiting 0 having written nothing.
func TestSignSaysWhetherItWroteAnAttestation(t *testing.T) {
	for _, tc := range []struct {
		name         string
		layers       []ocispec.Descriptor
		wantOut      string
		wantMiss     string
		wantAttested int
	}{
		{
			name:         "a fetched layer is attested",
			layers:       []ocispec.Descriptor{sourceLayer([]byte("weights"), "huggingface.co/org/repo", "model.gguf", "abc123", "")},
			wantOut:      "Attested the source of 1 of 1 layer(s)",
			wantAttested: 1,
		},
		{
			// The case a bare count cannot express: a mixed pack, where
			// most of the artifact has provenance and part of it does not.
			name: "a partly sourced artifact says how much it covers",
			layers: []ocispec.Descriptor{
				sourceLayer([]byte("fetched weights"), "huggingface.co/org/repo", "model.gguf", "abc123", ""),
				localLayer([]byte("a local template"), "template.jinja"),
			},
			wantOut:      "Attested the source of 1 of 2 layer(s)",
			wantAttested: 1,
		},
		{
			name:     "a local layer is not, and sign says so",
			layers:   []ocispec.Descriptor{localLayer([]byte("weights"), "model.gguf")},
			wantMiss: "No source attestation written",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reg := registrytest.New(t)
			seedModel(t, reg, "llm/tiny", "q4", tc.layers)
			priv, privKey := attestKeypair(t)

			t.Setenv("COSIGN_PASSWORD", "")
			v := viper.New()
			v.Set(keyRegistryPlainHTTP, true)
			cmd := newSignCmd(v)
			var out, errOut bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&errOut)
			cmd.SetArgs([]string{reg.Host() + "/llm/tiny:q4", "--key", privKey})
			if err := cmd.Execute(); err != nil {
				t.Fatalf("sign: %v", err)
			}
			// Asserted on stdout alone. Folding the streams together would
			// pass with either line moved to stderr, and both describe the
			// same outcome of the same command.
			if tc.wantOut != "" && !strings.Contains(out.String(), tc.wantOut) {
				t.Errorf("sign wrote %q to stdout, want it to contain %q (stderr: %q)", out.String(), tc.wantOut, errOut.String())
			}
			if tc.wantMiss != "" && !strings.Contains(out.String(), tc.wantMiss) {
				t.Errorf("sign wrote %q to stdout, want it to contain %q (stderr: %q)", out.String(), tc.wantMiss, errOut.String())
			}

			// What sign said must match what is actually on the registry.
			// Checking the message alone would pass with the attestation
			// never pushed, which is the defect class this test names.
			ref := reg.Host() + "/llm/tiny:q4"
			recorded, err := readAttestation(t, ref, verifierFor(t, priv))
			if tc.wantAttested > 0 {
				if err != nil {
					t.Fatalf("sign said it attested, but no attestation is readable: %v", err)
				}
				if len(recorded) != tc.wantAttested {
					t.Errorf("attestation covers %d layers, want %d", len(recorded), tc.wantAttested)
				}
			} else if !errors.Is(err, attest.ErrNoAttestation) {
				t.Errorf("sign said it wrote none, so none must be readable; got %v (%v)", recorded, err)
			}
		})
	}
}

// TestAttestationMismatchNamesTheSameLayerEveryTime: with more than one
// layer left uncovered, the refusal must name the same one on every run.
// Reporting from a map walk picks an arbitrary entry, so the message a
// caller sees, and any test or tool matching on it, changes between runs
// for one unchanged artifact.
func TestAttestationMismatchNamesTheSameLayerEveryTime(t *testing.T) {
	man := ocispec.Manifest{Layers: []ocispec.Descriptor{
		sourceLayer([]byte("first"), "huggingface.co/org/a", "a.safetensors", "aaa111", ""),
		sourceLayer([]byte("second"), "huggingface.co/org/b", "b.safetensors", "bbb222", ""),
		sourceLayer([]byte("third"), "huggingface.co/org/c", "c.safetensors", "ccc333", ""),
	}}
	// An attestation covering none of them: every layer is a candidate for
	// the message, so an arbitrary pick has three values to choose from.
	first := attestationMatchesManifest(nil, man)
	if first == nil {
		t.Fatal("an attestation covering none of the artifact's sourced layers must be refused")
	}
	for i := range 40 {
		got := attestationMatchesManifest(nil, man)
		if got == nil || got.Error() != first.Error() {
			t.Fatalf("run %d reported %v, want the same layer as the first run: %v", i, got, first)
		}
	}
	// And it must be the manifest's first layer, not merely a stable one.
	if !strings.Contains(first.Error(), "a.safetensors") {
		t.Errorf("refusal = %v, want it to name the first uncovered layer", first)
	}
}

// verifierFor builds a verifier from a keypair's public half, for tests
// that read an attestation back through internal/attest directly.
func verifierFor(t *testing.T, priv *ecdsa.PrivateKey) signature.Verifier {
	t.Helper()
	v, err := signature.LoadVerifier(&priv.PublicKey, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestVerifyWarnsWhenSourcedLayersHaveNoAttestation: deleting an
// attestation is a downgrade that forges nothing. The signature still
// verifies, so without a word here the whole event is silent and the
// output is identical to a model that was never packed from upstream.
// The artifact's own layers are the evidence: they record where they came
// from, so a statement should exist.
func TestVerifyWarnsWhenSourcedLayersHaveNoAttestation(t *testing.T) {
	reg := registrytest.New(t)
	layer := sourceLayer([]byte("weights"), "huggingface.co/org/repo", "model.gguf", "abc123", "")
	mDesc := seedModel(t, reg, "llm/tiny", "q4", []ocispec.Descriptor{layer})
	priv, _ := attestKeypair(t)
	pubKey := attestPubKeyFile(t, priv)
	ref := reg.Host() + "/llm/tiny:q4"

	// Signed without the attestation, which is what a failed attestation
	// push leaves behind and what deleting the statement produces. The
	// signature is untouched, so nothing is forged and nothing refuses.
	signer, err := signature.LoadSigner(priv, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	repo := attestTestRepo(t, reg, "llm/tiny")
	if _, err := signing.Sign(t.Context(), repo, reg.Host()+"/llm/tiny", mDesc, signer); err != nil {
		t.Fatalf("sign: %v", err)
	}

	out, err := runVerifyCapture(t, ref, pubKey)
	if err != nil {
		t.Fatalf("the model is signed, so verify must still pass: %v", err)
	}
	if !strings.Contains(out, "Verified") {
		t.Fatalf("verify reported %q, want a pass", out)
	}
	if !strings.Contains(out, "WARNING") || !strings.Contains(out, "no attestation is present") {
		t.Errorf("verify reported %q, want it to say the attestation these layers imply is missing", out)
	}
	// The signature is genuinely fine; the point is that only this line
	// separates the two cases.
	if strings.Contains(out, "provenance:") {
		t.Errorf("verify reported %q, but there is no attestation to draw provenance from", out)
	}
}

// TestVerifyStaysQuietForAnArtifactWithNoUpstream is the other half: a
// model packed from local files owes no statement, and warning about every
// one of them would make the warning worthless.
func TestVerifyStaysQuietForAnArtifactWithNoUpstream(t *testing.T) {
	reg := registrytest.New(t)
	seedModel(t, reg, "llm/tiny", "q4", []ocispec.Descriptor{localLayer([]byte("weights"), "model.gguf")})
	priv, privKey := attestKeypair(t)
	pubKey := attestPubKeyFile(t, priv)
	ref := reg.Host() + "/llm/tiny:q4"

	if err := runSign(t, ref, privKey); err != nil {
		t.Fatalf("sign: %v", err)
	}
	out, err := runVerifyCapture(t, ref, pubKey)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if strings.Contains(out, "WARNING") {
		t.Errorf("verify reported %q, but a purely local artifact owes no attestation", out)
	}
	if !strings.Contains(out, "Verified") {
		t.Errorf("verify reported %q, want a clean pass", out)
	}
}

// TestVerifyFromAStoreMissingOnlyTheAttestationWarnsRatherThanRefusing
// pins the consequence ADR-0014 accepts. Verification prefers the local
// store on the strength of the signature alone, so a store holding a model
// and its signature but not its attestation never asks the registry, which
// does hold one. That trade is deliberate: an artifact that never had an
// attestation is the ordinary case and would otherwise cost a registry
// round trip on every verification. What must not happen is that it passes
// in silence.
func TestVerifyFromAStoreMissingOnlyTheAttestationWarnsRatherThanRefusing(t *testing.T) {
	reg := registrytest.New(t)
	weights := []byte("weights")
	reg.PutBlob("llm/tiny", weights) // seedModel plants the manifest, not the content
	layer := sourceLayer(weights, "huggingface.co/org/repo", "model.gguf", "abc123", "")
	mDesc := seedModel(t, reg, "llm/tiny", "q4", []ocispec.Descriptor{layer})
	priv, privKey := attestKeypair(t)
	pubKey := attestPubKeyFile(t, priv)
	ref := reg.Host() + "/llm/tiny:q4"

	// The registry holds everything, attestation included.
	if err := runSign(t, ref, privKey); err != nil {
		t.Fatalf("sign: %v", err)
	}

	// A store that pulled the model and its signature and did not get the
	// attestation, which is what a failed attestation fetch leaves.
	home := t.TempDir()
	t.Setenv("PALAN_HOME", home)
	st, err := openStore(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := refname.Parse(ref, "")
	if err != nil {
		t.Fatal(err)
	}
	repo := attestTestRepo(t, reg, "llm/tiny")
	if _, err := oras.Copy(t.Context(), repo, "q4", st.OCI(), parsed.String(), oras.DefaultCopyOptions); err != nil {
		t.Fatal(err)
	}
	sigTag := signing.SigTag(mDesc.Digest)
	if _, err := oras.Copy(t.Context(), repo, sigTag, st.OCI(), signing.SigRef(parsed, mDesc.Digest), oras.DefaultCopyOptions); err != nil {
		t.Fatal(err)
	}

	v := viper.New()
	v.Set(keyRegistryPlainHTTP, true)
	cmd := newVerifyCmd(v)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{ref, "--key", pubKey})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("the model and its signature are both here, so verify must pass: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "source: local store") {
		t.Fatalf("verify reported %q, want it to have answered from the store", got)
	}
	if !strings.Contains(got, "WARNING") {
		t.Errorf("verify reported %q: the registry holds an attestation this store does not, and nothing said so", got)
	}
}

// TestVerifyWarnsWhenTheManifestCannotBeReadToSayWhatWasOwed: the report
// of a missing attestation is itself something that can be silenced.
// Whoever can delete a tag to strip the statement can delete one more file
// so the manifest cannot be read, and a report that answers "nothing to
// say" on a failed read gives them exactly the silence they were after.
func TestVerifyWarnsWhenTheManifestCannotBeReadToSayWhatWasOwed(t *testing.T) {
	reg := registrytest.New(t)
	weights := []byte("weights")
	reg.PutBlob("llm/tiny", weights)
	layer := sourceLayer(weights, "huggingface.co/org/repo", "model.gguf", "abc123", "")
	mDesc := seedModel(t, reg, "llm/tiny", "q4", []ocispec.Descriptor{layer})
	priv, _ := attestKeypair(t)
	pubKey := attestPubKeyFile(t, priv)
	ref := reg.Host() + "/llm/tiny:q4"

	signer, err := signature.LoadSigner(priv, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	repo := attestTestRepo(t, reg, "llm/tiny")
	if _, err := signing.Sign(t.Context(), repo, reg.Host()+"/llm/tiny", mDesc, signer); err != nil {
		t.Fatalf("sign: %v", err)
	}

	// A store holding the model and its signature, then robbed of the one
	// file that says what the artifact is made of. The tag still resolves,
	// because the index records the descriptor, and the signature still
	// verifies, because it is read from its own manifest.
	home := t.TempDir()
	t.Setenv("PALAN_HOME", home)
	st, err := openStore(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := refname.Parse(ref, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := oras.Copy(t.Context(), repo, "q4", st.OCI(), parsed.String(), oras.DefaultCopyOptions); err != nil {
		t.Fatal(err)
	}
	sigTag := signing.SigTag(mDesc.Digest)
	if _, err := oras.Copy(t.Context(), repo, sigTag, st.OCI(), signing.SigRef(parsed, mDesc.Digest), oras.DefaultCopyOptions); err != nil {
		t.Fatal(err)
	}
	blob := filepath.Join(home, "blobs", "sha256", mDesc.Digest.Encoded())
	if err := os.Remove(blob); err != nil {
		t.Fatalf("removing the manifest blob: %v", err)
	}

	v := viper.New()
	v.Set(keyRegistryPlainHTTP, true)
	cmd := newVerifyCmd(v)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{ref, "--key", pubKey})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("the signature is intact, so verify must still pass: %v", err)
	}
	if !strings.Contains(out.String(), "WARNING") {
		t.Errorf("verify reported %q, want it to say it could not tell whether an attestation was owed", out.String())
	}
}

// TestVerifyFindsAnAttestationByItsTagInTheLocalStore pins the tag path
// rather than the referrers fallback. oci.Store answers Predecessors from
// the manifests it holds regardless of what they are tagged, so a broken
// tag lookup could still produce a correct result by accident; this test
// wraps the store in noReferrers so only a correct tag lookup can answer.
func TestVerifyFindsAnAttestationByItsTagInTheLocalStore(t *testing.T) {
	ctx := context.Background()
	reg := registrytest.New(t)
	weights := []byte("weights")
	reg.PutBlob("llm/tiny", weights) // seedModel plants only the manifest
	layer := sourceLayer(weights, "huggingface.co/org/repo",
		"model.gguf", "abc123", strings.Repeat("11", 32))
	mDesc := seedModel(t, reg, "llm/tiny", "a", []ocispec.Descriptor{layer})

	priv, keyFile := attestKeypair(t)
	modelRef := reg.Host() + "/llm/tiny:a"
	if err := runSign(t, modelRef, keyFile); err != nil {
		t.Fatalf("sign: %v", err)
	}
	parsed, err := refname.Parse(modelRef, "")
	if err != nil {
		t.Fatal(err)
	}

	// A store built the way save/load leave one: model, signature and
	// attestation, each tagged by full reference.
	st, err := oci.NewWithContext(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	repo := attestTestRepo(t, reg, "llm/tiny")
	if _, err := oras.Copy(ctx, repo, "a", st, parsed.String(),
		oras.DefaultCopyOptions); err != nil {
		t.Fatalf("copying the model into the store: %v", err)
	}
	sigRef := signing.SigRef(parsed, mDesc.Digest)
	if _, err := oras.Copy(ctx, repo, signing.SigTag(mDesc.Digest), st,
		sigRef, oras.DefaultCopyOptions); err != nil {
		t.Fatalf("copying the signature into the store: %v", err)
	}
	attRef := signing.AttRef(parsed, mDesc.Digest)
	if _, err := oras.Copy(ctx, repo, signing.AttTag(mDesc.Digest), st,
		attRef, oras.DefaultCopyOptions); err != nil {
		t.Fatalf("copying the attestation into the store: %v", err)
	}

	envelope, err := signing.FetchAttestation(
		ctx, noReferrers{st}, attRef, mDesc)
	if err != nil {
		t.Fatalf("resolving the attestation by its store reference: %v", err)
	}
	if len(envelope) == 0 {
		t.Fatal("the tag resolved but carried no envelope")
	}
	if _, err := attest.Verify(envelope, mDesc, verifierFor(t, priv)); err != nil {
		t.Fatalf("the envelope the tag path returned does not verify: %v", err)
	}
}

// noReferrers narrows a target down to Resolve, Fetch and Exists, hiding
// Predecessors so a test can rule out the referrers fallback answering in
// the tag lookup's place.
type noReferrers struct {
	oras.ReadOnlyTarget
}
