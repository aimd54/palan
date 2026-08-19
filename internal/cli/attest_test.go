// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/spf13/viper"
	"oras.land/oras-go/v2/content"
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
	t.Setenv("PALAN_HOME", t.TempDir())
	v := viper.New()
	v.Set(keyRegistryPlainHTTP, true)
	cmd := newVerifyCmd(v)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{ref, "--key", keyFile})
	return cmd.Execute()
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
	envelope, err := signing.FetchAttestation(ctx, repo, desc)
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
