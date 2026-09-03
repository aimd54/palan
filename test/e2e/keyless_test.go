//go:build e2e

// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/aimd54/palan/internal/keyless/keylesstest"
	"github.com/aimd54/palan/internal/signing"
)

const bundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"

var e2eSigner = keylesstest.Signer{
	Subject: "https://forge.example/org/models/.github/workflows/release.yml@refs/tags/v3.0.0",
	Issuer:  "https://token.forge.example",
}

// writeKeylessConfig writes the config a host verifying keyless signatures
// carries: a pattern, the identity allowed under it, and the trusted root
// the certificate is checked against.
func writeKeylessConfig(t *testing.T, pattern, trustRoot, subject, issuer string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	cfg := "registry:\n  plain-http: true\nverify:\n  required: true\n  policy:\n" +
		"    - pattern: \"" + pattern + "\"\n" +
		"      trust-root: " + trustRoot + "\n" +
		"      identities:\n" +
		"        - subject: \"" + subject + "\"\n" +
		"          issuer: \"" + issuer + "\"\n"
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeTrustRootFile(t *testing.T, l *keylesstest.Log) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "trusted-root.json")
	if err := os.WriteFile(path, l.TrustedRoot, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// attachBundleToRegistry publishes a keyless signature the way a signing
// tool does: as a referrer of the model with no tag of its own, pushed to a
// real registry that answers the referrers API natively.
func attachBundleToRegistry(t *testing.T, ref string, subject ocispec.Descriptor, bundleJSON []byte) {
	t.Helper()
	ctx := context.Background()
	repo, err := remote.NewRepository(ref)
	if err != nil {
		t.Fatal(err)
	}
	repo.PlainHTTP = true

	cfg := []byte("{}")
	cfgDesc := content.NewDescriptorFromBytes(ocispec.MediaTypeImageConfig, cfg)
	if err := repo.Blobs().Push(ctx, cfgDesc, bytes.NewReader(cfg)); err != nil {
		t.Fatalf("pushing the bundle config: %v", err)
	}
	blobDesc := content.NewDescriptorFromBytes(bundleMediaType, bundleJSON)
	if err := repo.Blobs().Push(ctx, blobDesc, bytes.NewReader(bundleJSON)); err != nil {
		t.Fatalf("pushing the bundle: %v", err)
	}

	manifest := ocispec.Manifest{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: bundleMediaType,
		Config:       cfgDesc,
		Layers:       []ocispec.Descriptor{blobDesc},
		Subject:      &subject,
	}
	manifest.SchemaVersion = 2
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	mDesc := content.NewDescriptorFromBytes(manifest.MediaType, raw)
	mDesc.ArtifactType = manifest.ArtifactType
	if err := repo.Manifests().Push(ctx, mDesc, bytes.NewReader(raw)); err != nil {
		t.Fatalf("attaching the keyless signature: %v", err)
	}
}

// TestKeylessSignatureIsIndexedByTheRegistry is the reason this test exists
// at all rather than only in the unit suite.
//
// Bundle discovery asks the registry what refers to the model, and nothing
// else: no tag is consulted, because a tag is something anybody with push
// access can create. The in-process registry the unit tests use answers no
// referrers API, so oras-go falls back to the tag-schema index there and the
// native path never runs. zot answers it for real.
func TestKeylessSignatureIsIndexedByTheRegistry(t *testing.T) {
	host := registryHost(t)
	fx := writeFixtures(t, 96<<10)
	ref := host + "/llm/keyless-indexed:v1"
	home := t.TempDir()
	palan(t, home, "pack", fx.ggufPath, "-t", ref)
	palan(t, home, "push", ref)

	repo, desc := resolveRef(t, ref)
	l := keylesstest.NewLog(t)
	attachBundleToRegistry(t, ref, desc, l.Bundle(t, desc.Digest, e2eSigner))

	// The capability is forced rather than detected, which is the point of
	// running this against zot at all. oras-go falls back to a tag-schema
	// index when a registry answers no referrers API, and the in-process
	// registry the unit tests use does exactly that, so those tests never
	// exercise the native endpoint. Forcing it means a registry that does
	// not serve the endpoint fails here instead of quietly proving nothing.
	native, err := remote.NewRepository(ref)
	if err != nil {
		t.Fatal(err)
	}
	native.PlainHTTP = true
	if err := native.SetReferrersCapability(true); err != nil {
		t.Fatal(err)
	}

	// Asked for by exact artifact type, which is stricter than palan's own
	// filter: palan lists referrers unfiltered and selects by media type
	// prefix. A registry that indexed the bundle under some other type
	// fails here rather than silently going undiscovered later.
	refs, err := registry.Referrers(context.Background(), native, desc, bundleMediaType)
	if err != nil {
		t.Fatalf("the registry does not serve the referrers API natively: %v", err)
	}
	if len(refs) != 1 {
		t.Fatalf("registry indexed %d keyless signatures for the model, want 1", len(refs))
	}

	// And there is deliberately no tag: this is the shape a signing tool
	// publishes, and finding it must not depend on one existing.
	//
	// The name is checked to be usable first. A malformed reference would
	// also fail to resolve, and this assertion would then pass while
	// showing nothing about whether a tag exists.
	tag := signing.BundleTag(refs[0].Digest)
	if err := (registry.Reference{
		Registry: parsedHost(t, ref), Repository: "llm/keyless-indexed", Reference: tag,
	}).ValidateReference(); err != nil {
		t.Fatalf("the bundle tag %q is not a usable reference: %v", tag, err)
	}
	if _, err := repo.Resolve(context.Background(), tag); err == nil {
		t.Error("the bundle resolves under a tag, so this test would not prove referrer discovery")
	}
}

// TestKeylessVerifyThroughARealRegistry runs the whole milestone against
// zot: pack, push, attach a keyless signature, pull it into a store that
// never saw it, and verify with the registry no longer consulted.
func TestKeylessVerifyThroughARealRegistry(t *testing.T) {
	host := registryHost(t)
	fx := writeFixtures(t, 96<<10)
	ref := host + "/llm/keyless-verify:v1"

	publisher := t.TempDir()
	palan(t, publisher, "pack", fx.ggufPath, "-t", ref)
	palan(t, publisher, "push", ref)
	_, desc := resolveRef(t, ref)

	l := keylesstest.NewLog(t)
	attachBundleToRegistry(t, ref, desc, l.Bundle(t, desc.Digest, e2eSigner))
	cfg := writeKeylessConfig(t, host+"/**", writeTrustRootFile(t, l),
		e2eSigner.Subject, e2eSigner.Issuer)

	// verify.required is set, so the pull is gated on the keyless
	// signature. That the gate is what runs is established by the sibling
	// refusal test rather than by this one; here the pull is the way the
	// signature reaches a store that never saw it.
	consumer := t.TempDir()
	out := palan(t, consumer, "--config", cfg, "pull", ref)
	if !strings.Contains(out, "Keyless signature stored alongside the model") {
		t.Errorf("pull output does not report the signature travelling:\n%s", out)
	}

	out = palan(t, consumer, "--config", cfg, "verify", ref)
	if !strings.Contains(out, "source: local store") {
		t.Errorf("verify did not read the store:\n%s", out)
	}
	if !strings.Contains(out, e2eSigner.Subject) {
		t.Errorf("verify did not name the signer:\n%s", out)
	}
}

// TestKeylessRefusalSurvivesARealRegistry holds the acceptance criterion's
// second half against real infrastructure: the same artifact, the same
// policy, with the inclusion proof taken out.
func TestKeylessRefusalSurvivesARealRegistry(t *testing.T) {
	host := registryHost(t)
	fx := writeFixtures(t, 96<<10)
	ref := host + "/llm/keyless-stripped:v1"

	publisher := t.TempDir()
	palan(t, publisher, "pack", fx.ggufPath, "-t", ref)
	palan(t, publisher, "push", ref)
	_, desc := resolveRef(t, ref)

	l := keylesstest.NewLog(t)
	full := l.Bundle(t, desc.Digest, e2eSigner)
	var parsed map[string]any
	if err := json.Unmarshal(full, &parsed); err != nil {
		t.Fatal(err)
	}
	entry := parsed["verificationMaterial"].(map[string]any)["tlogEntries"].([]any)[0].(map[string]any)
	delete(entry, "inclusionProof")
	stripped, err := json.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	attachBundleToRegistry(t, ref, desc, stripped)

	cfg := writeKeylessConfig(t, host+"/**", writeTrustRootFile(t, l),
		e2eSigner.Subject, e2eSigner.Issuer)
	consumer := t.TempDir()
	out, err := palanRun(consumer, "--config", cfg, "pull", ref)
	if err == nil {
		t.Fatalf("a signature with no inclusion proof was accepted:\n%s", out)
	}
	if !strings.Contains(out, "no offline evidence") {
		t.Errorf("refusal does not say what is missing:\n%s", out)
	}
	// The refusal has to leave nothing behind: the gate runs before the
	// weights move, and a store holding them would mean it ran too late.
	if held, lsErr := palanRun(consumer, "--config", cfg, "ls"); lsErr == nil &&
		strings.Contains(held, "keyless-stripped") {
		t.Errorf("the refused model is in the store:\n%s", held)
	}
}

// TestCosignNewBundleFormatIsReadAsABundle checks palan against the real
// tool's output rather than against material palan itself produced.
//
// A full keyless signature cannot be made here: it needs a browser sign-in,
// a certificate authority and a transparency log. What can be checked is
// everything up to the cryptography, which is the half a fixture cannot
// prove: that `cosign sign --new-bundle-format` publishes a bundle where
// palan looks for one, under a media type palan recognises. cosign signing
// with a key writes a bundle naming a bare public key, so palan must find
// it and then refuse it for having no certificate to hold to a policy.
// Refusing for that reason is the evidence the bundle was read.
func TestCosignNewBundleFormatIsReadAsABundle(t *testing.T) {
	cosign := requireTool(t, "cosign")
	t.Setenv("COSIGN_PASSWORD", testKeyPassword)
	host := registryHost(t)
	fx := writeFixtures(t, 96<<10)
	priv, _ := writeTestKeys(t)

	ref := host + "/llm/cosign-newbundle:v1"
	home := t.TempDir()
	palan(t, home, "pack", fx.ggufPath, "-t", ref)
	palan(t, home, "push", ref)

	cs := exec.Command(cosign, "sign", "--key", priv,
		"--new-bundle-format", "--tlog-upload=false",
		"--allow-insecure-registry", "--yes", ref)
	cs.Env = append(os.Environ(), "HOME="+t.TempDir())
	if out, err := cs.CombinedOutput(); err != nil {
		t.Fatalf("cosign sign --new-bundle-format failed: %v\n%s", err, out)
	}

	// palan's own discovery finds it, which is the interop claim: the media
	// type cosign writes is the one palan filters referrers by.
	repo, desc := resolveRef(t, ref)
	found, err := signing.BundleReferrers(context.Background(), repo, desc)
	if err != nil {
		t.Fatalf("looking for the bundle cosign wrote: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("palan found %d bundles attached by cosign, want 1", len(found))
	}

	l := keylesstest.NewLog(t)
	cfg := writeKeylessConfig(t, host+"/**", writeTrustRootFile(t, l),
		e2eSigner.Subject, e2eSigner.Issuer)
	out, err := palanRun(t.TempDir(), "--config", cfg, "verify", ref)
	if err == nil {
		t.Fatalf("a bundle naming no certificate verified:\n%s", out)
	}
	// The reason matters more than the refusal. This message can only come
	// from code that parsed the bundle and read its verification material,
	// so it says the format was understood rather than skipped.
	if !strings.Contains(out, "public key rather than by certificate") {
		t.Errorf("palan did not read cosign's bundle; it refused for another reason:\n%s", out)
	}
}

// parsedHost returns the registry host of a reference, for building a
// reference to validate.
func parsedHost(t *testing.T, ref string) string {
	t.Helper()
	parsed, err := registry.ParseReference(ref)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.Registry
}
