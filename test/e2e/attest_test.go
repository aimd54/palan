// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package e2e

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/aimd54/palan/internal/gguf/gguftest"
	"github.com/aimd54/palan/internal/hf/hftest"
)

// attestRevision is a well-formed 40-character commit id, the shape hf.go
// requires before it will record a revision at all. It stands in for
// whatever commit a real Hugging Face repository would report.
const attestRevision = "a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4"

// hfSource starts a fake Hugging Face hub serving one GGUF file under
// org/repo and returns the hf:// reference to pack it from, plus the
// repository string an attestation built from it must record.
//
// internal/hf's Client honours HF_ENDPOINT (hf.go's NewClient), and
// hftest.New starts a real httptest.Server bound to a loopback TCP port
// rather than an in-process RoundTripper, so it is reachable over the
// network exactly as Hugging Face itself would be. That is what lets the
// palan binary, run as a subprocess by palan() below, resolve an hf://
// source at all: it never shares this test process's memory or transport.
func hfSource(t *testing.T, org, repo string, payload []byte) (source, sourceRepo string) {
	t.Helper()
	hub := hftest.New(t, map[string][]byte{"tiny.gguf": payload})
	hub.Revision = attestRevision
	t.Setenv("HF_ENDPOINT", hub.URL())
	sourceRepo = strings.TrimPrefix(hub.URL(), "http://") + "/" + org + "/" + repo
	return "hf://" + org + "/" + repo + "/tiny.gguf", sourceRepo
}

// TestAttestationSurvivesABundleAndVerifiesOffline packs a model from a fake
// repository, signs it, pushes it, carries it through a bundle into a second
// store, and verifies there with the registry gone. Provenance that does not
// survive the journey is provenance an offline site does not have.
func TestAttestationSurvivesABundleAndVerifiesOffline(t *testing.T) {
	t.Setenv("COSIGN_PASSWORD", testKeyPassword)
	host := registryHost(t)
	source, sourceRepo := hfSource(t, "org", "bundle-model",
		gguftest.TinyModel("llama", "tiny", "15M", 2048, 4, []byte("bundle-attest-weights")))
	priv, pub := writeTestKeys(t)

	ref := host + "/llm/attest-bundle:v1"

	online := t.TempDir()
	palan(t, online, "pack", source, "-t", ref)
	palan(t, online, "push", ref)
	palan(t, online, "sign", ref, "--key", priv)

	// sign writes the attestation straight to the registry, the same as it
	// does the signature, so pulling is what brings both down beside the
	// model in the local store (TestOfflineVerifyFromBundle in sign_test.go
	// establishes the same shape for a plain signature).
	palan(t, online, "pull", ref)

	bundle := filepath.Join(t.TempDir(), "attest.tar")
	palan(t, online, "save", ref, "-o", bundle)

	// A fresh store, never pointed at the registry beforehand: nothing here
	// was pulled, only imported from the bundle.
	offline := t.TempDir()
	palan(t, offline, "load", "-i", bundle, "--verify", "--verify-key", pub)

	out := palan(t, offline, "verify", ref, "--key", pub)
	if !strings.Contains(out, "Verified") {
		t.Errorf("verify from the bundle failed:\n%s", out)
	}
	if !strings.Contains(out, "local store") {
		t.Errorf("verification should have read the local store, not the registry:\n%s", out)
	}
	want := "provenance: " + sourceRepo + "@" + attestRevision
	if !strings.Contains(out, want) {
		t.Errorf("verify output = %q, want it to name the source repository and revision (%q)", out, want)
	}
}

// TestCosignReadsTheAttestationPalanWrote is the interop half: the same
// contract ADR-0007 set for signatures, applied to attestations.
func TestCosignReadsTheAttestationPalanWrote(t *testing.T) {
	cosign := requireTool(t, "cosign")
	t.Setenv("COSIGN_PASSWORD", testKeyPassword)
	host := registryHost(t)
	source, _ := hfSource(t, "org", "cosign-model",
		gguftest.TinyModel("llama", "tiny", "15M", 2048, 4, []byte("cosign-attest-weights")))
	priv, pub := writeTestKeys(t)

	ref := host + "/llm/attest-cosign:v1"

	home := t.TempDir()
	palan(t, home, "pack", source, "-t", ref)
	palan(t, home, "push", ref)
	palan(t, home, "sign", ref, "--key", priv)

	run(t, cosign, "verify-attestation", "--key", pub,
		"--type", "https://palan.dev/source/v1",
		"--insecure-ignore-tlog", "--allow-insecure-registry", ref)
}
