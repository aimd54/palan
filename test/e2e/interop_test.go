// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package e2e

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/aimd54/palan/pkg/modelspec"
)

// TestOrasInterop: the G2 contract in the oras direction — a palan-packed
// artifact must be a plain, spec-compliant OCI artifact for generic tools,
// and a ModelPack artifact produced by oras must be pullable by palan.
func TestOrasInterop(t *testing.T) {
	oras, err := exec.LookPath("oras")
	if err != nil {
		t.Skip("oras not in PATH")
	}
	host := registryHost(t)
	fx := writeFixtures(t, 256<<10)
	ref := host + "/llm/interop-oras:q4"

	home := t.TempDir()
	packOut := palan(t, home, "pack", fx.ggufPath, fx.licPath, "-t", ref)
	packedDigest := firstDigest(t, packOut)
	palan(t, home, "push", ref)

	// oras must fetch the exact manifest bytes palan pushed.
	manifest := run(t, oras, "manifest", "fetch", "--plain-http", ref)
	sum := sha256.Sum256([]byte(manifest))
	if got := "sha256:" + hex.EncodeToString(sum[:]); got != packedDigest {
		t.Errorf("oras-fetched manifest digest %s, want %s", got, packedDigest)
	}
	var m struct {
		ArtifactType string `json:"artifactType"`
	}
	if err := json.Unmarshal([]byte(manifest), &m); err != nil || m.ArtifactType != modelspec.ArtifactTypeModelManifest {
		t.Errorf("artifactType via oras: %q (%v)", m.ArtifactType, err)
	}

	// Foreign producer: push a ModelPack artifact with oras, pull with palan.
	workDir := t.TempDir()
	cfg := `{"descriptor":{"name":"oras-made"},"modelfs":{"type":"layers","diffIds":[]},"config":{"format":"gguf"}}`
	if err := os.WriteFile(filepath.Join(workDir, "config.json"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "tiny.gguf"), fx.ggufBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	orasRef := host + "/llm/oras-made:v1"
	cmd := exec.Command(oras, "push", "--plain-http",
		"--artifact-type", modelspec.ArtifactTypeModelManifest,
		"--config", "config.json:"+modelspec.MediaTypeModelConfig,
		orasRef,
		"tiny.gguf:"+modelspec.MediaTypeModelWeightRaw)
	cmd.Dir = workDir
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir())
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("oras push: %v\n%s", err, out)
	}

	homeB := t.TempDir()
	palan(t, homeB, "pull", orasRef)
	var rows []struct {
		Ref  string `json:"ref"`
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal([]byte(palan(t, homeB, "ls", "--json")), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Kind != "model" {
		t.Errorf("oras-made artifact not recognized as model: %+v", rows)
	}
}

// TestModctlInterop: modctl (the ModelPack reference implementation) must
// pull and extract a palan-packed artifact intact (M2 acceptance, ADR-0005's
// compliance oracle).
func TestModctlInterop(t *testing.T) {
	modctl, err := exec.LookPath("modctl")
	if err != nil {
		t.Skip("modctl not in PATH")
	}
	host := registryHost(t)
	fx := writeFixtures(t, 256<<10)
	ref := host + "/llm/interop-modctl:q4"

	home := t.TempDir()
	palan(t, home, "pack", fx.ggufPath, fx.licPath, "-t", ref)
	palan(t, home, "push", ref)

	extractDir := t.TempDir()
	run(t, modctl, "pull", "--plain-http", "--extract-from-remote", "--extract-dir", extractDir, ref)

	got, err := os.ReadFile(filepath.Join(extractDir, "tiny.gguf"))
	if err != nil {
		t.Fatalf("modctl did not extract the weight file: %v", err)
	}
	if !bytes.Equal(got, fx.ggufBytes) {
		t.Error("modctl-extracted weights differ from the original")
	}
	if _, err := os.Stat(filepath.Join(extractDir, "LICENSE")); err != nil {
		t.Errorf("modctl did not extract the license: %v", err)
	}
}
