//go:build e2e

// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
)

// hfProbe is a genuinely small GGUF, so the opt-in test costs about a
// megabyte rather than several gigabytes.
const (
	hfRepo = "ggml-org/tiny-llamas"
	hfFile = "stories260K.gguf"
)

// TestPackFromHuggingFace exercises the real API and CDN. It is opt-in
// because CI should not depend on a third party's availability or rate
// limits: run with PALAN_E2E_HF=1.
func TestPackFromHuggingFace(t *testing.T) {
	if os.Getenv("PALAN_E2E_HF") == "" {
		t.Skip("set PALAN_E2E_HF=1 to exercise the live Hugging Face API")
	}
	host := registryHost(t)
	ref := host + "/llm/tiny-llamas:260k"

	home := t.TempDir()
	out := palan(t, home, "pack", "hf://"+hfRepo+"/"+hfFile, "-t", ref, "--push")
	if !strings.Contains(out, "Fetching "+hfFile) {
		t.Errorf("the fetch should be reported:\n%s", out)
	}

	described := palan(t, home, "describe", ref)
	// Provenance has to point at the repository the bytes came from.
	if !strings.Contains(described, "https://huggingface.co/"+hfRepo) {
		t.Errorf("source annotation missing:\n%s", described)
	}

	// The recorded upstream digest must be the one the repository publishes,
	// not something palan derived on its own.
	want := "sha256:" + upstreamDigest(t)
	if !strings.Contains(described, want) {
		t.Errorf("origin digest should be %s:\n%s", want, described)
	}
}

// upstreamDigest asks Hugging Face what the file's SHA-256 is.
func upstreamDigest(t *testing.T) string {
	t.Helper()
	body := strings.NewReader(`{"paths":["` + hfFile + `"]}`)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		"https://huggingface.co/api/models/"+hfRepo+"/paths-info/main", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var infos []struct {
		LFS struct {
			OID string `json:"oid"`
		} `json:"lfs"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&infos); err != nil || len(infos) == 0 {
		t.Fatalf("paths-info: %v", err)
	}
	return infos[0].LFS.OID
}

// TestPackFromHuggingFaceRejectsBareRepo needs no network beyond the API
// listing, and covers the case someone hits first: naming a repository
// without saying which quantisation.
func TestPackFromHuggingFaceRejectsBareRepo(t *testing.T) {
	if os.Getenv("PALAN_E2E_HF") == "" {
		t.Skip("set PALAN_E2E_HF=1 to exercise the live Hugging Face API")
	}
	host := registryHost(t)
	out, err := palanRun(t.TempDir(), "pack", "hf://"+hfRepo, "-t", host+"/llm/x:1")
	if err == nil {
		t.Errorf("a bare repository must not be guessed at:\n%s", out)
	}
	if !strings.Contains(out, hfFile) {
		t.Errorf("the error should list what the repository publishes:\n%s", out)
	}
}
