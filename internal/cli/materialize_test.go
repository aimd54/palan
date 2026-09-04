// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"

	"github.com/aimd54/palan/internal/registrytest"
	"github.com/aimd54/palan/internal/store"
)

// runPullOutput runs the real pull command with verification required,
// materializing into dir the way an init container does.
func runPullOutput(t *testing.T, home, ref, pubFile, dir string) (string, error) {
	t.Helper()
	t.Setenv("PALAN_HOME", home)
	v := viper.New()
	v.Set(keyRegistryPlainHTTP, true)
	v.Set(keyVerifyRequired, true)
	v.Set(keyVerifyKey, pubFile)
	cmd := newPullCmd(v)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{ref, "--output=" + dir})
	err := cmd.Execute()
	return dir, err
}

// TestMaterializeRefusesABlobThatDoesNotHashToItsManifest is the shape a
// signature cannot catch: the signature covers the manifest, the transfer
// skips a blob the store already holds, and the file written out is a copy
// leaving the content-addressed store for a directory something else reads.
// Every step reports success while the bytes handed on are not the signed
// ones.
func TestMaterializeRefusesABlobThatDoesNotHashToItsManifest(t *testing.T) {
	reg := registrytest.New(t)
	home := t.TempDir()
	ref, pubKey, layer := signedUpstreamModel(t, reg, []byte("the weights a publisher released"))
	runPullInto(t, home, ref)

	// A store that already holds the model, so the next pull writes out
	// what is here rather than fetching it again.
	st, err := store.Open(context.Background(), home)
	if err != nil {
		t.Fatal(err)
	}
	path, err := st.BlobPath(layer.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("the weights an attacker wrote!!!"), 0o600); err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(t.TempDir(), "models")
	_, err = runPullOutput(t, home, ref, pubKey, dir)
	if err == nil {
		t.Fatal("a substituted blob was written into the volume a serving container mounts")
	}
	if !strings.Contains(err.Error(), layer.Digest.String()) {
		t.Errorf("the refusal does not name the blob: %v", err)
	}
	// Positive state: the volume holds nothing. A refusal that wrote a
	// partial or wrong file and a refusal that wrote none both return an
	// error, and only the directory says which happened.
	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("the refusal left %d file(s) in the output directory", len(entries))
	}
}

// TestMaterializeWritesTheModelWhenTheBlobsAreIntact is the other half. An
// empty output directory proves nothing about the refusal above if the
// command never writes one.
func TestMaterializeWritesTheModelWhenTheBlobsAreIntact(t *testing.T) {
	reg := registrytest.New(t)
	home := t.TempDir()
	ref, pubKey, _ := signedUpstreamModel(t, reg, []byte("the weights a publisher released"))
	runPullInto(t, home, ref)

	dir := filepath.Join(t.TempDir(), "models")
	if _, err := runPullOutput(t, home, ref, pubKey, dir); err != nil {
		t.Fatalf("pull --output over intact blobs: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "model.gguf")) // #nosec G304 -- test fixture under a temp dir
	if err != nil {
		t.Fatalf("the model was not written into the output directory: %v", err)
	}
	if string(body) != "the weights a publisher released" {
		t.Fatalf("the output directory holds %q", body)
	}
}

// TestMaterializeRefusesToWriteThroughASymlink: a name already in the
// output directory that points somewhere else would otherwise be written
// through, so a pull into a directory somebody else can prepare writes the
// model wherever that link aims.
func TestMaterializeRefusesToWriteThroughASymlink(t *testing.T) {
	reg := registrytest.New(t)
	home := t.TempDir()
	ref, pubKey, _ := signedUpstreamModel(t, reg, []byte("the weights a publisher released"))

	outer := t.TempDir()
	target := filepath.Join(outer, "elsewhere")
	if err := os.WriteFile(target, []byte("a file outside the output directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(outer, "models")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "model.gguf")); err != nil {
		t.Fatal(err)
	}

	if _, err := runPullOutput(t, home, ref, pubKey, dir); err == nil {
		t.Fatal("pull wrote through a symlink in the output directory")
	}
	body, err := os.ReadFile(target) // #nosec G304 -- test fixture under a temp dir
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "a file outside the output directory" {
		t.Fatalf("the file the link aimed at was overwritten, it now holds %q", body)
	}
}
