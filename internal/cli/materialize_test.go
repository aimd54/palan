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

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
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

// TestMaterializeTakesBackWhatItWroteWhenALaterLayerFails: a model can be
// many files, and the directory is what something else reads. Files left
// from a refused pull are a partial model that looks like a whole one to
// whatever mounts the volume next.
func TestMaterializeTakesBackWhatItWroteWhenALaterLayerFails(t *testing.T) {
	reg := registrytest.New(t)
	home := t.TempDir()

	first := []byte("shard one of the weights")
	second := []byte("shard two of the weights")
	reg.PutBlob("llm/sharded", first)
	reg.PutBlob("llm/sharded", second)
	seedModel(t, reg, "llm/sharded", "v1", []ocispec.Descriptor{
		localLayer(first, "model-00001-of-00002.safetensors"),
		localLayer(second, "model-00002-of-00002.safetensors"),
	})
	ref := reg.Host() + "/llm/sharded:v1"
	priv, privKey := attestKeypair(t)
	pubKey := attestPubKeyFile(t, priv)
	if err := runSign(t, ref, privKey); err != nil {
		t.Fatalf("signing the fixture: %v", err)
	}
	runPullInto(t, home, ref)

	// Only the second shard is substituted, so the first is written and
	// then has to be taken back.
	st, err := store.Open(context.Background(), home)
	if err != nil {
		t.Fatal(err)
	}
	path, err := st.BlobPath(digest.FromBytes(second))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("shard two an attacker wrote"), 0o600); err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(t.TempDir(), "models")
	if _, err := runPullOutput(t, home, ref, pubKey, dir); err == nil {
		t.Fatal("a substituted shard was written into the output directory")
	}
	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("the refusal left a partial model behind: %v", names)
	}
}

// seedNestedModel puts a signed model on reg whose layer claims a nested
// file name. palan's own pack flattens names, but materialize supports
// nested ones deliberately, for ModelPack artifacts built elsewhere.
func seedNestedModel(t *testing.T, reg *registrytest.Registry, name string, body []byte) (ref, pubKey string) {
	t.Helper()
	reg.PutBlob("llm/nested", body)
	seedModel(t, reg, "llm/nested", "v1", []ocispec.Descriptor{localLayer(body, name)})
	priv, privKey := attestKeypair(t)
	pubKey = attestPubKeyFile(t, priv)
	ref = reg.Host() + "/llm/nested:v1"
	if err := runSign(t, ref, privKey); err != nil {
		t.Fatalf("signing the fixture: %v", err)
	}
	return ref, pubKey
}

// TestMaterializeRefusesToWriteThroughASymlinkedDirectory: guarding the
// last path component does not establish that the write lands inside the
// output directory. Path joining cleans a nested name so the result looks
// contained, while an intermediate component can still be a link pointing
// anywhere, and creating the chain follows it.
func TestMaterializeRefusesToWriteThroughASymlinkedDirectory(t *testing.T) {
	reg := registrytest.New(t)
	ref, pubKey := seedNestedModel(t, reg, "sub/model.gguf", []byte("weights that must stay inside the volume"))

	outer := t.TempDir()
	outside := filepath.Join(outer, "outside")
	if err := os.MkdirAll(outside, 0o750); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(outer, "models")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "sub")); err != nil {
		t.Fatal(err)
	}

	if _, err := runPullOutput(t, t.TempDir(), ref, pubKey, dir); err == nil {
		t.Fatal("pull wrote through a symlinked directory in the output directory")
	}
	// Positive state: nothing landed on the far side of the link.
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("the write escaped the output directory: %v", entries[0].Name())
	}
}

// TestMaterializeDoesNotOverwriteAFileTheLinkAimsAt is the sharper half:
// the escape overwrites rather than merely creating, so an existing file
// outside the output directory is replaced with attacker-chosen bytes that
// carry a signature the policy accepts.
func TestMaterializeDoesNotOverwriteAFileTheLinkAimsAt(t *testing.T) {
	reg := registrytest.New(t)
	ref, pubKey := seedNestedModel(t, reg, "sub/keep.txt", []byte("bytes chosen by whoever built the artifact"))

	outer := t.TempDir()
	victimDir := filepath.Join(outer, "victim")
	if err := os.MkdirAll(victimDir, 0o750); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(victimDir, "keep.txt")
	const original = "a file that has nothing to do with this pull"
	if err := os.WriteFile(victim, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(outer, "models")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victimDir, filepath.Join(dir, "sub")); err != nil {
		t.Fatal(err)
	}

	if _, err := runPullOutput(t, t.TempDir(), ref, pubKey, dir); err == nil {
		t.Fatal("pull wrote through a symlinked directory")
	}
	body, err := os.ReadFile(victim) // #nosec G304 -- test fixture under a temp dir
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != original {
		t.Fatalf("a file outside the output directory was overwritten, it now holds %q", body)
	}
}

// TestMaterializeWritesANestedNameWhenNothingIsLinked keeps the refusals
// above honest: nested names are supported, so the guard must refuse the
// link rather than the nesting.
func TestMaterializeWritesANestedNameWhenNothingIsLinked(t *testing.T) {
	reg := registrytest.New(t)
	body := []byte("weights under a nested name")
	ref, pubKey := seedNestedModel(t, reg, "sub/model.gguf", body)

	dir := filepath.Join(t.TempDir(), "models")
	if _, err := runPullOutput(t, t.TempDir(), ref, pubKey, dir); err != nil {
		t.Fatalf("a nested layer name that escapes nothing must materialize: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "sub", "model.gguf")) // #nosec G304 -- test fixture under a temp dir
	if err != nil {
		t.Fatalf("the nested file was not written: %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("the nested file holds %q", got)
	}
}

func TestMaterializeRefusesTwoLayersClaimingOneFileName(t *testing.T) {
	reg := registrytest.New(t)
	first := []byte("the layer that would be written first")
	second := []byte("the layer that would overwrite it")
	reg.PutBlob("llm/clash", first)
	reg.PutBlob("llm/clash", second)
	seedModel(t, reg, "llm/clash", "v1", []ocispec.Descriptor{
		localLayer(first, "model.gguf"),
		localLayer(second, "model.gguf"),
	})
	ref := reg.Host() + "/llm/clash:v1"
	priv, privKey := attestKeypair(t)
	pubKey := attestPubKeyFile(t, priv)
	if err := runSign(t, ref, privKey); err != nil {
		t.Fatalf("signing the fixture: %v", err)
	}

	dir := filepath.Join(t.TempDir(), "models")
	if _, err := runPullOutput(t, t.TempDir(), ref, pubKey, dir); err == nil {
		t.Fatal("two layers claiming one name were materialized, so one silently replaced the other")
	} else if !strings.Contains(err.Error(), "model.gguf") {
		t.Errorf("the refusal does not name the file both layers claim: %v", err)
	}
}

// TestMaterializeRefusesAWeightLayerWithNoFileName: a layer with no file
// name has nowhere to go, and skipping it quietly is right for a small one
// and wrong for the weights. The command would otherwise report success
// over a directory holding everything except the model.
func TestMaterializeRefusesAWeightLayerWithNoFileName(t *testing.T) {
	reg := registrytest.New(t)
	weights := []byte("weights whose layer records no file name")
	extra := []byte("a small file beside them")
	reg.PutBlob("llm/nameless", weights)
	reg.PutBlob("llm/nameless", extra)
	nameless := localLayer(weights, "model.gguf")
	nameless.Annotations = nil
	seedModel(t, reg, "llm/nameless", "v1", []ocispec.Descriptor{nameless, localLayer(extra, "tokenizer.json")})
	ref := reg.Host() + "/llm/nameless:v1"
	priv, privKey := attestKeypair(t)
	pubKey := attestPubKeyFile(t, priv)
	if err := runSign(t, ref, privKey); err != nil {
		t.Fatalf("signing the fixture: %v", err)
	}

	dir := filepath.Join(t.TempDir(), "models")
	if _, err := runPullOutput(t, t.TempDir(), ref, pubKey, dir); err == nil {
		t.Fatal("a model whose weight layer has no file name was reported as materialized")
	}
	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("the refusal left %d file(s) behind, so a serving container would find a partial model", len(entries))
	}
}

// TestMaterializeRefusesALinkThatStaysInsideTheOutputDirectory: the root
// refuses a name resolving outside the directory, and resolves the path
// itself, so a caller's O_NOFOLLOW does nothing. A link that stays inside
// is followed, and the write lands on whatever it names.
func TestMaterializeRefusesALinkThatStaysInsideTheOutputDirectory(t *testing.T) {
	reg := registrytest.New(t)
	ref, pubKey, _ := signedUpstreamModel(t, reg, []byte("weights that belong in model.gguf"))

	dir := filepath.Join(t.TempDir(), "models")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	const other = "somewhere-else.bin"
	target := filepath.Join(dir, other)
	if err := os.WriteFile(target, []byte("a file already in the directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, filepath.Join(dir, "model.gguf")); err != nil {
		t.Fatal(err)
	}

	if _, err := runPullOutput(t, t.TempDir(), ref, pubKey, dir); err == nil {
		t.Fatal("the write followed a link inside the output directory")
	}
	body, err := os.ReadFile(target) // #nosec G304 -- test fixture under a temp dir
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "a file already in the directory" {
		t.Fatalf("the write landed on the file the link named, which now holds %q", body)
	}
}

// TestMaterializeTakesBackDirectoriesItCreated: the gate pattern is sold on
// a refusal writing nothing into the volume a serving container mounts, and
// a directory left behind is something.
func TestMaterializeTakesBackDirectoriesItCreated(t *testing.T) {
	reg := registrytest.New(t)
	body := []byte("weights under a nested name")
	ref, pubKey := seedNestedModel(t, reg, "sub/deeper/model.gguf", body)

	home := t.TempDir()
	runPullInto(t, home, ref)
	st, err := store.Open(context.Background(), home)
	if err != nil {
		t.Fatal(err)
	}
	path, err := st.BlobPath(digest.FromBytes(body))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("weights an attacker put there!!"), 0o600); err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(t.TempDir(), "models")
	if _, err := runPullOutput(t, home, ref, pubKey, dir); err == nil {
		t.Fatal("a substituted blob was materialized")
	}
	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("the refusal left %s behind in the output directory", entries[0].Name())
	}
}

// TestMaterializeKeepsADirectoryItDidNotCreate is the other half: the
// rollback must take back what this run made and nothing else.
func TestMaterializeKeepsADirectoryItDidNotCreate(t *testing.T) {
	reg := registrytest.New(t)
	body := []byte("weights under a nested name")
	ref, pubKey := seedNestedModel(t, reg, "sub/model.gguf", body)

	home := t.TempDir()
	runPullInto(t, home, ref)
	st, err := store.Open(context.Background(), home)
	if err != nil {
		t.Fatal(err)
	}
	path, err := st.BlobPath(digest.FromBytes(body))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("weights an attacker put there!!"), 0o600); err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(t.TempDir(), "models")
	// The operator's own directory, present before the pull ran.
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := runPullOutput(t, home, ref, pubKey, dir); err == nil {
		t.Fatal("a substituted blob was materialized")
	}
	if _, err := os.Stat(filepath.Join(dir, "sub")); err != nil {
		t.Fatalf("the rollback removed a directory it did not create: %v", err)
	}
}
