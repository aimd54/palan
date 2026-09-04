// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/viper"

	"github.com/aimd54/palan/internal/gguf/gguftest"
	"github.com/aimd54/palan/internal/registrytest"
	"github.com/aimd54/palan/internal/router"
	"github.com/aimd54/palan/internal/store"
)

// bogusRuntimeRef is a runtime that does not exist. Pointing run and serve
// at it turns "the gate let this through" into an observable event: the
// command gets as far as resolving a runtime and fails there by name,
// which no refusal in front of it would produce.
const bogusRuntimeRef = "llm/no-such-runtime:v1"

// seedGGUF puts a servable GGUF model on reg under repo:tag and returns its
// reference and weight layer.
func seedGGUF(t *testing.T, reg *registrytest.Registry, repo, tag string, payload []byte) (ref string, layer ocispec.Descriptor) {
	t.Helper()
	weights := gguftest.TinyModel("llama", "tiny", "15M", 2048, 15, payload)
	reg.PutBlob(repo, weights)
	layer = localLayer(weights, "model.gguf")
	seedModel(t, reg, repo, tag, []ocispec.Descriptor{layer})
	return reg.Host() + "/" + repo + ":" + tag, layer
}

// substituteTail rewrites the end of a blob in place, leaving its length and
// its GGUF header alone. The artifact stays servable and stays signed; only
// the bytes changed, which is the state re-hashing exists to find.
func substituteTail(t *testing.T, st *store.Store, d ocispec.Descriptor) {
	t.Helper()
	path, err := st.BlobPath(d.Digest)
	if err != nil {
		t.Fatalf("the weight blob is not in the store: %v", err)
	}
	body, err := os.ReadFile(path) // #nosec G304 -- test fixture under a temp dir
	if err != nil {
		t.Fatal(err)
	}
	tail := []byte("SUBSTITUTED!!!!!")
	if len(body) <= len(tail) {
		t.Fatalf("the fixture is too small to substitute into: %d bytes", len(body))
	}
	copy(body[len(body)-len(tail):], tail)
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

// runRunCmd executes the real run command against home with verification
// required, returning what it wrote to stderr alongside the error.
func runRunCmd(t *testing.T, home, ref, pubFile, runtimeRef string, rehash bool) (string, error) {
	t.Helper()
	t.Setenv("PALAN_HOME", home)
	v := viper.New()
	v.Set(keyRegistryPlainHTTP, true)
	v.Set(keyVerifyRequired, true)
	v.Set(keyVerifyKey, pubFile)
	if runtimeRef != "" {
		v.Set(keyRuntimeRef, runtimeRef)
	}
	if rehash {
		v.Set(keyVerifyRehash, true)
	}
	cmd := newRunCmd(v)
	var errOut bytes.Buffer
	cmd.SetOut(io.Discard)
	cmd.SetErr(&errOut)
	cmd.SetArgs([]string{ref})
	err := cmd.Execute()
	return errOut.String(), err
}

// TestRunRefusesAResidentCopyTheSignatureDoesNotCover is the hole a gate
// that only checks a signature leaves open. The store holds the artifact
// and not its signature, so the gate reads the registry, and the registry
// now serves a different artifact under the same tag. Both halves are
// individually fine: the registry's copy really is signed, and the host's
// copy really is what it pulled. Loading one on the strength of the other
// is what must not happen.
func TestRunRefusesAResidentCopyTheSignatureDoesNotCover(t *testing.T) {
	reg := registrytest.New(t)
	home := t.TempDir()

	// Pulled before anything was signed, so the store holds no signature.
	ref, resident := seedGGUF(t, reg, "llm/qwen3", "v1", []byte("the weights this host pulled"))
	runPullInto(t, home, ref)

	// The tag moves to a different artifact, and that one is signed.
	seedGGUF(t, reg, "llm/qwen3", "v1", []byte("the weights the tag points at now"))
	priv, privKey := attestKeypair(t)
	pubFile := attestPubKeyFile(t, priv)
	if err := runSign(t, ref, privKey); err != nil {
		t.Fatalf("signing the moved tag: %v", err)
	}

	_, err := runRunCmd(t, home, ref, pubFile, bogusRuntimeRef, false)
	if err == nil {
		t.Fatal("run loaded a resident copy on the strength of a signature over a different artifact")
	}
	if !strings.Contains(err.Error(), "not what verified") {
		t.Fatalf("the refusal does not say the resident copy is not the verified one: %v", err)
	}
	if strings.Contains(err.Error(), bogusRuntimeRef) {
		t.Fatalf("run reached runtime resolution, so it got past the content check: %v", err)
	}

	// Positive state: the copy this host holds is untouched by the refusal.
	st, err := store.Open(context.Background(), home)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.BlobPath(resident.Digest); err != nil {
		t.Fatalf("the resident weight blob is gone after a refusal: %v", err)
	}
}

// TestRunLoadsSubstitutedWeightsUntilRehashIsAskedFor shows the deferred gap
// from both sides in one fixture. Asserting only the refusal would leave it
// unclear that a signature ever accepted these bytes.
func TestRunLoadsSubstitutedWeightsUntilRehashIsAskedFor(t *testing.T) {
	reg := registrytest.New(t)
	home := t.TempDir()
	ref, layer := seedGGUF(t, reg, "llm/qwen3", "v1", []byte("the weights a publisher released"))
	priv, privKey := attestKeypair(t)
	pubFile := attestPubKeyFile(t, priv)
	if err := runSign(t, ref, privKey); err != nil {
		t.Fatalf("signing the fixture: %v", err)
	}
	runPullInto(t, home, ref)

	st, err := store.Open(context.Background(), home)
	if err != nil {
		t.Fatal(err)
	}
	substituteTail(t, st, layer)

	// The manifest is untouched, so the signature verifies and run gets all
	// the way to the runtime it cannot find.
	_, err = runRunCmd(t, home, ref, pubFile, bogusRuntimeRef, false)
	if err == nil || !strings.Contains(err.Error(), bogusRuntimeRef) {
		t.Fatalf("the signature must still admit substituted weights, or this test is not about the gap: %v", err)
	}

	_, err = runRunCmd(t, home, ref, pubFile, bogusRuntimeRef, true)
	if err == nil {
		t.Fatal("re-hashing accepted substituted weights")
	}
	if !strings.Contains(err.Error(), layer.Digest.String()) {
		t.Fatalf("the refusal does not name the blob that changed: %v", err)
	}
	if strings.Contains(err.Error(), bogusRuntimeRef) {
		t.Fatalf("run reached runtime resolution despite substituted weights: %v", err)
	}
}

// TestServeRefusesSubstitutedWeightsAsUnverifiedRatherThanMissing goes
// through the backend the router actually calls, because the distinction
// between refused and missing is what decides whether a client sees 403 or
// 404 (ADR-0008).
func TestServeRefusesSubstitutedWeightsAsUnverifiedRatherThanMissing(t *testing.T) {
	reg := registrytest.New(t)
	home := t.TempDir()
	ref, layer := seedGGUF(t, reg, "llm/qwen3", "v1", []byte("the weights a publisher released"))
	priv, privKey := attestKeypair(t)
	pubFile := attestPubKeyFile(t, priv)
	if err := runSign(t, ref, privKey); err != nil {
		t.Fatalf("signing the fixture: %v", err)
	}
	runPullInto(t, home, ref)

	ctx := context.Background()
	st, err := store.Open(ctx, home)
	if err != nil {
		t.Fatal(err)
	}
	substituteTail(t, st, layer)

	v := viper.New()
	v.Set(keyRegistryPlainHTTP, true)
	v.Set(keyVerifyRequired, true)
	v.Set(keyVerifyKey, pubFile)

	// Without re-hashing the model loads: the spec names the blob the
	// runtime would mmap, which is the substituted file.
	loading := &storeBackend{st: st, bin: "irrelevant-to-this-test", logDir: t.TempDir(),
		gate: verifyGate(v, st, false, "")}
	spec, _, err := loading.Spec(ctx, ref)
	if err != nil {
		t.Fatalf("the signature must still admit substituted weights: %v", err)
	}
	if spec.ModelPath == "" {
		t.Fatal("the backend returned a spec with no model path")
	}

	refusing := &storeBackend{st: st, bin: "irrelevant-to-this-test", logDir: t.TempDir(),
		gate: verifyGate(v, st, false, ""), rehash: true}
	_, _, err = refusing.Spec(ctx, ref)
	if err == nil {
		t.Fatal("the backend loaded substituted weights with re-hashing on")
	}
	if !errors.Is(err, router.ErrUnverified) {
		t.Fatalf("a substituted blob must read as refused rather than missing, got: %v", err)
	}
	if !strings.Contains(err.Error(), layer.Digest.String()) {
		t.Fatalf("the refusal does not name the blob that changed: %v", err)
	}

	// Re-reading asked for on its own, with no signature check beside it.
	// serve reaches this through a different branch from run's, so it gets
	// its own assertion rather than inheriting run's.
	rehashOnly := &storeBackend{st: st, bin: "irrelevant-to-this-test", logDir: t.TempDir(), rehash: true}
	if _, _, err := rehashOnly.Spec(ctx, ref); err == nil {
		t.Fatal("re-reading on its own loaded substituted weights")
	} else if !strings.Contains(err.Error(), layer.Digest.String()) {
		t.Fatalf("the refusal does not name the blob that changed: %v", err)
	}
}

// runRunUnverified runs the real run command with no signature check
// configured at all, so a re-read asked for on its own is the only thing
// standing between the store and the runtime.
func runRunUnverified(t *testing.T, home, ref string, rehash bool) (string, error) {
	t.Helper()
	t.Setenv("PALAN_HOME", home)
	v := viper.New()
	v.Set(keyRegistryPlainHTTP, true)
	v.Set(keyRuntimeRef, bogusRuntimeRef)
	if rehash {
		v.Set(keyVerifyRehash, true)
	}
	cmd := newRunCmd(v)
	var errOut bytes.Buffer
	cmd.SetOut(io.Discard)
	cmd.SetErr(&errOut)
	cmd.SetArgs([]string{ref})
	err := cmd.Execute()
	return errOut.String(), err
}

// TestRehashRunsWhenAskedForOnItsOwn: re-reading the blobs and checking a
// signature are separate questions, and a host may reasonably ask for the
// first without configuring the second. Answering neither because only one
// was configured is how a requested check becomes silence: the command
// would exit 0 having read nothing and said nothing.
func TestRehashRunsWhenAskedForOnItsOwn(t *testing.T) {
	reg := registrytest.New(t)
	home := t.TempDir()
	ref, layer := seedGGUF(t, reg, "llm/qwen3", "v1", []byte("the weights a publisher released"))
	runPullInto(t, home, ref)

	st, err := store.Open(context.Background(), home)
	if err != nil {
		t.Fatal(err)
	}
	substituteTail(t, st, layer)

	// Nothing configured: run reaches the runtime it cannot find, which is
	// what makes the other half of this test meaningful.
	_, err = runRunUnverified(t, home, ref, false)
	if err == nil || !strings.Contains(err.Error(), bogusRuntimeRef) {
		t.Fatalf("with nothing configured run should have reached runtime resolution: %v", err)
	}

	_, err = runRunUnverified(t, home, ref, true)
	if err == nil {
		t.Fatal("verify.rehash on its own read nothing back")
	}
	if !strings.Contains(err.Error(), layer.Digest.String()) {
		t.Fatalf("the refusal does not name the blob that changed: %v", err)
	}
	if strings.Contains(err.Error(), bogusRuntimeRef) {
		t.Fatalf("run reached runtime resolution over a substituted blob: %v", err)
	}
}

// residentCopyDiffersFromSignedTag leaves the store holding an artifact
// whose weight layer is not a GGUF, under a tag the registry now serves a
// signed GGUF for. Reading the resident copy's bytes fails, so the error
// says which check ran first.
func residentCopyDiffersFromSignedTag(t *testing.T) (home, ref, pubFile string) {
	t.Helper()
	reg := registrytest.New(t)
	home = t.TempDir()
	ref = reg.Host() + "/llm/qwen3:v1"

	notAModel := []byte("bytes that are not a gguf file at all")
	reg.PutBlob("llm/qwen3", notAModel)
	seedModel(t, reg, "llm/qwen3", "v1", []ocispec.Descriptor{localLayer(notAModel, "model.gguf")})
	runPullInto(t, home, ref)

	seedGGUF(t, reg, "llm/qwen3", "v1", []byte("the weights the tag points at now"))
	priv, privKey := attestKeypair(t)
	pubFile = attestPubKeyFile(t, priv)
	if err := runSign(t, ref, privKey); err != nil {
		t.Fatalf("signing the moved tag: %v", err)
	}
	return home, ref, pubFile
}

// TestTheResidentCopyIsCheckedBeforeItsBytesAreParsed pins an ordering the
// code comments call the point rather than a detail. Deciding whether an
// artifact is servable means reading its weight header, so a check placed
// after that reports a parse failure over content that should never have
// been opened, and the operator is sent after the wrong problem.
func TestTheResidentCopyIsCheckedBeforeItsBytesAreParsed(t *testing.T) {
	home, ref, pubFile := residentCopyDiffersFromSignedTag(t)

	_, err := runRunCmd(t, home, ref, pubFile, bogusRuntimeRef, false)
	if err == nil {
		t.Fatal("run loaded a resident copy the signature does not cover")
	}
	if !strings.Contains(err.Error(), "not what verified") {
		t.Fatalf("the refusal is not the content check: %v", err)
	}
	// "magic" is requireGGUF's word for a weight header it could not read.
	// Seeing it here means the artifact's own bytes were parsed first.
	if strings.Contains(err.Error(), "magic") {
		t.Fatalf("the resident copy was parsed before it was checked: %v", err)
	}
}

// TestServeRefusesAResidentCopyTheSignatureDoesNotCover is the same
// ordering and the same refusal through the backend the router calls, where
// the answer has to be 403 rather than 404.
func TestServeRefusesAResidentCopyTheSignatureDoesNotCover(t *testing.T) {
	home, ref, pubFile := residentCopyDiffersFromSignedTag(t)
	ctx := context.Background()
	st, err := store.Open(ctx, home)
	if err != nil {
		t.Fatal(err)
	}
	v := viper.New()
	v.Set(keyRegistryPlainHTTP, true)
	v.Set(keyVerifyRequired, true)
	v.Set(keyVerifyKey, pubFile)

	b := &storeBackend{st: st, bin: "irrelevant-to-this-test", logDir: t.TempDir(),
		gate: verifyGate(v, st, false, "")}
	if _, _, err := b.Spec(ctx, ref); err == nil {
		t.Fatal("the backend loaded a resident copy the signature does not cover")
	} else {
		if !errors.Is(err, router.ErrUnverified) {
			t.Fatalf("a resident copy that is not the verified one must read as refused, got: %v", err)
		}
		if !strings.Contains(err.Error(), "not what verified") {
			t.Fatalf("the refusal is not the content check: %v", err)
		}
		if strings.Contains(err.Error(), "magic") {
			t.Fatalf("the resident copy was parsed before it was checked: %v", err)
		}
	}
}
