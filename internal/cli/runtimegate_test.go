// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"io"
	"strings"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/viper"

	"github.com/aimd54/palan/internal/registrytest"
	"github.com/aimd54/palan/internal/store"
)

// residentModelAndRuntime seeds a signed model and a runtime artifact on the
// same registry, signs the runtime only when asked, and pulls both into one
// store, which is the state a host is in when it is about to serve.
func residentModelAndRuntime(t *testing.T, signRuntime bool) (home, modelRef, runtimeRef, pubFile string) {
	t.Helper()
	reg := registrytest.New(t)
	home = t.TempDir()

	modelRef, _ = seedGGUF(t, reg, "llm/qwen3", "v1", []byte("the weights a publisher released"))
	priv, privKey := attestKeypair(t)
	pubFile = attestPubKeyFile(t, priv)
	if err := runSign(t, modelRef, privKey); err != nil {
		t.Fatalf("signing the model: %v", err)
	}
	runPullInto(t, home, modelRef)

	engine := []byte("an llama-server build")
	reg.PutBlob("runtimes/llama-server", engine)
	seedModel(t, reg, "runtimes/llama-server", "b1", []ocispec.Descriptor{localLayer(engine, "llama-server")})
	runtimeRef = reg.Host() + "/runtimes/llama-server:b1"
	if signRuntime {
		if err := runSign(t, runtimeRef, privKey); err != nil {
			t.Fatalf("signing the runtime: %v", err)
		}
	}
	runPullInto(t, home, runtimeRef)
	return home, modelRef, runtimeRef, pubFile
}

// TestRunRefusesAnUnsignedRuntimeBuild: a host that checks its weights and
// not the engine that reads them has checked the smaller half.
func TestRunRefusesAnUnsignedRuntimeBuild(t *testing.T) {
	home, modelRef, runtimeRef, pubFile := residentModelAndRuntime(t, false)

	_, err := runRunCmd(t, home, modelRef, pubFile, runtimeRef, false)
	if err == nil {
		t.Fatal("run spawned an unsigned runtime under a policy that requires verification")
	}
	if !strings.Contains(err.Error(), runtimeRef) {
		t.Fatalf("the refusal does not name the runtime it refused: %v", err)
	}
	if !strings.Contains(err.Error(), "FAILED") {
		t.Fatalf("the refusal does not read as a verification failure: %v", err)
	}
}

// TestRunAcceptsASignedRuntimeBuild is the other side of the same fixture.
// Without it, a gate that refused every runtime would pass the test above.
// The runtime here is a plain artifact rather than a real engine, so run
// gets past verification and fails unpacking it, which is exactly the
// evidence wanted: the check let it through.
func TestRunAcceptsASignedRuntimeBuild(t *testing.T) {
	home, modelRef, runtimeRef, pubFile := residentModelAndRuntime(t, true)

	_, err := runRunCmd(t, home, modelRef, pubFile, runtimeRef, false)
	if err == nil {
		t.Fatal("the fixture is not a real engine, so run cannot have started it")
	}
	// Asserted on what the error is rather than on what it is not: run has
	// to get past verification and fail unpacking a model-shaped artifact
	// that was never a runtime. A differently worded refusal would satisfy
	// a check for the absence of "FAILED".
	if !strings.Contains(err.Error(), "not a runtime artifact") {
		t.Fatalf("run did not reach unpacking, so the signed runtime was refused somewhere earlier: %v", err)
	}
}

// TestRunSaysWhenTheEngineCameFromPath: with no runtime artifact configured,
// llama-server is whatever the host installed, and palan has nothing to hold
// it to. Saying nothing would read the same as a runtime that was checked.
func TestRunSaysWhenTheEngineCameFromPath(t *testing.T) {
	home, modelRef, _, pubFile := residentModelAndRuntime(t, false)

	// An empty PATH, so the fallback is the same on every machine: this
	// test is about what run says, not about whether a real llama-server
	// happens to be installed where it runs.
	t.Setenv("PATH", t.TempDir())

	errOut, err := runRunCmd(t, home, modelRef, pubFile, "", false)
	// Phrases unique to the notice. Runtime resolution then fails on the
	// empty PATH with a message that mentions both PATH and runtime.ref, so
	// asserting on either of those alone would pass with the notice gone.
	if !strings.Contains(errOut, "cannot say where that build came from") {
		t.Fatalf("run said nothing about the engine being unchecked (error was %v); it wrote:\n%s", err, errOut)
	}
	if !strings.Contains(errOut, "Set runtime.ref to a signed runtime artifact") {
		t.Errorf("the notice does not say what would close it; it wrote:\n%s", errOut)
	}
}

// TestRuntimePullRefusesAnUnsignedBuildBeforeAnyByteMoves checks the store
// rather than the error: a pull that refuses after writing blobs and one
// that refuses before writing any both return non-nil.
func TestRuntimePullRefusesAnUnsignedBuildBeforeAnyByteMoves(t *testing.T) {
	reg := registrytest.New(t)
	engine := []byte("an llama-server build nothing has signed")
	reg.PutBlob("runtimes/llama-server", engine)
	layer := localLayer(engine, "llama-server")
	seedModel(t, reg, "runtimes/llama-server", "b1", []ocispec.Descriptor{layer})
	ref := reg.Host() + "/runtimes/llama-server:b1"
	priv, _ := attestKeypair(t)
	pubFile := attestPubKeyFile(t, priv)

	home := t.TempDir()
	t.Setenv("PALAN_HOME", home)
	v := viper.New()
	v.Set(keyRegistryPlainHTTP, true)
	v.Set(keyVerifyRequired, true)
	v.Set(keyVerifyKey, pubFile)
	cmd := newRuntimeCmd(v)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"pull", ref})
	if err := cmd.Execute(); err == nil {
		t.Fatal("runtime pull fetched an unsigned engine build under verify.required")
	}

	st, err := store.Open(context.Background(), home)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.BlobPath(layer.Digest); err == nil {
		t.Fatal("the store holds the engine blob after a refusal")
	}
}
