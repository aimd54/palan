// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry"

	"github.com/aimd54/palan/internal/registrytest"
	"github.com/aimd54/palan/internal/signing"
	"github.com/aimd54/palan/internal/store"
)

// holdWithoutSignature takes the store at home exclusively and leaves it as a
// pull does between tagging a model and fetching its signature, the index
// half saved. finish puts the signature back, saves the index and releases.
func holdWithoutSignature(t *testing.T, home, ref string) (finish func()) {
	t.Helper()
	ctx := context.Background()
	writer, err := store.Open(ctx, home)
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := writer.Lock(ctx)
	if err != nil {
		t.Fatal(err)
	}
	model, err := writer.Resolve(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := registry.ParseReference(ref)
	if err != nil {
		t.Fatal(err)
	}
	sigRef := signing.SigRef(parsed, model.Digest)
	sig, err := writer.Resolve(ctx, sigRef)
	if err != nil {
		t.Fatalf("the fixture holds no signature to take away: %v", err)
	}
	raw, err := content.FetchAll(ctx, writer.OCI(), sig)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.OCI().Delete(ctx, sig); err != nil {
		t.Fatal(err)
	}
	// And the index halfway through the save that follows.
	index := filepath.Join(home, "index.json")
	whole, err := os.ReadFile(index) // #nosec G304 -- the fixture's own store
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(index, whole[:len(whole)/2], 0o600); err != nil {
		t.Fatal(err)
	}
	return func() {
		if err := writer.OCI().Push(ctx, sig, bytes.NewReader(raw)); err != nil {
			t.Error(err)
		}
		if err := writer.Tag(ctx, sig, sigRef); err != nil {
			t.Error(err)
		}
		unlock()
	}
}

// TestRunWaitsForASignatureStillArriving: a pull tags a model before it
// fetches its signature, so run reads under a shared lock and waits for the
// pull rather than refusing, offline, a model about to verify.
func TestRunWaitsForASignatureStillArriving(t *testing.T) {
	reg := registrytest.New(t)
	home := t.TempDir()
	ref, _ := seedGGUF(t, reg, "llm/qwen3", "v1", []byte("weights arriving with their signature"))
	priv, privKey := attestKeypair(t)
	pubFile := attestPubKeyFile(t, priv)
	if err := runSign(t, ref, privKey); err != nil {
		t.Fatalf("signing the fixture: %v", err)
	}
	runPullInto(t, home, ref)
	// Nothing to fall back on from here, so only the store can answer.
	reg.Close()

	finish := holdWithoutSignature(t, home, ref)
	var stderr syncBuffer
	done := make(chan error, 1)
	go func() { done <- runRunCmdTo(t, home, ref, pubFile, bogusRuntimeRef, false, &stderr) }()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(stderr.String(), "Waiting for another palan process") {
		select {
		case err := <-done:
			finish()
			t.Fatalf("run finished while a pull held the store: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			finish()
			t.Fatalf("run neither waited nor said so: %q", stderr.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	finish()

	select {
	case err := <-done:
		// The signature verified from the store, so run got as far as
		// looking its runtime up.
		if err == nil || !strings.Contains(err.Error(), bogusRuntimeRef) {
			t.Fatalf("run did not get past the gate once the pull had finished: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not proceed once the store was released")
	}
}

// TestRunAnnouncesItsWaitToPull: a model that is not here is fetched under
// the exclusive lock, which waits for every reader, a push among them.
func TestRunAnnouncesItsWaitToPull(t *testing.T) {
	ctx := context.Background()
	reg := registrytest.New(t)
	home := t.TempDir()
	ref, _ := seedGGUF(t, reg, "llm/qwen3", "v1", []byte("weights fetched once the store is free"))
	priv, privKey := attestKeypair(t)
	pubFile := attestPubKeyFile(t, priv)
	if err := runSign(t, ref, privKey); err != nil {
		t.Fatalf("signing the fixture: %v", err)
	}
	_, release, err := store.OpenShared(ctx, home)
	if err != nil {
		t.Fatal(err)
	}

	var stderr syncBuffer
	done := make(chan error, 1)
	go func() { done <- runRunCmdTo(t, home, ref, pubFile, bogusRuntimeRef, false, &stderr) }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		out := stderr.String()
		pulling := strings.Index(out, "pulling")
		if pulling >= 0 && strings.Contains(out[pulling:], waitingForStore) {
			break
		}
		select {
		case err := <-done:
			release()
			t.Fatalf("run finished while another process read the store: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			release()
			t.Fatalf("run did not say it was waiting to pull: %q", out)
		}
		time.Sleep(20 * time.Millisecond)
	}
	release()

	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), bogusRuntimeRef) {
			t.Fatalf("run did not get past the pull once the store was free: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not proceed once the store was released")
	}
}

// TestRunRefusesATagMovedAfterItsPull: the store is let go between the fetch
// and the reads after it, so what those reads find is held to the digest the
// signature was checked against.
func TestRunRefusesATagMovedAfterItsPull(t *testing.T) {
	ctx := context.Background()
	reg := registrytest.New(t)
	home := t.TempDir()
	ref, _ := seedGGUF(t, reg, "llm/qwen3", "v1", []byte("the weights that verified"))
	other, _ := seedGGUF(t, reg, "llm/other", "v1", []byte("weights nothing signed"))
	priv, privKey := attestKeypair(t)
	pubFile := attestPubKeyFile(t, priv)
	if err := runSign(t, ref, privKey); err != nil {
		t.Fatalf("signing the fixture: %v", err)
	}
	runPullInto(t, home, other)

	afterPull = func() {
		st, err := store.Open(ctx, home)
		if err != nil {
			t.Error(err)
			return
		}
		unlock, err := st.Lock(ctx)
		if err != nil {
			t.Error(err)
			return
		}
		defer unlock()
		desc, err := st.Resolve(ctx, other)
		if err == nil {
			err = st.Tag(ctx, desc, ref)
		}
		if err != nil {
			t.Error(err)
		}
	}
	defer func() { afterPull = nil }()

	err := runRunCmdTo(t, home, ref, pubFile, bogusRuntimeRef, false, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "not what verified") {
		t.Fatalf("run after its tag moved to unsigned weights: %v, want it refused", err)
	}
}

// TestRunPickerWaitsForAWriter: run with no reference lists the store to
// choose from, and that list is read under the lock like everything else.
func TestRunPickerWaitsForAWriter(t *testing.T) {
	ctx := context.Background()
	home := t.TempDir()
	first, second := twoServedModels(t, home)
	t.Setenv("PALAN_HOME", home)

	finish := holdMidSave(t, home)
	type listed struct {
		n   int
		err error
	}
	got := make(chan listed, 1)
	var stderr syncBuffer
	go func() {
		items, err := storeItems(ctx, &stderr)
		got <- listed{len(items), err}
	}()
	select {
	case l := <-got:
		finish()
		t.Fatalf("the picker read the store while another process held it (%d items, %v)", l.n, l.err)
	case <-time.After(time.Second):
	}
	if !strings.Contains(stderr.String(), waitingForStore) {
		finish()
		t.Fatalf("the picker waited without saying so: %q", stderr.String())
	}
	finish()
	select {
	case l := <-got:
		if l.err != nil || l.n != 2 {
			t.Fatalf("the picker once the store was free: %d items, %v; want %s and %s", l.n, l.err, first, second)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the picker did not read the store once it was released")
	}
}
