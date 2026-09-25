// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package runtime

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/gofrs/flock"

	"github.com/aimd54/palan/internal/store"
)

// TestEnsureHoldsTheUnpackLockWhileItUnpacks: the lock has to cover the copy
// and the rename, not only the moment it is taken. A blob replaced by a named
// pipe holds Ensure inside the copy until the test writes the bytes.
func TestEnsureHoldsTheUnpackLockWhileItUnpacks(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	ref := packRuntime(t, st)
	desc, err := st.Resolve(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := store.FetchManifest(ctx, st.OCI(), desc)
	if err != nil {
		t.Fatal(err)
	}
	layer := manifest.Layers[len(manifest.Layers)-1]
	blob, err := st.BlobPath(layer.Digest)
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(blob) // #nosec G304 -- test fixture under a temp dir
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(blob); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(blob, 0o600); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := Ensure(ctx, st, ref, desc)
		done <- err
	}()
	// The staging directory appears once the lock is held and before the
	// copy, which then waits for a writer on the pipe.
	staged := filepath.Join(st.Root(), "runtimes", "llama-server", ".unpack-*")
	deadline := time.Now().Add(10 * time.Second)
	for {
		if m, _ := filepath.Glob(staged); len(m) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("ensure never began to unpack")
		}
		time.Sleep(10 * time.Millisecond)
	}
	rival := flock.New(filepath.Join(st.Root(), "runtimes", unpackLockName))
	if ok, err := rival.TryLock(); err != nil || ok {
		_ = rival.Unlock()
		t.Errorf("another unpack could take the lock while this one was copying (ok=%v, err=%v)", ok, err)
	}

	w, err := os.OpenFile(blob, os.O_WRONLY, 0) // #nosec G304 -- the fixture's own pipe
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(body); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ensure: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ensure did not finish once the blob was written")
	}
	if ok, err := rival.TryLock(); err != nil || !ok {
		t.Fatalf("the unpack lock stayed held after ensure returned (ok=%v, err=%v)", ok, err)
	}
	_ = rival.Unlock()
}
