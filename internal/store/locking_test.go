// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestCollectionSeesWhatArrivedWhileItWaited: opening a store reads what the
// layout holds, and the lock is what makes that answer stay true. Everything
// written between the two was invisible to whoever opened first, so a
// collector queued behind a pull walked a view from before it, found the
// arriving model's blobs unreferenced and removed them. Both commands
// reported success, and the failure surfaced later as a model that was
// simply gone.
func TestCollectionSeesWhatArrivedWhileItWaited(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	seed, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	pushTestModel(t, seed, "registry.internal/llm/settled:v1", []byte("a model that was already here"))

	// The collector opens the store, reading the layout as it stands, and
	// then waits for the lock.
	collector, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}

	// While it waits, another process pulls a model and tags it.
	puller, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := puller.Lock(ctx)
	if err != nil {
		t.Fatal(err)
	}
	arrived := pushTestModel(t, puller, "registry.internal/llm/arriving:v1", []byte("a model pulled while gc waited"))
	unlock()

	// The lock is granted and collection runs.
	collectorUnlock, err := collector.Lock(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := collector.GC(ctx); err != nil {
		t.Fatalf("gc: %v", err)
	}
	collectorUnlock()

	if _, err := collector.BlobPath(arrived.Digest); err != nil {
		t.Fatalf("collection removed a model that arrived while it waited for the lock: %v", err)
	}
	if _, err := collector.Resolve(ctx, "registry.internal/llm/arriving:v1"); err != nil {
		t.Errorf("the reference that arrived while collection waited is gone: %v", err)
	}
}

// TestASharedLockSeesWhatArrivedWhileItWaited: the same window on the read
// side. A command that opened before another process pulled would report a
// model as absent while it sits on disk, which for verification is a refusal
// over something that is there.
func TestASharedLockSeesWhatArrivedWhileItWaited(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	reader, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}

	writer, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := writer.Lock(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pushTestModel(t, writer, "registry.internal/llm/late:v1", []byte("a model pulled while a reader waited"))
	unlock()

	release, err := reader.RLock(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err := reader.Resolve(ctx, "registry.internal/llm/late:v1"); err != nil {
		t.Fatalf("a reader holding the shared lock cannot see a model that arrived before it took it: %v", err)
	}
}

// TestAFailedReloadReleasesTheLock: the lock outlives the command that took
// it if it is not released, and every later command then waits on a holder
// that has gone. A store that cannot be re-read is a bad reason to wedge
// every process that comes after.
func TestAFailedReloadReleasesTheLock(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	pushTestModel(t, s, "registry.internal/llm/wedge:v1", []byte("weights"))

	// An index the layout cannot read, so re-reading fails.
	index := filepath.Join(dir, "index.json")
	if err := os.WriteFile(index, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	blocked, err := Open(ctx, dir)
	if err != nil {
		// Opening already fails, which is the same refusal a caller gets
		// and leaves no lock behind.
		blocked = s
	}
	if _, lerr := blocked.Lock(ctx); lerr == nil {
		t.Fatal("locking succeeded over a layout that cannot be read")
	}

	// The lock has to be free for whoever comes next.
	if err := os.WriteFile(index, []byte(`{"schemaVersion":2,"manifests":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	next, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	// Bounded, because a lock left held makes this wait rather than fail,
	// and a test that hangs says the same thing as one that never ran.
	waiting, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	unlock, err := next.Lock(waiting)
	if err != nil {
		t.Fatalf("the lock was left held by a command that failed to start: %v", err)
	}
	unlock()
}
