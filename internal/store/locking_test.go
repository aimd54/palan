// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gofrs/flock"
)

// tornIndexes are the states a reader holding no lock can find index.json
// in while another process saves it: the save truncates the file and then
// writes it, and a read of more than one chunk can straddle two saves.
func tornIndexes(whole []byte) map[string][]byte {
	spliced := append(append([]byte{}, whole[:len(whole)/2]...), whole[len(whole)/4:]...)
	return map[string][]byte{
		"empty":     {},
		"cut short": whole[:len(whole)/2],
		"spliced":   spliced,
	}
}

// TestOpeningWaitsOutAnIndexCaughtMidSave: a command reads the layout before
// it takes the lock, and the save it can land in the middle of lasts one
// write. Failing there reported a store that was fine as unreadable.
func TestOpeningWaitsOutAnIndexCaughtMidSave(t *testing.T) {
	ctx := context.Background()
	for _, name := range []string{"empty", "cut short", "spliced"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			s, err := Open(ctx, dir)
			if err != nil {
				t.Fatal(err)
			}
			pushTestModel(t, s, "registry.internal/llm/saved:v1", []byte("weights"))
			index := filepath.Join(dir, "index.json")
			whole, err := os.ReadFile(index)
			if err != nil {
				t.Fatal(err)
			}
			torn := tornIndexes(whole)[name]
			var probe map[string]any
			if err := json.NewDecoder(bytes.NewReader(torn)).Decode(&probe); err == nil {
				t.Fatalf("the %s index decodes, so this case tests nothing", name)
			}
			if err := os.WriteFile(index, torn, 0o600); err != nil {
				t.Fatal(err)
			}

			saved := make(chan error, 1)
			go func() {
				time.Sleep(2 * indexReadBackoff) // the save completes
				saved <- os.WriteFile(index, whole, 0o600)
			}()
			reader, err := Open(ctx, dir)
			if serr := <-saved; serr != nil {
				t.Fatal(serr)
			}
			if err != nil {
				t.Fatalf("a read that caught a save halfway failed instead of waiting it out: %v", err)
			}
			if _, err := reader.Resolve(ctx, "registry.internal/llm/saved:v1"); err != nil {
				t.Fatalf("the store read after the save does not hold what was saved: %v", err)
			}
		})
	}
}

// TestOpeningReportsAnIndexThatStaysBroken: waiting out a save has to end.
// An index that is still cut short once no save could still be running is
// broken, and says so rather than holding the command.
func TestOpeningReportsAnIndexThatStaysBroken(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	pushTestModel(t, s, "registry.internal/llm/broken:v1", []byte("weights"))
	index := filepath.Join(dir, "index.json")
	whole, err := os.ReadFile(index)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(index, tornIndexes(whole)["cut short"], 0o600); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := Open(ctx, dir)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("opening a truncated index: got %v, want it reported as cut short", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("opening a truncated index never gave up")
	}
}

// TestOpenSharedReadsTheLayoutOnlyOnceLocked: a writer holding the store
// can leave index.json halfway through a save for as long as it likes, and
// a reader that locks first never sees it. One that reads before locking
// finds it torn however long it retries.
func TestOpenSharedReadsTheLayoutOnlyOnceLocked(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	writer, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	pushTestModel(t, writer, "registry.internal/llm/held:v1", []byte("weights"))
	unlock, err := writer.Lock(ctx)
	if err != nil {
		t.Fatal(err)
	}
	index := filepath.Join(dir, "index.json")
	whole, err := os.ReadFile(index)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(index, tornIndexes(whole)["cut short"], 0o600); err != nil {
		t.Fatal(err)
	}

	type opened struct {
		s       *Store
		release func()
		err     error
	}
	got := make(chan opened, 1)
	go func() {
		s, release, err := OpenShared(ctx, dir)
		got <- opened{s, release, err}
	}()
	select {
	case o := <-got:
		t.Fatalf("opening returned while another process held the store (%v)", o.err)
	case <-time.After(2 * indexReadAttempts * indexReadBackoff):
	}

	if err := os.WriteFile(index, whole, 0o600); err != nil {
		t.Fatal(err)
	}
	unlock()
	var o opened
	select {
	case o = <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("opening did not proceed once the store was released")
	}
	if o.err != nil {
		t.Fatalf("opening once the save had finished: %v", o.err)
	}
	if _, err := o.s.Resolve(ctx, "registry.internal/llm/held:v1"); err != nil {
		t.Fatalf("the store opened does not hold what was saved: %v", err)
	}

	// The shared lock is held until released, and not after.
	rival := flock.New(filepath.Join(dir, ".palan.lock"))
	if ok, err := rival.TryLock(); err != nil || ok {
		t.Fatalf("an exclusive lock was granted while the opened store held its shared one (ok=%v, err=%v)", ok, err)
	}
	o.release()
	if ok, err := rival.TryLock(); err != nil || !ok {
		t.Fatalf("the store stayed locked after release (ok=%v, err=%v)", ok, err)
	}
	_ = rival.Unlock()
}

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

// TestAFailedReloadReleasesTheSharedLock is the same guarantee on the read
// side, and it matters more there. A command holds one store for as long as
// it runs, so a shared lock leaked by a re-read that failed blocks every
// pull, collection and removal on the host until that process is killed.
func TestAFailedReloadReleasesTheSharedLock(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	pushTestModel(t, s, "registry.internal/llm/shared-wedge:v1", []byte("weights"))

	index := filepath.Join(dir, "index.json")
	if err := os.WriteFile(index, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, rerr := s.RLock(ctx); rerr == nil {
		t.Fatal("the shared lock was granted over a layout that cannot be read")
	}

	if err := os.WriteFile(index, []byte(`{"schemaVersion":2,"manifests":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// An exclusive lock, because that is what a shared one left behind
	// would refuse. Bounded, since a lock still held makes this wait rather
	// than fail, and a test that hangs says the same thing as one that
	// never ran.
	next, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	waiting, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	unlock, err := next.Lock(waiting)
	if err != nil {
		t.Fatalf("a shared lock was left held by a command that failed to start: %v", err)
	}
	unlock()
}
