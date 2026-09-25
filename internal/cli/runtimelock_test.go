// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofrs/flock"
	"github.com/spf13/viper"

	"github.com/aimd54/palan/internal/registrytest"
	palanruntime "github.com/aimd54/palan/internal/runtime"
	"github.com/aimd54/palan/internal/store"
)

// packStandInRuntime packs a runtime into the store at home whose engine
// exits at once, for tests that need a runtime unpacked and never served.
func packStandInRuntime(t *testing.T, home string) string {
	t.Helper()
	ctx := context.Background()
	bin := filepath.Join(t.TempDir(), "llama-server")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil { // #nosec G306 -- an executable fixture
		t.Fatal(err)
	}
	st, err := store.Open(ctx, home)
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := st.Lock(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	const ref = "registry.invalid/runtimes/llama-server:b1-cpu"
	cfg := palanruntime.Config{
		Name: "llama-server", Build: "b1", OS: goruntime.GOOS, Arch: goruntime.GOARCH,
		Flavor: "cpu", Entrypoint: "llama-server",
	}
	if _, err := palanruntime.Pack(ctx, st, []palanruntime.PackFile{{Path: bin, Name: "llama-server"}}, cfg, ref); err != nil {
		t.Fatalf("packing the stand-in runtime: %v", err)
	}
	return ref
}

// holdUnpacking takes the runtime unpack lock under home as another process
// would. arrived waits until something has come to unpack a runtime there.
func holdUnpacking(t *testing.T, home string) (arrived func(), release func()) {
	t.Helper()
	dir := filepath.Join(home, "runtimes")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	lk := flock.New(filepath.Join(dir, ".unpack.lock"))
	if ok, err := lk.TryLock(); err != nil || !ok {
		t.Fatalf("taking the unpack lock: ok=%v err=%v", ok, err)
	}
	// Ensure creates the runtime's directory just before it asks for the
	// lock, so its appearing means the caller is waiting on the lock now.
	arrived = func() {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(filepath.Join(dir, "llama-server")); err == nil {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("nothing came to unpack the runtime")
	}
	return arrived, func() { _ = lk.Unlock() }
}

// storeHeld reports whether some process holds the store at home, by trying
// to take it exclusively as a pull or a collection would.
func storeHeld(t *testing.T, home string) bool {
	t.Helper()
	rival := flock.New(filepath.Join(home, ".palan.lock"))
	ok, err := rival.TryLock()
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		_ = rival.Unlock()
	}
	return !ok
}

// TestRunHoldsTheStoreWhileItPreparesTheModel: the check, the parse and the
// runtime's unpack happen under the shared lock, whether the model was here
// already or had to be pulled first.
func TestRunHoldsTheStoreWhileItPreparesTheModel(t *testing.T) {
	for _, resident := range []bool{true, false} {
		name := map[bool]string{true: "resident", false: "pulled first"}[resident]
		t.Run(name, func(t *testing.T) {
			reg := registrytest.New(t)
			home := t.TempDir()
			ref := seedPackedGGUF(t, reg, "llm/tiny", "v1", []byte("a model run prepares"))
			if resident {
				runPullInto(t, home, ref)
			}
			rt := packStandInRuntime(t, home)
			t.Setenv("PALAN_HOME", home)
			arrived, release := holdUnpacking(t, home)

			v := viper.New()
			v.Set(keyRegistryPlainHTTP, true)
			v.Set(keyRuntimeRef, rt)
			cmd := newRunCmd(v)
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			cmd.SetArgs([]string{ref, "--prompt", "hi"})
			done := make(chan error, 1)
			go func() { done <- cmd.Execute() }()

			arrived()
			if !storeHeld(t, home) {
				release()
				t.Fatal("run was unpacking its runtime with the store free for a pull or a collection")
			}
			release()
			select {
			case <-done:
			case <-time.After(30 * time.Second):
				t.Fatal("run did not return once the runtime could be unpacked")
			}
			if storeHeld(t, home) {
				t.Fatal("the store stayed held after run returned")
			}
		})
	}
}

// syncBuffer is a bytes.Buffer safe to read while a command writes to it.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// TestServeHoldsTheStoreWhileItStartsUp: serve's start-up reads, the runtime
// check and its unpack, happen under the shared lock, and the lock is gone
// by the time it listens.
func TestServeHoldsTheStoreWhileItStartsUp(t *testing.T) {
	home := t.TempDir()
	first, _ := twoServedModels(t, home)
	rt := packStandInRuntime(t, home)
	t.Setenv("PALAN_HOME", home)
	arrived, release := holdUnpacking(t, home)

	v := viper.New()
	v.Set(keyRuntimeRef, rt)
	cmd := newServeCmd(v)
	var out syncBuffer
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{first, "--memory-budget", "1GiB", "--addr", "127.0.0.1:0"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- cmd.ExecuteContext(ctx) }()

	arrived()
	if !storeHeld(t, home) {
		release()
		t.Fatal("serve was unpacking its runtime with the store free for a pull or a collection")
	}
	release()
	deadline := time.Now().Add(20 * time.Second)
	for !strings.Contains(out.String(), "listening") {
		if time.Now().After(deadline) {
			t.Fatalf("serve did not start listening: %q", out.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if storeHeld(t, home) {
		t.Error("serve kept the store after it started listening")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("serve did not stop")
	}
}
