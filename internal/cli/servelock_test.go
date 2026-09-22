// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gofrs/flock"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"

	"github.com/aimd54/palan/internal/gguf/gguftest"
	"github.com/aimd54/palan/internal/modelmeta"
	"github.com/aimd54/palan/internal/registrytest"
	"github.com/aimd54/palan/internal/router"
	"github.com/aimd54/palan/internal/store"
	"github.com/aimd54/palan/pkg/modelspec"
)

// seedPackedGGUF puts a GGUF model on reg under repo:tag in the shape pack
// builds, a ModelPack manifest and config, and returns its reference.
// seedGGUF's plain image manifest loads, but /v1/models does not list it.
func seedPackedGGUF(t *testing.T, reg *registrytest.Registry, repo, tag string, payload []byte) string {
	t.Helper()
	weights := gguftest.TinyModel("llama", "tiny", "15M", 2048, 15, payload)
	reg.PutBlob(repo, weights)
	cfg, err := json.Marshal(modelspec.Model{Config: modelspec.ModelConfig{Format: modelmeta.FormatGGUF}})
	if err != nil {
		t.Fatal(err)
	}
	reg.PutBlob(repo, cfg)
	manifest := ocispec.Manifest{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: modelspec.ArtifactTypeModelManifest,
		Config:       content.NewDescriptorFromBytes(modelspec.MediaTypeModelConfig, cfg),
		Layers:       []ocispec.Descriptor{localLayer(weights, "model.gguf")},
	}
	manifest.SchemaVersion = 2
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	reg.PutManifest(repo, tag, ocispec.MediaTypeImageManifest, raw)
	return reg.Host() + "/" + repo + ":" + tag
}

// twoServedModels pulls two loadable models into home and returns their
// references.
func twoServedModels(t *testing.T, home string) (first, second string) {
	t.Helper()
	reg := registrytest.New(t)
	first = seedPackedGGUF(t, reg, "llm/first", "v1", []byte("the first served model"))
	second = seedPackedGGUF(t, reg, "llm/second", "v1", []byte("the second served model"))
	runPullInto(t, home, first)
	runPullInto(t, home, second)
	return first, second
}

// TestServeLoadSeesAModelPulledAfterItStarted: serve runs for hours, and a
// store read once at startup and served from memory afterwards reports a
// model as absent for as long as the process lives, however long ago it
// was pulled. Each load has to read the layout as it stands.
func TestServeLoadSeesAModelPulledAfterItStarted(t *testing.T) {
	ctx := context.Background()
	home := t.TempDir()
	reg := registrytest.New(t)
	early, _ := seedGGUF(t, reg, "llm/early", "v1", []byte("pulled before serve started"))
	runPullInto(t, home, early)

	st, err := store.Open(ctx, home)
	if err != nil {
		t.Fatal(err)
	}
	b := &storeBackend{root: st.Root(), bin: "irrelevant-to-this-test", logDir: t.TempDir()}
	if _, _, err := b.Spec(ctx, early); err != nil {
		t.Fatalf("the model that was there at startup does not load: %v", err)
	}

	// Pulled by another process while serve runs.
	late, _ := seedGGUF(t, reg, "llm/late", "v1", []byte("pulled while serve was running"))
	runPullInto(t, home, late)

	spec, _, err := b.Spec(ctx, late)
	if err != nil {
		t.Fatalf("a model pulled after serve started cannot be loaded: %v", err)
	}
	if spec.ModelPath == "" {
		t.Fatal("the load returned no path for a model that is on disk")
	}
}

// TestServeLoadsHoldTheirOwnLocks: a shared lock taken by one load must
// still be held after another load finishes. A lock wrapper that does not
// count holders releases the file lock the first time anyone releases, and
// a store read halfway through by load A is then open to a pull or a
// collection the moment load B completes. Tested by the thing that would
// exploit it: an exclusive lock from outside, which must be refused while
// any load is inside.
func TestServeLoadsHoldTheirOwnLocks(t *testing.T) {
	ctx := context.Background()
	home := t.TempDir()
	first, second := twoServedModels(t, home)

	parked := make(chan struct{})
	release := make(chan struct{})
	b := &storeBackend{root: home, bin: "irrelevant-to-this-test", logDir: t.TempDir(),
		gateFor: func(s *store.Store) func(context.Context, string) (ocispec.Descriptor, error) {
			return func(ctx context.Context, ref string) (ocispec.Descriptor, error) {
				d, err := s.Resolve(ctx, ref)
				if err != nil {
					return ocispec.Descriptor{}, err
				}
				if ref == first {
					// Load A stops here, inside its lock, until told to go on.
					close(parked)
					<-release
				}
				return d, nil
			}
		}}

	var wg sync.WaitGroup
	wg.Add(1)
	var firstErr error
	go func() {
		defer wg.Done()
		_, _, firstErr = b.Spec(ctx, first)
	}()
	<-parked

	// Load B runs to completion while A is parked.
	if _, _, err := b.Spec(ctx, second); err != nil {
		t.Fatalf("second load: %v", err)
	}

	// A is still inside. Nothing may take the store exclusively.
	rival := flock.New(filepath.Join(home, ".palan.lock"))
	got, err := rival.TryLock()
	if err != nil {
		t.Fatal(err)
	}
	if got {
		_ = rival.Unlock()
		t.Fatal("an exclusive lock was granted while a load was still reading the store")
	}

	close(release)
	wg.Wait()
	if firstErr != nil {
		t.Fatalf("first load: %v", firstErr)
	}
	// And once every load is out, the store is free again.
	got, err = rival.TryLock()
	if err != nil {
		t.Fatal(err)
	}
	if !got {
		t.Fatal("the store stayed locked after every load had finished")
	}
	_ = rival.Unlock()
}

// holdMidSave takes the store at home exclusively and leaves index.json
// halfway through a save, as a pull does while it tags what it fetched. The
// returned function finishes the save and releases the store.
func holdMidSave(t *testing.T, home string) (finish func()) {
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
	index := filepath.Join(home, "index.json")
	whole, err := os.ReadFile(index)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(index, whole[:len(whole)/2], 0o600); err != nil {
		t.Fatal(err)
	}
	return func() {
		if err := os.WriteFile(index, whole, 0o600); err != nil {
			t.Error(err)
		}
		unlock()
	}
}

// TestServeLoadNeverReadsAHalfSavedIndex: a load that starts while another
// process is saving the store must wait for the save rather than read it.
// Reading first and locking second found the index torn, and reported a
// model that was on disk as not servable.
func TestServeLoadNeverReadsAHalfSavedIndex(t *testing.T) {
	ctx := context.Background()
	home := t.TempDir()
	first, _ := twoServedModels(t, home)
	b := &storeBackend{root: home, bin: "irrelevant-to-this-test", logDir: t.TempDir()}

	finish := holdMidSave(t, home)
	type loaded struct {
		path string
		err  error
	}
	got := make(chan loaded, 1)
	go func() {
		spec, _, err := b.Spec(ctx, first)
		got <- loaded{spec.ModelPath, err}
	}()
	select {
	case l := <-got:
		finish()
		t.Fatalf("a load finished while another process held the store (%v)", l.err)
	case <-time.After(time.Second):
	}
	finish()

	select {
	case l := <-got:
		if l.err != nil {
			t.Fatalf("the load after the save finished: %v", l.err)
		}
		if _, err := os.Stat(l.path); err != nil {
			t.Fatalf("the load returned a model path that is not on disk: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the load did not proceed once the store was released")
	}
}

// TestServeLoadOnABusyStoreIsUnavailable: a load that gives up waiting for
// a pull is not a missing model. Reported as missing, a client stops
// asking for something that is about to be there.
func TestServeLoadOnABusyStoreIsUnavailable(t *testing.T) {
	ctx := context.Background()
	home := t.TempDir()
	first, _ := twoServedModels(t, home)
	b := &storeBackend{root: home, bin: "irrelevant-to-this-test", logDir: t.TempDir()}

	finish := holdMidSave(t, home)
	defer finish()
	waiting, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	_, _, err := b.Spec(waiting, first)
	if !errors.Is(err, router.ErrUnavailable) {
		t.Fatalf("a load that timed out behind a pull: got %v, want it reported as the store being busy", err)
	}
}

// TestServeListAnswersWhileAWriterHoldsTheStore: /v1/models verifies nothing,
// and a pull holds the store for its whole transfer, so a listing that
// waited for the store answered nothing for as long as any pull ran.
func TestServeListAnswersWhileAWriterHoldsTheStore(t *testing.T) {
	ctx := context.Background()
	home := t.TempDir()
	first, second := twoServedModels(t, home)
	b := &storeBackend{root: home, bin: "irrelevant-to-this-test", logDir: t.TempDir()}

	writer, err := store.Open(ctx, home)
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := writer.Lock(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()

	waiting, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	start := time.Now()
	refs, err := b.List(waiting)
	if err != nil {
		t.Fatalf("listing while a pull holds the store: %v", err)
	}
	if took := time.Since(start); took > time.Second {
		t.Errorf("listing waited %v for a pull to finish", took)
	}
	listed := map[string]bool{}
	for _, r := range refs {
		listed[r] = true
	}
	if !listed[first] || !listed[second] {
		t.Fatalf("listing while a pull holds the store: got %v, want %s and %s", refs, first, second)
	}
}

// TestServeLoadsRunConcurrently: two loads for two models at once, which is
// what the router does, since its single-flight is keyed by reference.
// Nothing here asserts on timing; it exists to be run under the race
// detector, which is the only thing that sees a store handle being swapped
// beneath a concurrent reader.
func TestServeLoadsRunConcurrently(t *testing.T) {
	ctx := context.Background()
	home := t.TempDir()
	first, second := twoServedModels(t, home)
	b := &storeBackend{root: home, bin: "irrelevant-to-this-test", logDir: t.TempDir()}

	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for i := 0; i < 2; i++ {
		for _, ref := range []string{first, second} {
			wg.Add(1)
			go func(ref string) {
				defer wg.Done()
				if _, _, err := b.Spec(ctx, ref); err != nil {
					errs <- err
				}
			}(ref)
		}
	}
	// The list is read alongside the loads, as /v1/models would.
	wg.Add(1)
	go func() {
		defer wg.Done()
		refs, err := b.List(ctx)
		if err != nil {
			errs <- err
			return
		}
		if len(refs) != 2 {
			errs <- fmt.Errorf("the list read alongside the loads holds %v, want both models", refs)
		}
	}()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("concurrent loads did not finish")
	}
	close(errs)
	for err := range errs {
		t.Errorf("a concurrent load failed: %v", err)
	}
}
