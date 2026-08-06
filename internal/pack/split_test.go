// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package pack

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aimd54/palan/internal/gguf/gguftest"
	"github.com/aimd54/palan/internal/store"
	"github.com/aimd54/palan/pkg/modelspec"
)

// writeSplitSet materializes n parts of a split GGUF in dir and returns their
// paths in order. Only the first part carries a readable header, which is what
// llama.cpp does and what makes a lone first part look packable.
func writeSplitSet(t *testing.T, dir string, n int) []string {
	t.Helper()
	paths := make([]string, 0, n)
	for i := 1; i <= n; i++ {
		name := filepath.Join(dir, sprintfPart("tiny", i, n))
		data := gguftest.TinyModel("llama", "tiny", "15M", 2048, 15,
			[]byte(strings.Repeat("w", i*8)))
		if err := os.WriteFile(name, data, 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, name)
	}
	return paths
}

func sprintfPart(stem string, i, n int) string {
	return fmt.Sprintf("%s-%05d-of-%05d.gguf", stem, i, n)
}

// TestSplitModelGathersEverySibling: naming one part of a split model packs
// the whole set. Before this, a lone part produced a one-layer artifact that
// described itself like a complete model and could not load.
func TestSplitModelGathersEverySibling(t *testing.T) {
	dir := t.TempDir()
	paths := writeSplitSet(t, dir, 3)

	st := openTestStore(t)
	desc, err := Model(context.Background(), st, []File{{Path: paths[0]}}, "example.com/llm/split:q4", testOpts)
	if err != nil {
		t.Fatalf("packing part 1 of a 3-part model: %v", err)
	}

	man, err := store.FetchManifest(context.Background(), st.OCI(), desc)
	if err != nil {
		t.Fatal(err)
	}
	var weights []string
	for _, l := range man.Layers {
		if l.MediaType == modelspec.MediaTypeModelWeightRaw {
			weights = append(weights, l.Annotations[modelspec.AnnotationFilepath])
		}
	}
	if len(weights) != 3 {
		t.Fatalf("packed %d weight layer(s) from a 3-part model, want 3: %v", len(weights), weights)
	}
	for i, got := range weights {
		want := sprintfPart("tiny", i+1, 3)
		if got != want {
			t.Errorf("weight layer %d is %q, want %q (parts must stay in order)", i, got, want)
		}
	}
}

// TestSplitModelRefusesAnIncompleteSet: a part whose siblings are not on disk
// is an error, not a smaller model.
func TestSplitModelRefusesAnIncompleteSet(t *testing.T) {
	dir := t.TempDir()
	paths := writeSplitSet(t, dir, 3)
	if err := os.Remove(paths[2]); err != nil {
		t.Fatal(err)
	}

	st := openTestStore(t)
	_, err := Model(context.Background(), st, []File{{Path: paths[0]}}, "example.com/llm/split:q4", testOpts)
	if err == nil {
		t.Fatal("packed a 3-part model with one part missing; want an error")
	}
	if !strings.Contains(err.Error(), "tiny-00003-of-00003.gguf") {
		t.Errorf("error does not name the missing part: %v", err)
	}
}

// TestSplitModelAcceptsEveryPartNamed: naming all parts explicitly is the
// same artifact as naming one, so the gathering cannot double-count.
func TestSplitModelAcceptsEveryPartNamed(t *testing.T) {
	dir := t.TempDir()
	paths := writeSplitSet(t, dir, 2)

	one, err := Model(context.Background(), openTestStore(t),
		[]File{{Path: paths[0]}}, "example.com/llm/split:q4", testOpts)
	if err != nil {
		t.Fatal(err)
	}
	all, err := Model(context.Background(), openTestStore(t),
		[]File{{Path: paths[0]}, {Path: paths[1]}}, "example.com/llm/split:q4", testOpts)
	if err != nil {
		t.Fatal(err)
	}
	if one.Digest != all.Digest {
		t.Errorf("naming one part gave %s, naming both gave %s; want the same artifact", one.Digest, all.Digest)
	}
}

// TestUnsplitModelIsUntouched: an ordinary single-file model must not acquire
// neighbours just because other GGUFs sit beside it.
func TestUnsplitModelIsUntouched(t *testing.T) {
	dir := t.TempDir()
	files := writeFixtures(t, dir)
	writeSplitSet(t, dir, 2) // unrelated split model in the same directory

	st := openTestStore(t)
	desc, err := Model(context.Background(), st, files, "example.com/llm/plain:q4", testOpts)
	if err != nil {
		t.Fatal(err)
	}
	man, err := store.FetchManifest(context.Background(), st.OCI(), desc)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range man.Layers {
		name := l.Annotations[modelspec.AnnotationFilepath]
		if strings.Contains(name, "-of-") {
			t.Errorf("a plain model pulled in %q from the directory beside it", name)
		}
	}
}
