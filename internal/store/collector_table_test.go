// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content/oci"
)

// This table records what the layout's own collector does with each shape a
// store can hold, and holds palan's collection against it.
//
// It exists because reasoning about the rule was wrong three times running,
// and building the shapes and watching them was right immediately. The
// collector's behaviour is not documented and not obvious: it tests one hop
// of a subject chain, against a graph built from every tagged descriptor,
// and a hop it can read but cannot place sends it round forever rather than
// dropping anything. Rules derived from reading it have to be checked
// against it.
//
// Three properties are asserted for every row, so adding a shape costs one
// builder and nothing else:
//
//   - collection returns. That is the defect this all started from, and a
//     command that hangs reports nothing at all.
//   - nothing is deleted that the collector itself would have kept. Being
//     stricter than the collector is how content goes missing on a store
//     where nothing was wrong.
//   - the store still works afterwards. Collection that succeeds once and
//     then refuses forever is worse than collection that never ran.
//
// What each shape *should* lose is deliberately not in the table. That is a
// per-shape judgement and it belongs in a test that says so out loud; these
// three hold for every shape there will ever be.

// shape builds one store and names the objects worth asking about.
//
// mayRemove names what palan is allowed to remove even though the collector
// kept it, with the reason it is allowed to. Every deliberate difference
// from the collector goes here and nowhere else, so a difference nobody
// decided on fails the table instead of passing quietly.
type shape struct {
	name      string
	build     func(t *testing.T, s *Store) map[string]ocispec.Descriptor
	mayRemove map[string]string
}

// blobPresent reports whether a layout directory still holds a blob,
// without going through a Store, so it can be asked of a directory the bare
// collector has just worked on.
func blobPresent(dir string, d digest.Digest) bool {
	_, err := os.Stat(filepath.Join(dir, "blobs", d.Algorithm().String(), d.Encoded()))
	return err == nil
}

// buildInto runs a shape into a fresh directory and returns it with what it
// named.
func buildInto(t *testing.T, sh shape) (string, map[string]ocispec.Descriptor) {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	return dir, sh.build(t, s)
}

// survivors reports which named objects a directory still holds.
func survivors(dir string, named map[string]ocispec.Descriptor) map[string]bool {
	out := make(map[string]bool, len(named))
	for name, d := range named {
		out[name] = blobPresent(dir, d.Digest)
	}
	return out
}

// collectorAlone runs the layout's own collection, with its own defaults,
// over a directory palan has not touched. It reports whether it returned
// and whether it reported success, which are different questions.
func collectorAlone(t *testing.T, dir string, within time.Duration) (returned, clean bool) {
	t.Helper()
	st, err := oci.NewWithContext(context.Background(), dir)
	if err != nil {
		// A layout it cannot even open keeps nothing, so nothing is owed.
		return true, false
	}
	done := make(chan error, 1)
	go func() { done <- st.GC(context.Background()) }()
	select {
	case err := <-done:
		return true, err == nil
	case <-time.After(within):
		return false, false
	}
}

func TestCollectionAgainstEveryShapeAStoreCanHold(t *testing.T) {
	for _, sh := range collectorShapes() {
		t.Run(sh.name, func(t *testing.T) {
			// The reference: what the collector does on its own, on a
			// store built the same way and touched by nothing else.
			refDir, refNamed := buildInto(t, sh)
			// A hang is immediate and endless, so a short wait separates
			// it from a slow walk without paying for it fifteen times.
			refReturned, refClean := collectorAlone(t, refDir, 5*time.Second)
			var kept map[string]bool
			if refReturned && refClean {
				kept = survivors(refDir, refNamed)
			}

			dir, named := buildInto(t, sh)
			s, err := Open(context.Background(), dir)
			if err != nil {
				t.Fatalf("opening the store: %v", err)
			}
			done := make(chan error, 1)
			go func() { done <- s.GC(context.Background()) }()
			select {
			case err := <-done:
				_ = err // failing is allowed; hanging and losing content are not
			case <-time.After(30 * time.Second):
				t.Fatalf("collection did not return (the collector on its own returned=%v)", refReturned)
			}

			if kept != nil {
				got := survivors(dir, named)
				for name, wasKept := range kept {
					if !wasKept || got[name] {
						continue
					}
					if why, allowed := sh.mayRemove[name]; allowed {
						t.Logf("removed %q, which the collector kept: %s", name, why)
						continue
					}
					t.Errorf("collection removed %q, which the collector on its own kept, "+
						"and no reason for that difference is recorded", name)
				}
			}

			// And the store is still usable by whatever runs next.
			again, err := Open(context.Background(), dir)
			if err != nil {
				t.Fatalf("the store cannot be opened after collection: %v", err)
			}
			done2 := make(chan error, 1)
			go func() { done2 <- again.GC(context.Background()) }()
			select {
			case err := <-done2:
				if err != nil {
					t.Errorf("collection cannot run a second time: %v", err)
				}
			case <-time.After(30 * time.Second):
				t.Fatal("a second collection did not return")
			}
		})
	}
}

// collectorShapes is the list. Each entry is a store somebody could hand
// palan, whether by using it, by interrupting it, by writing the layout
// with other tooling, or by damaging it.
//
// One shape is deliberately absent: a manifest whose blob cannot be read.
// Opening a layout reads every manifest it names, so that store cannot be
// opened at all and collection never runs on it. It is reachable only when
// the blob stops reading while a process already holds the store open,
// which is what TestGCKeepsWhatHangsOffAManifestItCannotRead builds.
func collectorShapes() []shape {
	tagged := func(t *testing.T, s *Store, ref string, body []byte) ocispec.Descriptor {
		return pushTestModel(t, s, ref, body)
	}
	untag := func(t *testing.T, s *Store, ref string) {
		t.Helper()
		if err := s.OCI().Untag(context.Background(), ref); err != nil {
			t.Fatal(err)
		}
	}
	tag := func(t *testing.T, s *Store, d ocispec.Descriptor, ref string) {
		t.Helper()
		if err := s.Tag(context.Background(), d, ref); err != nil {
			t.Fatal(err)
		}
	}
	const ref = "registry.internal/llm/shape:v1"

	return []shape{
		{"a tagged model on its own", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			return map[string]ocispec.Descriptor{"model": tagged(t, s, ref, []byte("plain"))}
		}, nil},
		{"an untagged signature over a tagged model", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			m := tagged(t, s, ref, []byte("sig-untagged"))
			return map[string]ocispec.Descriptor{"model": m, "sig": pushUntaggedReferrer(t, s, m, "sig")}
		}, nil},
		{"a tagged signature over a tagged model", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			m := tagged(t, s, ref, []byte("sig-tagged"))
			sig := pushUntaggedReferrer(t, s, m, "sig")
			tag(t, s, sig, "registry.internal/llm/shape:sha256-a.sig")
			return map[string]ocispec.Descriptor{"model": m, "sig": sig}
		}, nil},
		{"an untagged signature whose model was removed", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			m := tagged(t, s, ref, []byte("removed-untagged"))
			sig := pushUntaggedReferrer(t, s, m, "sig")
			untag(t, s, ref)
			return map[string]ocispec.Descriptor{"model": m, "sig": sig}
		}, nil},
		{"a tagged signature whose model was removed", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			m := tagged(t, s, ref, []byte("removed-tagged"))
			sig := pushUntaggedReferrer(t, s, m, "sig")
			tag(t, s, sig, "registry.internal/llm/shape:sha256-b.sig")
			untag(t, s, ref)
			return map[string]ocispec.Descriptor{"model": m, "sig": sig}
		}, map[string]string{
			"sig":   "a signature that outlived its model is unlinked, or its tag holds the model's blobs forever and collection reclaims nothing",
			"model": "and once the signature is gone, nothing reaches the model either",
		}},
		{"an untagged referrer on an untagged signature", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			m := tagged(t, s, ref, []byte("chain-uu"))
			sig := pushUntaggedReferrer(t, s, m, "sig")
			return map[string]ocispec.Descriptor{"model": m, "sig": sig, "outer": pushUntaggedReferrer(t, s, sig, "outer")}
		}, map[string]string{
			"outer": "the collector places this one only if it happens to reach the signature first, which is a map iteration order, so it keeps it on some runs and spins forever on others; removing it is the deterministic half of that coin",
		}},
		{"a tagged attestation over an untagged signature", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			m := tagged(t, s, ref, []byte("chain-ut"))
			sig := pushUntaggedReferrer(t, s, m, "sig")
			att := pushUntaggedReferrer(t, s, sig, "att")
			tag(t, s, att, "registry.internal/llm/shape:sha256-c.att")
			return map[string]ocispec.Descriptor{"model": m, "sig": sig, "att": att}
		}, nil},
		{"a tagged attestation over a tagged signature", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			m := tagged(t, s, ref, []byte("chain-tt"))
			sig := pushUntaggedReferrer(t, s, m, "sig")
			tag(t, s, sig, "registry.internal/llm/shape:sha256-d.sig")
			att := pushUntaggedReferrer(t, s, sig, "att")
			tag(t, s, att, "registry.internal/llm/shape:sha256-d.att")
			return map[string]ocispec.Descriptor{"model": m, "sig": sig, "att": att}
		}, nil},
		{"a signature over a child of a tagged index", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			child := tagged(t, s, "registry.internal/llm/shape:child", []byte("index-child"))
			untag(t, s, "registry.internal/llm/shape:child")
			idx := pushIndexOver(t, s, []ocispec.Descriptor{child}, ref)
			return map[string]ocispec.Descriptor{"index": idx, "child": child, "sig": pushUntaggedReferrer(t, s, child, "sig")}
		}, nil},
		{"a signature over a child the layout does not hold", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			absent := ocispec.Descriptor{
				MediaType: ocispec.MediaTypeImageManifest,
				Digest:    digest.FromString("a child never received"),
				Size:      321,
			}
			idx := pushIndexOver(t, s, []ocispec.Descriptor{absent}, ref)
			return map[string]ocispec.Descriptor{"index": idx, "sig": pushUntaggedReferrer(t, s, absent, "sig")}
		}, nil},
		{"a signature over a subject nothing here names", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			absent := ocispec.Descriptor{
				MediaType: ocispec.MediaTypeImageManifest,
				Digest:    digest.FromString("a model never received"),
				Size:      99,
			}
			return map[string]ocispec.Descriptor{"sig": pushUntaggedReferrer(t, s, absent, "sig")}
		}, nil},
		{"a signature over a subject whose size is zero", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			absent := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromString("sizeless")}
			return map[string]ocispec.Descriptor{"sig": pushUntaggedReferrer(t, s, absent, "sig")}
		}, nil},
		{"two untagged referrers naming each other's ancestry", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			m := tagged(t, s, ref, []byte("mutual"))
			untag(t, s, ref)
			first := pushUntaggedReferrer(t, s, m, "first")
			return map[string]ocispec.Descriptor{"first": first, "second": pushUntaggedReferrer(t, s, first, "second")}
		}, nil},
		{"a referrer over a layer rather than a manifest", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			m := tagged(t, s, ref, []byte("over-a-layer"))
			man, err := FetchManifest(context.Background(), s.OCI(), m)
			if err != nil {
				t.Fatal(err)
			}
			return map[string]ocispec.Descriptor{"model": m, "sig": pushUntaggedReferrer(t, s, man.Layers[0], "sig")}
		}, nil},
		{"an index left tagged over nothing", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			return map[string]ocispec.Descriptor{"index": pushIndexOver(t, s, nil, ref)}
		}, nil},
		{"an untagged referrer on a tagged signature", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			m := tagged(t, s, ref, []byte("outer-over-tagged"))
			sig := pushUntaggedReferrer(t, s, m, "sig")
			tag(t, s, sig, "registry.internal/llm/shape:sha256-e.sig")
			return map[string]ocispec.Descriptor{"model": m, "sig": sig, "outer": pushUntaggedReferrer(t, s, sig, "outer")}
		}, nil},
		{"an index naming a manifest whose blob is gone", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			m := tagged(t, s, ref, []byte("half-swept"))
			untag(t, s, ref)
			path, err := s.BlobPath(m.Digest)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			return map[string]ocispec.Descriptor{"model": m}
		}, nil},
	}
}
