// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/errdef"

	"github.com/aimd54/palan/internal/signing"
	"github.com/aimd54/palan/pkg/modelspec"
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
// Four properties are asserted for every row, so adding a shape costs one
// builder and nothing else:
//
//   - collection returns. That is the defect this all started from, and a
//     command that hangs reports nothing at all.
//   - nothing is deleted that the collector itself would have kept. Being
//     stricter than the collector is how content goes missing on a store
//     where nothing was wrong.
//   - nothing a manifest still in the layout names is deleted, so what is
//     kept is kept whole.
//   - the store still works afterwards. Collection that succeeds once and
//     then refuses forever is worse than collection that never ran.
//
// What each shape *should* lose is deliberately not in the table. That is a
// per-shape judgement and it belongs in a test that says so out loud; these
// four hold for every shape there will ever be.

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

// presentBlobs lists the digests a layout directory holds.
func presentBlobs(t *testing.T, dir string) map[digest.Digest]bool {
	t.Helper()
	out := map[digest.Digest]bool{}
	names, err := os.ReadDir(filepath.Join(dir, "blobs", "sha256"))
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		out[digest.NewDigestFromEncoded(digest.SHA256, n.Name())] = true
	}
	return out
}

// lostFromKept walks everything the layout still lists and returns what it
// names that was present before and is gone now.
func lostFromKept(t *testing.T, s *Store, before map[digest.Digest]bool) []digest.Digest {
	t.Helper()
	ctx := context.Background()
	queue, err := s.indexManifests()
	if err != nil {
		t.Fatal(err)
	}
	type visit struct {
		mediaType string
		digest    digest.Digest
	}
	seen := map[visit]bool{}
	var lost []digest.Digest
	for len(queue) > 0 {
		node := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		key := visit{node.MediaType, node.Digest}
		if seen[key] {
			continue
		}
		seen[key] = true
		if present, _ := s.OCI().Exists(ctx, node); !present {
			if before[node.Digest] {
				lost = append(lost, node.Digest)
			}
			continue
		}
		successors, err := content.Successors(ctx, s.OCI(), node)
		if err == nil {
			queue = append(queue, successors...)
		}
	}
	return lost
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
	// How many names the table actually held to the collector's answer.
	// A row where the collector hangs or errors has no answer to compare
	// against, and a row that declares every name it exposes compares
	// nothing either. Both are legitimate and both are silent, so the
	// count is reported and floored: a change that quietly turns the table
	// into a list of shapes nobody checks fails here instead of passing.
	compared := 0
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
			before := presentBlobs(t, dir)
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
					if !wasKept {
						continue
					}
					if _, declared := sh.mayRemove[name]; !declared {
						compared++
					}
					if got[name] {
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
			for _, lost := range lostFromKept(t, again, before) {
				t.Errorf("collection removed %s, which a manifest it kept still names", lost)
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
	// The floor is a fraction of the shapes, not a fixed number, so adding
	// a shape whose collector hangs does not quietly lower the bar.
	if min := len(collectorShapes()); compared < min {
		t.Errorf("the table held only %d names to the collector's answer across %d shapes; "+
			"below one apiece it is a list of stores nobody is checking", compared, min)
	}
	t.Logf("held %d names to the collector's answer across %d shapes", compared, len(collectorShapes()))
}

// pushManifestOver stores a manifest carrying one layer and tags it, so a
// digest can be reached as a layer rather than as a manifest.
func pushManifestOver(t *testing.T, s *Store, layer ocispec.Descriptor, tagRef string) ocispec.Descriptor {
	t.Helper()
	ctx := context.Background()
	cfg := content.NewDescriptorFromBytes("application/octet-stream", []byte("{}"))
	if err := s.OCI().Push(ctx, cfg, bytes.NewReader([]byte("{}"))); err != nil && !errors.Is(err, errdef.ErrAlreadyExists) {
		t.Fatal(err)
	}
	raw, err := json.Marshal(ocispec.Manifest{
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    cfg,
		Layers:    []ocispec.Descriptor{layer},
	})
	if err != nil {
		t.Fatal(err)
	}
	desc := content.NewDescriptorFromBytes(ocispec.MediaTypeImageManifest, raw)
	if err := s.OCI().Push(ctx, desc, bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	if err := s.Tag(ctx, desc, tagRef); err != nil {
		t.Fatal(err)
	}
	return desc
}

// nameEntryAfterItsOwnDigest gives one index entry a reference name equal
// to its digest, which is how the layout records a manifest with no tag and
// what the collector tests for.
func nameEntryAfterItsOwnDigest(t *testing.T, root string, d digest.Digest) {
	t.Helper()
	path := filepath.Join(root, "index.json")
	raw, err := os.ReadFile(path) // #nosec G304 -- the store's own layout file
	if err != nil {
		t.Fatal(err)
	}
	var idx ocispec.Index
	if err := json.Unmarshal(raw, &idx); err != nil {
		t.Fatal(err)
	}
	found := false
	for i := range idx.Manifests {
		if idx.Manifests[i].Digest != d {
			continue
		}
		if idx.Manifests[i].Annotations == nil {
			idx.Manifests[i].Annotations = map[string]string{}
		}
		idx.Manifests[i].Annotations[ocispec.AnnotationRefName] = d.String()
		found = true
	}
	if !found {
		t.Fatalf("the layout does not list %s", d)
	}
	out, err := json.Marshal(idx)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
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
	dropBlob := func(t *testing.T, s *Store, d ocispec.Descriptor) {
		t.Helper()
		path, err := s.BlobPath(d.Digest)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil {
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
		{"a tagged signature over a model whose blob is gone", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			m := tagged(t, s, ref, []byte("blobless-model"))
			sig := pushUntaggedReferrer(t, s, m, "sig")
			tag(t, s, sig, "registry.internal/llm/shape:sha256-f.sig")
			dropBlob(t, s, m)
			return map[string]ocispec.Descriptor{"sig": sig}
		}, nil},
		{"a tagged attestation over a tagged signature over a model whose blob is gone", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			m := tagged(t, s, ref, []byte("blobless-chain"))
			sig := pushUntaggedReferrer(t, s, m, "sig")
			tag(t, s, sig, "registry.internal/llm/shape:sha256-g.sig")
			att := pushUntaggedReferrer(t, s, sig, "att")
			tag(t, s, att, "registry.internal/llm/shape:sha256-g.att")
			dropBlob(t, s, m)
			return map[string]ocispec.Descriptor{"sig": sig, "att": att}
		}, nil},
		{"a tagged signature over a blob-less model a tagged index still names", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			m := tagged(t, s, "registry.internal/llm/shape:child", []byte("blobless-indexed"))
			untag(t, s, "registry.internal/llm/shape:child")
			idx := pushIndexOver(t, s, []ocispec.Descriptor{m}, ref)
			sig := pushUntaggedReferrer(t, s, m, "sig")
			tag(t, s, sig, "registry.internal/llm/shape:sha256-h.sig")
			dropBlob(t, s, m)
			return map[string]ocispec.Descriptor{"index": idx, "sig": sig}
		}, nil},
		{"a tagged signature named as a child of a tagged index, over an absent subject", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			absent := ocispec.Descriptor{
				MediaType: ocispec.MediaTypeImageManifest,
				Digest:    digest.FromString("a subject never received"),
				Size:      77,
			}
			sig := pushUntaggedReferrer(t, s, absent, "sig")
			tag(t, s, sig, "registry.internal/llm/shape:sha256-i.sig")
			idx := pushIndexOver(t, s, []ocispec.Descriptor{sig}, ref)
			return map[string]ocispec.Descriptor{"index": idx, "sig": sig}
		}, nil},
		{"a tagged signature over the weight layer of an untagged model", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			m := tagged(t, s, ref, []byte("sig-over-layer"))
			man, err := FetchManifest(context.Background(), s.OCI(), m)
			if err != nil {
				t.Fatal(err)
			}
			sig := pushUntaggedReferrer(t, s, man.Layers[0], "sig")
			tag(t, s, sig, "registry.internal/llm/shape:sha256-j.sig")
			untag(t, s, ref)
			return map[string]ocispec.Descriptor{"sig": sig}
		}, map[string]string{
			"sig": "the layer it describes belongs to a model nothing tags any more, so this is the same signature-outlived-its-model case one hop over, and its tag would hold that layer forever",
		}},
		{"a tagged signature a tagged index names, over a model that was removed", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			m := tagged(t, s, ref, []byte("indexed-sig-live-subject"))
			sig := pushUntaggedReferrer(t, s, m, "sig")
			tag(t, s, sig, "registry.internal/llm/shape:sha256-k.sig")
			idx := pushIndexOver(t, s, []ocispec.Descriptor{sig}, "registry.internal/llm/shape:holder")
			untag(t, s, ref)
			return map[string]ocispec.Descriptor{"index": idx, "sig": sig}
		}, nil},
		{"an entry whose reference records its own digest", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			absent := ocispec.Descriptor{
				MediaType: ocispec.MediaTypeImageManifest,
				Digest:    digest.FromString("a subject for the self-named entry"),
				Size:      55,
			}
			sig := pushUntaggedReferrer(t, s, absent, "sig")
			// Written into the index directly: tagging refuses to record a
			// digest as a reference name, and this shape is what a layout
			// from other tooling can hold.
			nameEntryAfterItsOwnDigest(t, s.Root(), sig.Digest)
			return map[string]ocispec.Descriptor{"sig": sig}
		}, nil},
		{"a tagged index naming a tagged signature as an ordinary blob", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			m := tagged(t, s, ref, []byte("named-as-a-blob"))
			sig := pushUntaggedReferrer(t, s, m, "sig")
			tag(t, s, sig, "registry.internal/llm/shape:sha256-l.sig")
			// The child records the signature's digest under a media type
			// that names no successors, so walking the index reaches the
			// digest without ever reading the manifest behind it.
			asBlob := sig
			asBlob.MediaType = "application/octet-stream"
			idx := pushIndexOver(t, s, []ocispec.Descriptor{asBlob}, "registry.internal/llm/shape:holder")
			untag(t, s, ref)
			return map[string]ocispec.Descriptor{"index": idx, "sig": sig}
		}, nil},
		{"a tagged model whose layer is also a tagged signature", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			base := tagged(t, s, ref, []byte("collision-base"))
			sig := pushUntaggedReferrer(t, s, base, "sig")
			tag(t, s, sig, "registry.internal/llm/shape:sha256-m.sig")
			// A layer is arbitrary bytes, so a manifest may legitimately
			// carry another manifest's digest as one of its layers.
			asLayer := sig
			asLayer.MediaType = "application/octet-stream"
			carrier := pushManifestOver(t, s, asLayer, "registry.internal/llm/shape:carrier")
			untag(t, s, ref)
			return map[string]ocispec.Descriptor{"carrier": carrier, "sig": sig}
		}, nil},
		{"a self-named referrer over a subject that is present and unreached", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			m := tagged(t, s, ref, []byte("self-named-live-subject"))
			sig := pushUntaggedReferrer(t, s, m, "sig")
			untag(t, s, ref)
			nameEntryAfterItsOwnDigest(t, s.Root(), sig.Digest)
			return map[string]ocispec.Descriptor{"model": m, "sig": sig}
		}, map[string]string{
			"model": "the model is untagged and only this signature reached it, so both go once the signature does",
			"sig":   "a signature that outlived its model, reached here through an entry the layout records as untagged",
		}},
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
		{"a tagged model derived from one that was removed", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			base := tagged(t, s, ref, []byte("derived-base"))
			weights := []byte("the derived model's own weights")
			derived := pushModelOver(t, s, base, weights, "registry.internal/llm/shape:derived")
			untag(t, s, ref)
			return map[string]ocispec.Descriptor{
				"base":            base,
				"derived":         derived,
				"derived weights": content.NewDescriptorFromBytes(modelspec.MediaTypeModelWeightRaw, weights),
			}
		}, nil},
		{"a tagged index recording a subject that was removed", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			base := tagged(t, s, ref, []byte("index-subject"))
			child := tagged(t, s, "registry.internal/llm/shape:child", []byte("a child unrelated to the subject"))
			untag(t, s, "registry.internal/llm/shape:child")
			idx := pushIndexWithSubject(t, s, []ocispec.Descriptor{child}, &base, "registry.internal/llm/shape:index")
			untag(t, s, ref)
			return map[string]ocispec.Descriptor{"base": base, "child": child, "index": idx}
		}, nil},
		{"a tagged artifact of a type nothing here knows, over a removed model", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			m := tagged(t, s, ref, []byte("unknown-type-subject"))
			other := pushReferrerOfType(t, s, m, "something in its own right", "application/vnd.example.unknown.v1+json")
			tag(t, s, other, "registry.internal/llm/shape:unknown")
			untag(t, s, ref)
			return map[string]ocispec.Descriptor{"model": m, "artifact": other}
		}, nil},
		{"a derived model superseded under its tag, with its signature", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			base := tagged(t, s, ref, []byte("superseded-base"))
			oldWeights := []byte("the first version's own weights")
			old := pushModelOver(t, s, base, oldWeights, "registry.internal/llm/shape:derived")
			sig := pushUntaggedReferrer(t, s, old, "sig")
			tag(t, s, sig, "registry.internal/llm/shape:sha256-old.sig")
			pushModelOver(t, s, base, []byte("the second version's own weights"), "registry.internal/llm/shape:derived")
			return map[string]ocispec.Descriptor{
				"base": base, "old": old, "sig": sig,
				"old weights": content.NewDescriptorFromBytes(modelspec.MediaTypeModelWeightRaw, oldWeights),
			}
		}, nil},
		{"a never-tagged model attached to a tagged model", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			base := tagged(t, s, ref, []byte("attached-base"))
			weights := []byte("an adapter attached without a tag")
			adapter := pushModelOver(t, s, base, weights, "registry.internal/llm/shape:attached")
			untag(t, s, "registry.internal/llm/shape:attached")
			return map[string]ocispec.Descriptor{
				"base": base, "adapter": adapter,
				"adapter weights": content.NewDescriptorFromBytes(modelspec.MediaTypeModelWeightRaw, weights),
			}
		}, nil},
		{"an untagged index over a tagged model, naming an untagged model and a signature over it", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			m := tagged(t, s, ref, []byte("i1-model"))
			gone := tagged(t, s, "registry.internal/llm/shape:i1-base", []byte("i1-base"))
			child := pushModelOver(t, s, gone, []byte("i1 child"), "registry.internal/llm/shape:i1-child")
			untag(t, s, "registry.internal/llm/shape:i1-child")
			untag(t, s, "registry.internal/llm/shape:i1-base")
			sig := pushUntaggedReferrer(t, s, child, "sig")
			idx := pushIndexWithSubject(t, s, []ocispec.Descriptor{sig, child}, &m, "")
			return map[string]ocispec.Descriptor{"model": m, "child": child, "sig": sig, "index": idx}
		}, nil},
		{"a tagged index naming a manifest as a blob after naming it as an index", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			inner := tagged(t, s, "registry.internal/llm/shape:i2-inner", []byte("i2-inner"))
			untag(t, s, "registry.internal/llm/shape:i2-inner")
			sig := pushUntaggedReferrer(t, s, inner, "sig")
			x := pushIndexOver(t, s, []ocispec.Descriptor{inner}, "")
			asBlob := x
			asBlob.MediaType = "application/octet-stream"
			outer := pushIndexOver(t, s, []ocispec.Descriptor{x, asBlob}, ref)
			return map[string]ocispec.Descriptor{"inner": inner, "sig": sig, "x": x, "outer": outer}
		}, nil},
		{"a tagged signature over an untagged derived model over a removed base", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			base := tagged(t, s, ref, []byte("chain-derived-base"))
			derived := pushModelOver(t, s, base, []byte("weights of a derived model since removed"), "registry.internal/llm/shape:c-derived")
			sig := pushUntaggedReferrer(t, s, derived, "sig")
			tag(t, s, sig, "registry.internal/llm/shape:sha256-c.sig")
			untag(t, s, "registry.internal/llm/shape:c-derived")
			untag(t, s, ref)
			return map[string]ocispec.Descriptor{"base": base, "derived": derived, "sig": sig}
		}, map[string]string{
			"sig":     "a signature that outlived the model it signed",
			"derived": "untagged content that only the signature reached",
			"base":    "and what only the derived model reached",
		}},
		{"a tagged bill of materials with no subject", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			return map[string]ocispec.Descriptor{"sbom": pushTaggedTyped(t, s, "application/spdx+json", nil, "registry.internal/llm/shape:sbom")}
		}, nil},
		{"an untagged derived model inside a tagged index, over a removed base", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			base := tagged(t, s, ref, []byte("indexed-derived-base"))
			derived := pushModelOver(t, s, base, []byte("weights of an indexed derived model"), "registry.internal/llm/shape:indexed")
			untag(t, s, "registry.internal/llm/shape:indexed")
			idx := pushIndexOver(t, s, []ocispec.Descriptor{derived}, "registry.internal/llm/shape:holder-index")
			untag(t, s, ref)
			return map[string]ocispec.Descriptor{"base": base, "derived": derived, "index": idx}
		}, nil},
		{"an untagged attachment of an unknown type on a tagged model", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			m := tagged(t, s, ref, []byte("carded"))
			return map[string]ocispec.Descriptor{"model": m, "card": pushReferrerOfType(t, s, m, "a model card", "application/vnd.example.model-card")}
		}, nil},
		{"an untagged XML bill of materials on a tagged model", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			m := tagged(t, s, ref, []byte("xml-sbom"))
			return map[string]ocispec.Descriptor{"model": m, "sbom": pushReferrerOfType(t, s, m, "<bom/>", "application/vnd.cyclonedx+xml")}
		}, nil},
		{"a tagged attestation over an untagged attachment of a tagged model", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			m := tagged(t, s, ref, []byte("attested-card"))
			card := pushReferrerOfType(t, s, m, "a model card", "application/vnd.example.model-card")
			att := pushReferrerOfType(t, s, card, "an attestation over the card", signing.ArtifactTypeAttestation)
			tag(t, s, att, "registry.internal/llm/shape:sha256-card.att")
			return map[string]ocispec.Descriptor{"model": m, "card": card, "att": att}
		}, nil},
		{"an untagged index recording a tagged model, with a derived child", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			m := tagged(t, s, ref, []byte("indexed-subject"))
			derived := pushModelOver(t, s, m, []byte("a child of the untagged index"), "registry.internal/llm/shape:rv11")
			untag(t, s, "registry.internal/llm/shape:rv11")
			idx := pushIndexWithSubject(t, s, []ocispec.Descriptor{derived}, &m, "")
			return map[string]ocispec.Descriptor{"model": m, "derived": derived, "index": idx}
		}, nil},
		{"a superseded derived model still a child of a tagged index", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			base := tagged(t, s, ref, []byte("rv5-base"))
			old := pushModelOver(t, s, base, []byte("the version the index names"), "registry.internal/llm/shape:rv5")
			sig := pushUntaggedReferrer(t, s, old, "sig")
			tag(t, s, sig, "registry.internal/llm/shape:sha256-rv5.sig")
			idx := pushIndexOver(t, s, []ocispec.Descriptor{old}, "registry.internal/llm/shape:rv5-index")
			pushModelOver(t, s, base, []byte("the version the tag moved to"), "registry.internal/llm/shape:rv5")
			return map[string]ocispec.Descriptor{"base": base, "old": old, "sig": sig, "index": idx}
		}, nil},
		{"a tagged derived model whose subject is its own superseded version", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			base := tagged(t, s, ref, []byte("rv6-base"))
			first := pushModelOver(t, s, base, []byte("the first version"), "registry.internal/llm/shape:rv6")
			second := pushModelOver(t, s, first, []byte("the version derived from the first"), "registry.internal/llm/shape:rv6")
			return map[string]ocispec.Descriptor{"base": base, "first": first, "second": second}
		}, nil},
		{"two untagged derived models, one over the other, over a tagged base", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			base := tagged(t, s, ref, []byte("rv4-base"))
			inner := pushModelOver(t, s, base, []byte("rv4 inner"), "registry.internal/llm/shape:rv4-inner")
			outer := pushModelOver(t, s, inner, []byte("rv4 outer"), "registry.internal/llm/shape:rv4-outer")
			untag(t, s, "registry.internal/llm/shape:rv4-inner")
			untag(t, s, "registry.internal/llm/shape:rv4-outer")
			return map[string]ocispec.Descriptor{"base": base, "inner": inner, "outer": outer}
		}, map[string]string{
			"outer": "its subject is itself untagged, which the collector places on most runs and spins forever on the rest; removing it is the deterministic half of that coin",
		}},
		{"an untagged derived child of a tagged index, its base gone", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			base := tagged(t, s, ref, []byte("rv8-base"))
			derived := pushModelOver(t, s, base, []byte("rv8 child"), "registry.internal/llm/shape:rv8")
			untag(t, s, "registry.internal/llm/shape:rv8")
			idx := pushIndexOver(t, s, []ocispec.Descriptor{derived}, "registry.internal/llm/shape:rv8-index")
			untag(t, s, ref)
			dropBlob(t, s, base)
			return map[string]ocispec.Descriptor{"derived": derived, "index": idx}
		}, nil},
		{"an untagged derived model named as a layer, its base untagged", func(t *testing.T, s *Store) map[string]ocispec.Descriptor {
			base := tagged(t, s, ref, []byte("rv9-base"))
			derived := pushModelOver(t, s, base, []byte("rv9 carried"), "registry.internal/llm/shape:rv9")
			untag(t, s, "registry.internal/llm/shape:rv9")
			asLayer := derived
			asLayer.MediaType = "application/octet-stream"
			carrier := pushManifestOver(t, s, asLayer, "registry.internal/llm/shape:rv9-carrier")
			untag(t, s, ref)
			return map[string]ocispec.Descriptor{"derived": derived, "carrier": carrier}
		}, nil},
	}
}

// pushTaggedTyped tags a manifest of artifactType, naming subject when one
// is given, with a layer of its own.
func pushTaggedTyped(t *testing.T, s *Store, artifactType string, subject *ocispec.Descriptor, tagRef string) ocispec.Descriptor {
	t.Helper()
	ctx := context.Background()
	cfg := content.NewDescriptorFromBytes(ocispec.MediaTypeEmptyJSON, []byte("{}"))
	layer := content.NewDescriptorFromBytes("application/octet-stream", []byte(tagRef))
	for _, b := range []struct {
		desc ocispec.Descriptor
		raw  []byte
	}{{cfg, []byte("{}")}, {layer, []byte(tagRef)}} {
		if err := s.OCI().Push(ctx, b.desc, bytes.NewReader(b.raw)); err != nil && !errors.Is(err, errdef.ErrAlreadyExists) {
			t.Fatal(err)
		}
	}
	raw, err := json.Marshal(ocispec.Manifest{
		Versioned:    specs.Versioned{SchemaVersion: 2},
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: artifactType,
		Config:       cfg,
		Layers:       []ocispec.Descriptor{layer},
		Subject:      subject,
	})
	if err != nil {
		t.Fatal(err)
	}
	desc := content.NewDescriptorFromBytes(ocispec.MediaTypeImageManifest, raw)
	if err := s.OCI().Push(ctx, desc, bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	if err := s.Tag(ctx, desc, tagRef); err != nil {
		t.Fatal(err)
	}
	return desc
}
