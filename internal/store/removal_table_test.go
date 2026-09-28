// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/errdef"
)

// These tables remove references from every shape the collection table
// builds, and hold each refusal or deletion of a description to what
// palan's collection keeps naming it once it is deleted.

// tagsIn lists the references a store's layout records, leaving out names
// that are digests, which the layout uses for untagged entries.
func tagsIn(t *testing.T, s *Store) []string {
	t.Helper()
	all, err := s.indexManifests()
	if err != nil {
		t.Fatal(err)
	}
	var refs []string
	for _, d := range all {
		ref := d.Annotations[ocispec.AnnotationRefName]
		if _, err := digest.Parse(ref); ref != "" && err != nil {
			refs = append(refs, ref)
		}
	}
	return refs
}

// describedBy returns the manifest ref names when removal treats it as a
// description, one recording a subject and typed as only describing it.
func describedBy(t *testing.T, s *Store, ref string) (ocispec.Descriptor, bool) {
	t.Helper()
	ctx := context.Background()
	desc, err := s.Resolve(ctx, ref)
	if err != nil {
		return ocispec.Descriptor{}, false
	}
	h, err := s.readHead(ctx, desc)
	return desc, err == nil && h.subject != nil && describesOnly(h.artifactType)
}

// collectTwice runs collection, reopens the store, and runs it again. The
// first round may fail; the second has to succeed.
func collectTwice(t *testing.T, dir string) *Store {
	t.Helper()
	ctx := context.Background()
	var s *Store
	for round := 1; round <= 2; round++ {
		var err error
		if s, err = Open(ctx, dir); err != nil {
			t.Fatalf("opening the store for collection round %d: %v", round, err)
		}
		done := make(chan error, 1)
		go func() { done <- s.GC(ctx) }()
		select {
		case err := <-done:
			if err != nil && round == 2 {
				t.Errorf("collection cannot run a second time: %v", err)
			}
		case <-time.After(30 * time.Second):
			t.Fatalf("collection round %d did not return", round)
		}
	}
	return s
}

// namedOnceDeleted builds sh, deletes ds and every index entry for them,
// and collects. It reports whether anything the layout still lists names
// one of them, which deleting them on removal would leave naming nothing.
func namedOnceDeleted(t *testing.T, sh shape, ds map[digest.Digest]bool) bool {
	t.Helper()
	dir, _ := buildInto(t, sh)
	path := filepath.Join(dir, "index.json")
	raw, err := os.ReadFile(path) // #nosec G304 -- a test layout
	if err != nil {
		t.Fatal(err)
	}
	var index ocispec.Index
	if err := json.Unmarshal(raw, &index); err != nil {
		t.Fatal(err)
	}
	kept := index.Manifests[:0]
	for _, m := range index.Manifests {
		if !ds[m.Digest] {
			kept = append(kept, m)
		}
	}
	index.Manifests = kept
	if raw, err = json.Marshal(index); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	for d := range ds {
		if err := os.Remove(filepath.Join(dir, "blobs", d.Algorithm().String(), d.Encoded())); err != nil {
			t.Fatal(err)
		}
	}
	s := collectTwice(t, dir)
	return len(lostBeneath(t, s, ds)) > 0
}

// lostBeneath walks everything the layout still lists and returns what it
// names that was present before and is gone now.
func lostBeneath(t *testing.T, s *Store, before map[digest.Digest]bool) []digest.Digest {
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
		if successors, err := content.Successors(ctx, s.OCI(), node); err == nil {
			queue = append(queue, successors...)
		}
	}
	return lost
}

func TestRemovalAgainstEveryShapeAStoreCanHold(t *testing.T) {
	ctx := context.Background()
	outcomes := map[string]int{}
	for _, sh := range collectorShapes() {
		t.Run(sh.name, func(t *testing.T) {
			probe, _ := buildInto(t, sh)
			ps, err := Open(ctx, probe)
			if err != nil {
				t.Fatal(err)
			}
			for _, ref := range tagsIn(t, ps) {
				t.Run(ref, func(t *testing.T) {
					dir, _ := buildInto(t, sh)
					before := presentBlobs(t, dir)
					s, err := Open(ctx, dir)
					if err != nil {
						t.Fatal(err)
					}
					resolved := map[string]digest.Digest{}
					for _, r := range tagsIn(t, s) {
						if d, rerr := s.Resolve(ctx, r); rerr == nil {
							resolved[r] = d.Digest
						}
					}
					target, isDescription := describedBy(t, s, ref)
					otherTag := false
					for r, d := range resolved {
						otherTag = otherTag || (r != ref && d == target.Digest)
					}

					// What the removal may take with it, read from the shape:
					// tagged descriptions whose subject chain reaches the target.
					expected := map[string]bool{}
					whole := map[digest.Digest]bool{target.Digest: true}
					for grew := isDescription && !otherTag; grew; {
						grew = false
						for r, d := range resolved {
							if expected[r] || d == target.Digest {
								continue
							}
							if rd, isDesc := describedBy(t, s, r); isDesc {
								if h, err := s.readHead(ctx, rd); err == nil && whole[h.subject.Digest] {
									expected[r], whole[d], grew = true, true, true
								}
							}
						}
					}

					var held *HeldError
					along, rerr := s.RemoveReporting(ctx, ref)
					taken := map[string]bool{}
					for _, r := range along {
						taken[r] = true
					}
					if len(along) > 0 {
						outcomes["deleted with descriptions of it"]++
					}
					if rerr == nil {
						for r := range expected {
							if !taken[r] {
								t.Errorf("removing %s left %s, a tagged description of it", ref, r)
							}
						}
						for r := range taken {
							if !expected[r] {
								t.Errorf("removing %s took %s, which is no tagged description of it", ref, r)
							}
						}
					}
					switch err := rerr; {
					case errors.As(err, &held):
						outcomes["refused"]++
						if !isDescription {
							t.Errorf("removing %s, which is no description, was refused: %v", ref, err)
						}
						// What a refusal says to remove first is a reference
						// that can be removed, not a digest.
						if _, tagged := resolved[held.Holder]; !tagged {
							t.Errorf("removing %s was refused naming %q, which is no reference in the store", ref, held.Holder)
						}
						if held.Through != "" && !expected[held.Through] {
							t.Errorf("removing %s was refused through %s, which is no tagged description of it", ref, held.Through)
						}
					case err != nil:
						t.Fatalf("removing %s: %v", ref, err)
					case !isDescription:
						outcomes["untagged"]++
					case otherTag:
						outcomes["untagged, another tag names it"]++
					default:
						outcomes["deleted"]++
					}

					// Every other reference resolves to what it did, and a
					// refusal leaves the removed one in place as well.
					after, err := Open(ctx, dir)
					if err != nil {
						t.Fatal(err)
					}
					for r, want := range resolved {
						if (r == ref || taken[r]) && held == nil {
							if _, err := after.Resolve(ctx, r); err == nil {
								t.Errorf("%s still resolves after its removal", r)
							}
							continue
						}
						if got, err := after.Resolve(ctx, r); err != nil || got.Digest != want {
							t.Errorf("removing %s took %s with it: %v", ref, r, err)
						}
					}

					// A description is refused exactly when deleting it would
					// leave something collection keeps naming it, and deleted
					// otherwise, never left untagged with nothing to name it.
					if isDescription && !otherTag {
						named := namedOnceDeleted(t, sh, whole)
						present := blobPresent(dir, target.Digest)
						switch {
						case held != nil && !named:
							t.Errorf("removing %s was refused, but deleting it leaves nothing naming it: %v", ref, held)
						case held == nil && present:
							t.Errorf("removing %s untagged the description and kept its manifest", ref)
						case held == nil && named:
							t.Errorf("removing %s deleted a description that kept content names", ref)
						}
					}

					collected := collectTwice(t, dir)
					for _, lost := range lostBeneath(t, collected, before) {
						t.Errorf("collecting after removing %s lost %s, which a listed manifest names", ref, lost)
					}
				})
			}
		})
	}
	t.Logf("removal outcomes: %v", outcomes)
	// Each outcome is a branch of removal; a table that stops reaching one
	// has stopped testing it.
	for _, o := range []string{"refused", "untagged", "untagged, another tag names it", "deleted", "deleted with descriptions of it"} {
		if outcomes[o] == 0 {
			t.Errorf("no removal in the table was %s", o)
		}
	}
}

// TestRemovingEveryReferenceEmptiesTheStore removes every reference of each
// shape, retrying while any removal succeeds, and requires collection to
// leave nothing behind.
func TestRemovingEveryReferenceEmptiesTheStore(t *testing.T) {
	ctx := context.Background()
	for _, sh := range collectorShapes() {
		t.Run(sh.name, func(t *testing.T) {
			dir, _ := buildInto(t, sh)
			for {
				s, err := Open(ctx, dir)
				if err != nil {
					t.Fatal(err)
				}
				refs := tagsIn(t, s)
				if len(refs) == 0 {
					break
				}
				progress := false
				var refused []string
				for _, ref := range refs {
					if _, err := s.Resolve(ctx, ref); err != nil {
						continue // taken along by an earlier removal
					}
					var held *HeldError
					switch err := s.Remove(ctx, ref); {
					case errors.As(err, &held):
						refused = append(refused, held.Error())
					case err != nil:
						t.Fatalf("removing %s: %v", ref, err)
					default:
						progress = true
					}
				}
				if !progress {
					t.Fatalf("removal refused for good: %v", refused)
				}
			}
			s := collectTwice(t, dir)
			if listed, err := s.indexManifests(); err != nil || len(listed) != 0 {
				t.Errorf("with every reference removed, the layout still lists %d manifests: %v", len(listed), err)
			}
			if left := presentBlobs(t, dir); len(left) != 0 {
				t.Errorf("with every reference removed, %d blobs are left", len(left))
			}
		})
	}
}

// followRefusals removes ref from the store at dir, first removing each
// reference a refusal names, recursively. It returns those references in
// order, or a reason when a refusal names one already waiting on it.
func followRefusals(t *testing.T, dir, ref string) (removed []string, cycle string) {
	t.Helper()
	ctx := context.Background()
	var chase func(r string, path []string) string
	chase = func(r string, path []string) string {
		for range 20 {
			s, err := Open(ctx, dir)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.Resolve(ctx, r); err != nil {
				return "" // taken along by an earlier removal
			}
			var held *HeldError
			switch err := s.Remove(ctx, r); {
			case err == nil:
				return ""
			case !errors.As(err, &held):
				t.Fatalf("removing %s: %v", r, err)
			}
			if slices.Contains(append(path, r), held.Holder) || slices.Contains(removed, held.Holder) {
				return fmt.Sprintf("%s names %s, which is waiting on it or already gone (path %v)", r, held.Holder, append(path, r))
			}
			if c := chase(held.Holder, append(path, r)); c != "" {
				return c
			}
			removed = append(removed, held.Holder)
		}
		return fmt.Sprintf("%s still refused after 20 holders", r)
	}
	return removed, chase(ref, nil)
}

// TestFollowingARefusalRemovesTheReference: removing what a refusal names,
// and what refusals of that name, ends in the removal asked for, and each
// reference removed on the way was needed: with it left in place and the
// others removed, the removal is still refused.
func TestFollowingARefusalRemovesTheReference(t *testing.T) {
	ctx := context.Background()
	refusals := 0
	for _, sh := range collectorShapes() {
		probe, _ := buildInto(t, sh)
		ps, err := Open(ctx, probe)
		if err != nil {
			t.Fatal(err)
		}
		for _, ref := range tagsIn(t, ps) {
			dir, _ := buildInto(t, sh)
			s, err := Open(ctx, dir)
			if err != nil {
				t.Fatal(err)
			}
			var held *HeldError
			if err := s.Remove(ctx, ref); !errors.As(err, &held) {
				continue
			}
			refusals++
			dir, _ = buildInto(t, sh)
			removed, cycle := followRefusals(t, dir, ref)
			if cycle != "" {
				t.Errorf("%s: removing %s: %s", sh.name, ref, cycle)
				continue
			}
			for i, needed := range removed {
				dir, _ := buildInto(t, sh)
				s, err := Open(ctx, dir)
				if err != nil {
					t.Fatal(err)
				}
				for j, h := range removed {
					if j != i {
						_ = s.Remove(ctx, h)
					}
				}
				if err := s.Remove(ctx, ref); !errors.As(err, &held) {
					t.Errorf("%s: removing %s named %s, which it did not need removed", sh.name, ref, needed)
				}
			}
		}
	}
	if refusals == 0 {
		t.Error("no removal in the table was refused")
	}
}

// TestHeldAgreesWithCollection: once a reference that is not a description
// is removed, Held says of what it named exactly what collection then does.
func TestHeldAgreesWithCollection(t *testing.T) {
	ctx := context.Background()
	asked := 0
	for _, sh := range collectorShapes() {
		probe, _ := buildInto(t, sh)
		ps, err := Open(ctx, probe)
		if err != nil {
			t.Fatal(err)
		}
		for _, ref := range tagsIn(t, ps) {
			if _, isDescription := describedBy(t, ps, ref); isDescription {
				continue
			}
			dir, _ := buildInto(t, sh)
			s, err := Open(ctx, dir)
			if err != nil {
				t.Fatal(err)
			}
			desc, err := s.Resolve(ctx, ref)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Remove(ctx, ref); err != nil {
				t.Fatal(err)
			}
			held, err := s.Held(ctx, desc)
			if err != nil {
				t.Fatal(err)
			}
			asked++
			collectTwice(t, dir)
			if kept := blobPresent(dir, desc.Digest); held != kept {
				t.Errorf("%s: after removing %s, Held says %v and collection kept it=%v", sh.name, ref, held, kept)
			}
		}
	}
	if asked == 0 {
		t.Error("Held was never asked")
	}
}

// TestRemovingWhatDescribesARemovedModelIsNeverRefused: once the store no
// longer holds a removed model whose manifest is present, nothing keeps its
// descriptions either, so rm can remove each.
func TestRemovingWhatDescribesARemovedModelIsNeverRefused(t *testing.T) {
	ctx := context.Background()
	removals := 0
	for _, sh := range collectorShapes() {
		probe, _ := buildInto(t, sh)
		ps, err := Open(ctx, probe)
		if err != nil {
			t.Fatal(err)
		}
		for _, ref := range tagsIn(t, ps) {
			if _, isDescription := describedBy(t, ps, ref); isDescription {
				continue
			}
			dir, _ := buildInto(t, sh)
			s, err := Open(ctx, dir)
			if err != nil {
				t.Fatal(err)
			}
			desc, err := s.Resolve(ctx, ref)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Remove(ctx, ref); err != nil {
				t.Fatal(err)
			}
			if held, err := s.Held(ctx, desc); err != nil || held {
				continue
			}
			for _, r := range tagsIn(t, s) {
				d, isDescription := describedBy(t, s, r)
				if !isDescription {
					continue
				}
				if h, err := s.readHead(ctx, d); err != nil || h.subject.Digest != desc.Digest {
					continue
				}
				if err := s.Remove(ctx, r); err != nil && !errors.Is(err, errdef.ErrNotFound) {
					t.Errorf("%s: after removing %s, removing %s: %v", sh.name, ref, r, err)
				}
				removals++
			}
		}
	}
	if removals == 0 {
		t.Error("no description of a removed model was removed")
	}
}
