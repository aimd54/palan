// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package keyless

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func realRootJSON(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "trusted-root-public-good.json"))
	if err != nil {
		t.Fatalf("reading the trusted root fixture: %v", err)
	}
	return raw
}

// mutateRoot edits a trusted root as JSON, so a test states the one thing
// it changed.
func mutateRoot(t *testing.T, edit func(map[string]any)) []byte {
	t.Helper()
	var r map[string]any
	if err := json.Unmarshal(realRootJSON(t), &r); err != nil {
		t.Fatal(err)
	}
	edit(r)
	out, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestARealTrustedRootLoads is the control the refusals below need, and it
// pins the shape palan reads out of a file it did not write.
func TestARealTrustedRootLoads(t *testing.T) {
	root, err := LoadTrustedRoot(realRootJSON(t))
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	if len(root.authorities) == 0 {
		t.Error("the loaded root names no certificate authority")
	}
	// Named by the identifier a bundle uses to select it, which is what
	// makes the lookup in verification work at all.
	const publicGood = "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b959180 1d"
	want := strings.ReplaceAll(publicGood, " ", "")
	if _, ok := root.logs[want]; !ok {
		t.Errorf("the loaded root does not name transparency log %s; it has %d log(s)",
			want, len(root.logs))
	}
}

// TestARootNamesALogByWhateverItCallsItself covers the two ways a
// transparency log is named.
//
// A log of the original kind is named by the SHA-256 of its key. A tiled
// log names itself by a construction over its origin as well, so its
// stated identifier is not that hash. Deriving the identifier and refusing
// anything else made the current public Sigstore root unloadable, and an
// operator who pins that root could then verify nothing at all.
//
// The stated identifier is believed because the root is the operator's own
// pinned file. A tampered root is not a threat this can defend against:
// the key it names would be tampered with too.
func TestARootNamesALogByWhateverItCallsItself(t *testing.T) {
	stated := "cf1199155bddd051268d1f16ac5c0c75c009f6fb5a63f4177f8e18d7051e3fa0"
	raw, err := os.ReadFile(filepath.Join("testdata", "trusted-root-with-tiled-log.json"))
	if err != nil {
		t.Fatalf("reading the tiled-log root fixture: %v", err)
	}

	root, err := LoadTrustedRoot(raw)
	if err != nil {
		t.Fatalf("a trusted root carrying a tiled log did not load: %v", err)
	}
	if _, ok := root.logs[stated]; !ok {
		t.Errorf("the root does not name the tiled log %s; it holds %d log id(s)",
			stated, len(root.logs))
	}
	// The other log in the same file names itself the original way, so both
	// constructions have to work at once.
	const original = "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"
	if _, ok := root.logs[original]; !ok {
		t.Errorf("the root does not name log %s", original)
	}
}

// TestTheCurrentPublicRootVerifiesARealSignature is the check that would
// have caught the tiled-log refusal before it shipped: material palan did
// not produce, held against a root captured from the live Sigstore
// instance rather than from this repository's own history.
func TestTheCurrentPublicRootVerifiesARealSignature(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "trusted-root-with-tiled-log.json"))
	if err != nil {
		t.Fatalf("reading the tiled-log root fixture: %v", err)
	}
	root, err := LoadTrustedRoot(raw)
	if err != nil {
		t.Fatalf("loading the current public root: %v", err)
	}
	bundle, _ := loadFixtures(t)

	got, err := Verify(bundle, fixtureArtifact, root, fixtureIdentity())
	if err != nil {
		t.Fatalf("a real signature does not verify against the current public root: %v", err)
	}
	if got.Subject != fixtureSubject {
		t.Errorf("subject = %q, want %q", got.Subject, fixtureSubject)
	}
}

// TestARootNamingNoAuthorityIsRefused: such a file verifies no certificate,
// so every signature checked against it would refuse for a reason pointing
// at the signature instead of at the file.
func TestARootNamingNoAuthorityIsRefused(t *testing.T) {
	edited := mutateRoot(t, func(r map[string]any) {
		delete(r, "certificateAuthorities")
	})

	_, err := LoadTrustedRoot(edited)
	if err == nil {
		t.Fatal("a trusted root naming no certificate authority loaded")
	}
	if !strings.Contains(err.Error(), "certificate authority") {
		t.Errorf("refusal does not say what is missing: %v", err)
	}
}

// TestARootNamingNoLogIsRefused is the same argument for the other half:
// with no log key there is no inclusion proof anything can be checked
// against.
func TestARootNamingNoLogIsRefused(t *testing.T) {
	edited := mutateRoot(t, func(r map[string]any) {
		delete(r, "tlogs")
	})

	_, err := LoadTrustedRoot(edited)
	if err == nil {
		t.Fatal("a trusted root naming no transparency log loaded")
	}
	if !strings.Contains(err.Error(), "transparency log") {
		t.Errorf("refusal does not say what is missing: %v", err)
	}
}

func TestAnUnreadableCertificateInTheRootIsRefused(t *testing.T) {
	edited := mutateRoot(t, func(r map[string]any) {
		ca := r["certificateAuthorities"].([]any)[0].(map[string]any)
		chain := ca["certChain"].(map[string]any)
		chain["certificates"] = []any{map[string]any{"rawBytes": "bm90IGEgY2VydGlmaWNhdGU="}}
	})

	if _, err := LoadTrustedRoot(edited); err == nil {
		t.Fatal("a trusted root carrying an unreadable certificate loaded")
	}
}

func TestAnUnreadableLogKeyInTheRootIsRefused(t *testing.T) {
	edited := mutateRoot(t, func(r map[string]any) {
		tlog := r["tlogs"].([]any)[0].(map[string]any)
		tlog["publicKey"].(map[string]any)["rawBytes"] = "bm90IGEga2V5"
		delete(tlog, "logId")
	})

	if _, err := LoadTrustedRoot(edited); err == nil {
		t.Fatal("a trusted root carrying an unreadable log key loaded")
	}
}

// TestAWindowIncludesItsOwnEnds pins behaviour nothing else states. A
// service's trust window is compared against the moment a signature was
// logged, and whether the endpoints count decides the verdict for a
// signature made in the second a key was rotated.
func TestAWindowIncludesItsOwnEnds(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)
	w := window{start: &start, end: &end}

	for _, tc := range []struct {
		name string
		at   time.Time
		want bool
	}{
		{"the first instant", start, true},
		{"the last instant", end, true},
		{"one second before", start.Add(-time.Second), false},
		{"one second after", end.Add(time.Second), false},
		{"the middle", start.Add(24 * time.Hour), true},
	} {
		if got := w.covers(tc.at); got != tc.want {
			t.Errorf("%s: covers = %v, want %v", tc.name, got, tc.want)
		}
	}

	// An absent bound means unbounded, which is how a live service is
	// recorded, so a window with no end must not stop covering.
	open := window{start: &start}
	if !open.covers(start.Add(100 * 365 * 24 * time.Hour)) {
		t.Error("a window with no end stopped covering")
	}
	if (window{}).covers(start) != true {
		t.Error("a window with no bounds at all does not cover everything")
	}
}
