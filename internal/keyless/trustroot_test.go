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

// TestARootWhoseLogIdDisagreesWithItsKeyIsRefused is the check that keeps a
// trusted root from letting a bundle select a key by a name nothing
// verifies.
//
// A bundle names the log it claims to be in, and palan looks the key up by
// that name. If the file's stated name were believed rather than derived
// from the key, an edited root could point a well-known log's name at a key
// somebody else holds, and every signature that log ever recorded would be
// checkable against the wrong key.
func TestARootWhoseLogIdDisagreesWithItsKeyIsRefused(t *testing.T) {
	edited := mutateRoot(t, func(r map[string]any) {
		tlog := r["tlogs"].([]any)[0].(map[string]any)
		tlog["logId"] = map[string]any{
			"keyId": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		}
	})

	_, err := LoadTrustedRoot(edited)
	if err == nil {
		t.Fatal("a trusted root whose log id does not match its key loaded")
	}
	if !strings.Contains(err.Error(), "hashes to") {
		t.Errorf("refusal does not name the disagreement: %v", err)
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
