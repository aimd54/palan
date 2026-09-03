// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package keyless

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// mutateBundle edits a bundle as JSON and hands back the result, so a test
// can state the one thing it changed rather than carry a second fixture.
func mutateBundle(t *testing.T, bundle []byte, edit func(map[string]any)) []byte {
	t.Helper()
	var b map[string]any
	if err := json.Unmarshal(bundle, &b); err != nil {
		t.Fatalf("decoding the bundle: %v", err)
	}
	edit(b)
	out, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("re-encoding the bundle: %v", err)
	}
	return out
}

// firstTlogEntry reaches the log entry every test in this file edits.
func firstTlogEntry(t *testing.T, b map[string]any) map[string]any {
	t.Helper()
	material, ok := b["verificationMaterial"].(map[string]any)
	if !ok {
		t.Fatal("the bundle fixture has no verificationMaterial")
	}
	entries, ok := material["tlogEntries"].([]any)
	if !ok || len(entries) == 0 {
		t.Fatal("the bundle fixture has no tlogEntries")
	}
	entry, ok := entries[0].(map[string]any)
	if !ok {
		t.Fatal("the bundle fixture's first tlogEntry is not an object")
	}
	return entry
}

// flipFirstByte changes one bit of a base64 value, which is the smallest
// edit that a hash comparison must notice.
func flipFirstByte(t *testing.T, b64 string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("decoding %q: %v", b64, err)
	}
	if len(raw) == 0 {
		t.Fatalf("%q decodes to nothing", b64)
	}
	raw[0] ^= 0x01
	return base64.StdEncoding.EncodeToString(raw)
}

// certExpiry reports when the fixture's signing certificate stopped being
// valid, so a test can assert that verification is not simply passing
// because the certificate is still live.
func certExpiry(t *testing.T, bundle []byte) time.Time {
	t.Helper()
	var b struct {
		VerificationMaterial struct {
			Certificate struct {
				RawBytes []byte `json:"rawBytes"`
			} `json:"certificate"`
		} `json:"verificationMaterial"`
	}
	if err := json.Unmarshal(bundle, &b); err != nil {
		t.Fatalf("decoding the bundle: %v", err)
	}
	certs, err := parseDER(b.VerificationMaterial.Certificate.RawBytes)
	if err != nil {
		t.Fatalf("parsing the fixture certificate: %v", err)
	}
	return certs.NotAfter
}
