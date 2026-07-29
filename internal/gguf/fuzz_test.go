// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package gguf

import (
	"bytes"
	"testing"

	"github.com/aimd54/palan/internal/gguf/gguftest"
)

// FuzzRead exercises the header parser against arbitrary bytes. GGUF files
// arrive from registries and from whatever a user points `pack` at, so the
// parser must reject malformed input rather than panic, over-allocate, or
// loop forever. The bounds in this package (maxKVCount, maxKeyLen,
// maxStringLen, maxArrayLen) are what this target is probing.
func FuzzRead(f *testing.F) {
	f.Add(gguftest.TinyModel("llama", "tiny", "15M", 2048, 15, []byte("weights")))
	f.Add([]byte("GGUF"))
	f.Add([]byte("not a gguf file at all"))
	f.Add([]byte{})
	// Valid magic and version, then a KV count that must be refused rather
	// than turned into an allocation.
	f.Add([]byte("GGUF\x03\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\xff\xff\xff\xff\xff\xff\xff\xff"))

	f.Fuzz(func(t *testing.T, data []byte) {
		info, err := Read(bytes.NewReader(data))
		if err != nil {
			return // rejecting bad input is the expected outcome
		}
		if info == nil {
			t.Fatal("Read returned nil info with nil error")
		}
		// A successful parse must produce a version the package claims to
		// support; anything else means a bound or check was bypassed.
		if info.Version < 2 || info.Version > 3 {
			t.Fatalf("accepted unsupported version %d", info.Version)
		}
	})
}
