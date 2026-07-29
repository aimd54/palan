// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package modelspec

import "testing"

// FuzzParseServeDefaults exercises the annotation decoder. The value comes
// off a remote artifact's manifest, so a hostile registry controls it
// entirely; decoding must fail cleanly rather than panic.
func FuzzParseServeDefaults(f *testing.F) {
	f.Add(`{"ctx":8192,"ngl":99}`)
	f.Add(`{"ctx":-1}`)
	f.Add(`{"flags":["--foo","--bar"]}`)
	f.Add(`{"unknown":1}`)
	f.Add(`{}`)
	f.Add(``)
	f.Add(`{"ctx":99999999999999999999999999}`)

	f.Fuzz(func(t *testing.T, s string) {
		d, err := ParseServeDefaults(s)
		if err != nil {
			return // rejecting bad input is the expected outcome
		}
		// Anything that decodes must re-encode, since palan writes these
		// values back out at pack time.
		if _, err := d.Encode(); err != nil {
			t.Fatalf("decoded %q but could not re-encode: %v", s, err)
		}
	})
}
