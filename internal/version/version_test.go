// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package version

import "testing"

func TestResolve(t *testing.T) {
	tests := []struct {
		name    string
		stamped string
		module  string
		want    string
	}{
		{"ldflags stamp wins", "v0.1.0", "v0.2.0", "v0.1.0"},
		{"go install falls back to module version", "dev", "v0.1.0", "v0.1.0"},
		{"in-tree build stays dev", "dev", "(devel)", "dev"},
		{"missing module info stays dev", "dev", "", "dev"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolve(tt.stamped, tt.module); got != tt.want {
				t.Errorf("resolve(%q, %q) = %q, want %q", tt.stamped, tt.module, got, tt.want)
			}
		})
	}
}
