// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

// Package version exposes build-time version information stamped via ldflags.
package version

import (
	"fmt"
	"runtime/debug"
)

// Stamped at build time via -ldflags (see Makefile and .goreleaser.yaml).
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// Version returns the semantic version of this build. Release builds are
// stamped via ldflags; unstamped builds (`go install <module>@<version>`)
// fall back to the module version the Go toolchain recorded.
func Version() string {
	mod := ""
	if bi, ok := debug.ReadBuildInfo(); ok {
		mod = bi.Main.Version
	}
	return resolve(version, mod)
}

// resolve picks the ldflags-stamped version unless it is the "dev" default,
// in which case a usable module version wins. "(devel)" is what the
// toolchain records for in-tree builds and is no better than "dev".
func resolve(stamped, module string) string {
	if stamped != "dev" {
		return stamped
	}
	if module != "" && module != "(devel)" {
		return module
	}
	return stamped
}

// String returns a human-readable version line.
func String() string {
	return fmt.Sprintf("palan %s (commit %s, built %s)", Version(), commit, date)
}
