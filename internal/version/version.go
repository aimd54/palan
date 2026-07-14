// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

// Package version exposes build-time version information stamped via ldflags.
package version

import "fmt"

// Stamped at build time via -ldflags (see Makefile and .goreleaser.yaml).
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// Version returns the semantic version of this build.
func Version() string { return version }

// String returns a human-readable version line.
func String() string {
	return fmt.Sprintf("palan %s (commit %s, built %s)", version, commit, date)
}
