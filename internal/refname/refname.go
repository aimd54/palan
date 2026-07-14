// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

// Package refname normalizes model references.
//
// palan follows the Docker/OCI convention: a reference is
// [registry-host/]repository[:tag|@digest]. The first path component is
// treated as a registry host iff it contains a dot or colon or equals
// "localhost"; otherwise the configured default registry is prepended.
package refname

import (
	"fmt"
	"strings"

	"oras.land/oras-go/v2/registry"
)

// DefaultTag is applied when a reference names neither tag nor digest.
const DefaultTag = "latest"

// Parse normalizes raw into a fully-qualified reference. When raw has no
// registry host, defaultRegistry is applied; if that is empty too, Parse
// fails rather than guessing.
func Parse(raw, defaultRegistry string) (registry.Reference, error) {
	if raw == "" {
		return registry.Reference{}, fmt.Errorf("empty reference")
	}
	name := raw
	if !hasRegistryHost(raw) {
		if defaultRegistry == "" {
			return registry.Reference{}, fmt.Errorf(
				"reference %q has no registry host and no default registry is configured (set registry.default in the config or use a full reference)", raw)
		}
		name = defaultRegistry + "/" + raw
	}
	ref, err := registry.ParseReference(name)
	if err != nil {
		return registry.Reference{}, fmt.Errorf("invalid reference %q: %w", raw, err)
	}
	if ref.Reference == "" {
		ref.Reference = DefaultTag
	}
	return ref, nil
}

// hasRegistryHost reports whether the first path component of raw looks like
// a registry host (Docker convention).
func hasRegistryHost(raw string) bool {
	i := strings.IndexByte(raw, '/')
	if i <= 0 {
		return false
	}
	first := raw[:i]
	return strings.ContainsAny(first, ".:") || first == "localhost"
}
