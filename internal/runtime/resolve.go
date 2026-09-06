// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"fmt"
	"os/exec"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/aimd54/palan/internal/store"
)

// DefaultBinaryName is looked up in PATH when no runtime artifact is
// configured.
const DefaultBinaryName = "llama-server"

// Resolve locates a llama-server executable, in precedence order: the
// explicit runtime artifact ref (flag or config), then PATH. The returned
// string is an executable path.
//
// desc is the artifact the caller resolved ref to, and is what gets
// unpacked. Passing it rather than the name alone keeps the engine that was
// admitted and the engine that runs the same object.
func Resolve(ctx context.Context, st *store.Store, ref string, desc ocispec.Descriptor) (string, error) {
	if ref != "" {
		return Ensure(ctx, st, ref, desc)
	}
	if p, err := exec.LookPath(DefaultBinaryName); err == nil {
		return p, nil
	}
	return "", fmt.Errorf(
		"no llama-server available: pull a runtime artifact (`palan runtime pull REF` and set runtime.ref), or install llama-server in PATH")
}
