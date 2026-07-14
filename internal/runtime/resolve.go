// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/aimd54/palan/internal/store"
)

// DefaultBinaryName is looked up in PATH when no runtime artifact is
// configured.
const DefaultBinaryName = "llama-server"

// Resolve locates a llama-server executable, in precedence order: the
// explicit runtime artifact ref (flag or config), then PATH. The returned
// string is an executable path.
func Resolve(ctx context.Context, st *store.Store, ref string) (string, error) {
	if ref != "" {
		return Ensure(ctx, st, ref)
	}
	if p, err := exec.LookPath(DefaultBinaryName); err == nil {
		return p, nil
	}
	return "", fmt.Errorf(
		"no llama-server available: pull a runtime artifact (`palan runtime pull REF` and set runtime.ref), or install llama-server in PATH")
}
