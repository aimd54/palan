// Copyright The moci Authors
// SPDX-License-Identifier: Apache-2.0

// Command moci distributes and serves GGUF models as OCI artifacts.
// See docs/design/oci-llm-distribution.md for the design.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/aimd54/moci/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Execute(ctx)
	stop()
	os.Exit(code)
}
