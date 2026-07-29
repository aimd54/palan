// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

// Command palan distributes and serves GGUF models as OCI artifacts.
// See docs/architecture.md for how the pieces fit together.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/aimd54/palan/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Execute(ctx)
	stop()
	os.Exit(code)
}
