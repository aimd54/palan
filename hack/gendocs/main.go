// Copyright The moci Authors
// SPDX-License-Identifier: Apache-2.0

// Command gendocs regenerates the CLI reference (docs/reference) from the
// cobra command tree. Run via `make docs`.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"

	"github.com/aimd54/moci/internal/cli"
)

func main() {
	const dir = "docs/reference"
	root := cli.New()
	disableAutoGenTag(root)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := doc.GenMarkdownTree(root, dir); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("CLI reference regenerated in", dir)
}

func disableAutoGenTag(cmd *cobra.Command) {
	cmd.DisableAutoGenTag = true
	for _, c := range cmd.Commands() {
		disableAutoGenTag(c)
	}
}
