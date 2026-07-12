// Copyright The moci Authors
// SPDX-License-Identifier: Apache-2.0

// Command moci distributes and serves GGUF models as OCI artifacts.
// See docs/design/oci-llm-distribution.md for the design.
package main

import (
	"fmt"
	"os"

	"github.com/aimd54/moci/internal/version"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println(version.String())
		return
	}
	fmt.Fprintln(os.Stderr, "moci: command surface not implemented yet; see docs/design/oci-llm-distribution.md")
	os.Exit(1)
}
