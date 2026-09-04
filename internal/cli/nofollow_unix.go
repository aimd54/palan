// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import "syscall"

// openNoFollow makes an open fail rather than follow a symlink at the final
// path component, which closes the gap between checking what a name points
// at and writing to it.
const openNoFollow = syscall.O_NOFOLLOW
