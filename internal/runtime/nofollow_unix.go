// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package runtime

import "syscall"

// openNoFollow makes an open fail rather than follow a symlink at the final
// path component, closing the interval between checking what a name points
// at and reading it.
const openNoFollow = syscall.O_NOFOLLOW
