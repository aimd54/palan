// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

// openNoFollow has no Windows equivalent, so the Lstat beside it is the
// whole guard there. palan releases Linux and macOS builds; this exists so
// the tree still compiles for Windows rather than to make a claim about it.
const openNoFollow = 0
