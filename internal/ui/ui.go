// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

// Package ui decides whether terminal output is styled, and how.
//
// It is the only package that imports a styling library, so the rule that
// governs palan's output lives in one file rather than in every command:
// the machine-readable forms are the interface, and styling is decoration.
// `--json`, exit codes, and plain text carry the meaning; colour never does.
//
// When styling is off, every style renders its input unchanged. Call sites
// therefore style unconditionally and stay readable, and "the plain output
// did not move" is something a test proves rather than something each
// command has to remember (see internal/cli/render_test.go).
package ui

import (
	"io"
	"os"

	"charm.land/lipgloss/v2"
	"golang.org/x/term"
)

// noColor is set from --no-color. It is a package variable because the flag
// is parsed once, at the root, and read by every command below it.
var noColor bool

// SetNoColor records the --no-color flag. Call it before rendering anything.
func SetNoColor(v bool) { noColor = v }

// Enabled reports whether w should receive styled output.
//
// Three ways to say no, all of them honoured: the --no-color flag, the
// NO_COLOR convention (any non-empty value), and a terminal that has told us
// it cannot render anything (TERM=dumb), plus the obvious case of w not being
// a terminal at all, which covers pipes, files, and CI.
func Enabled(w io.Writer) bool {
	if noColor || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}

// Styles is the palette. A zero Styles renders everything unchanged, which is
// exactly what a non-terminal destination needs, so New can return it as-is
// rather than every caller branching.
type Styles struct {
	// Header labels a table's column row.
	Header lipgloss.Style
	// Key labels a field in a key/value listing.
	Key lipgloss.Style
	// Dim recedes: digests, sizes, anything present for reference rather
	// than for reading.
	Dim lipgloss.Style
	// Accent marks the identifier a reader is scanning for, such as a
	// model reference.
	Accent lipgloss.Style
	// Success, Warn and Error mark outcomes. They never carry the outcome
	// on their own: the words they wrap have to say it too.
	Success lipgloss.Style
	Warn    lipgloss.Style
	Error   lipgloss.Style
}

// New returns the styles appropriate for w.
func New(w io.Writer) Styles {
	if !Enabled(w) {
		return Styles{}
	}
	return enabledStyles()
}

// enabledStyles is the palette used when a terminal can show it. Split out so
// a test can exercise it without holding a real terminal open.
func enabledStyles() Styles {
	return Styles{
		Header:  lipgloss.NewStyle().Bold(true),
		Key:     lipgloss.NewStyle().Bold(true),
		Dim:     lipgloss.NewStyle().Foreground(lipgloss.BrightBlack),
		Accent:  lipgloss.NewStyle().Foreground(lipgloss.Cyan),
		Success: lipgloss.NewStyle().Foreground(lipgloss.Green),
		Warn:    lipgloss.NewStyle().Foreground(lipgloss.Yellow),
		Error:   lipgloss.NewStyle().Foreground(lipgloss.Red).Bold(true),
	}
}
