// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package ui

import (
	"bytes"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
)

// TestZeroStylesRenderUnchanged is the assumption the whole package rests on:
// when styling is off, styling a string is a no-op. If it ever stops holding,
// every command silently starts writing escape sequences into pipes, so it is
// asserted here rather than trusted.
func TestZeroStylesRenderUnchanged(t *testing.T) {
	var s Styles
	inputs := []string{
		"",
		"plain",
		"registry.internal/llm/qwen3:8b-q4",
		"two\nlines",
		"trailing space ",
		"  leading space",
		"unicode: café 日本語 🤖",
		"already styled: \x1b[31mred\x1b[0m",
		strings.Repeat("wide ", 40),
	}
	styles := map[string]func(...string) string{
		"Header":  s.Header.Render,
		"Key":     s.Key.Render,
		"Dim":     s.Dim.Render,
		"Accent":  s.Accent.Render,
		"Success": s.Success.Render,
		"Warn":    s.Warn.Render,
		"Error":   s.Error.Render,
	}
	for name, render := range styles {
		for _, in := range inputs {
			if got := render(in); got != in {
				t.Errorf("%s.Render(%q) = %q, want the input unchanged", name, in, got)
			}
		}
	}
}

// TestNewReturnsZeroStylesWhenDisabled ties New to the property above: a
// destination that cannot show styling gets the styles that change nothing.
func TestNewReturnsZeroStylesWhenDisabled(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("TERM", "xterm-256color")
	SetNoColor(false)
	t.Cleanup(func() { SetNoColor(false) })

	// A buffer is not a terminal, which is the case every pipeline hits.
	if got := New(&bytes.Buffer{}); !reflect.DeepEqual(got, Styles{}) {
		t.Error("a non-terminal destination must get styles that render unchanged")
	}
}

func TestEnabled(t *testing.T) {
	tests := []struct {
		name    string
		noColor bool
		env     map[string]string
		w       io.Writer
		want    bool
	}{
		{
			name: "buffer is never a terminal",
			w:    &bytes.Buffer{},
			want: false,
		},
		{
			name: "NO_COLOR set to anything disables",
			env:  map[string]string{"NO_COLOR": "1"},
			w:    os.Stdout,
			want: false,
		},
		{
			name: "NO_COLOR set to zero still disables, the convention is presence",
			env:  map[string]string{"NO_COLOR": "0"},
			w:    os.Stdout,
			want: false,
		},
		{
			name: "TERM=dumb disables",
			env:  map[string]string{"TERM": "dumb"},
			w:    os.Stdout,
			want: false,
		},
		{
			name:    "--no-color disables",
			noColor: true,
			w:       os.Stdout,
			want:    false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("NO_COLOR", "")
			t.Setenv("TERM", "xterm-256color")
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			SetNoColor(tc.noColor)
			t.Cleanup(func() { SetNoColor(false) })

			if got := Enabled(tc.w); got != tc.want {
				t.Errorf("Enabled() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestStylesActuallyStyleWhenEnabled guards the other direction. Without it a
// mistake that disabled styling everywhere would pass every test above, since
// they all assert that output is unchanged.
func TestStylesActuallyStyleWhenEnabled(t *testing.T) {
	s := enabledStyles()
	for name, got := range map[string]string{
		"Dim":     s.Dim.Render("x"),
		"Accent":  s.Accent.Render("x"),
		"Error":   s.Error.Render("x"),
		"Success": s.Success.Render("x"),
		"Warn":    s.Warn.Render("x"),
		"Key":     s.Key.Render("x"),
	} {
		if got == "x" {
			t.Errorf("%s produced no styling when styling was requested", name)
		}
		if !strings.Contains(got, "x") {
			t.Errorf("%s dropped the text it was given: %q", name, got)
		}
	}
}
