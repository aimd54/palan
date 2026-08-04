// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestRefOrPickPrefersTheArgument: a command given a reference must never
// consult the store or the terminal for one.
func TestRefOrPickPrefersTheArgument(t *testing.T) {
	cmd := &cobra.Command{Use: "run"}
	got, err := refOrPick(context.Background(), cmd, []string{"llm/tiny:v1"}, "pick")
	if err != nil {
		t.Fatalf("refOrPick with an argument returned an error: %v", err)
	}
	if got != "llm/tiny:v1" {
		t.Errorf("refOrPick = %q, want the argument it was given", got)
	}
}

// TestRefOrPickWithoutATerminalFails is the guard that keeps scripts working.
// Go tests run with stdin redirected, so this exercises the real path a
// pipeline or a CI job takes: the missing argument has to come back as an
// error rather than as a prompt nobody can answer.
//
// If this ever starts hanging instead of failing, that is the defect it
// exists to catch.
func TestRefOrPickWithoutATerminalFails(t *testing.T) {
	cmd := &cobra.Command{Use: "run"}
	_, err := refOrPick(context.Background(), cmd, nil, "pick")
	if err == nil {
		t.Fatal("a missing reference with no terminal must be an error")
	}
	if !strings.Contains(err.Error(), "requires a model reference") {
		t.Errorf("error = %q, want it to name what is missing", err)
	}
	if errors.Is(err, errPickerCancelled) {
		t.Error("the cancellation sentinel leaked to the caller instead of a usable message")
	}
}

// TestPickModelWithoutATerminalCancels pins the layer below: without a
// terminal the picker declines rather than trying to read keys.
func TestPickModelWithoutATerminalCancels(t *testing.T) {
	_, err := pickModel(context.Background(), "pick")
	if !errors.Is(err, errPickerCancelled) {
		t.Errorf("pickModel without a terminal = %v, want errPickerCancelled", err)
	}
}
