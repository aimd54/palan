// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"

	"charm.land/bubbles/v2/list"
	tea "charm.land/bubbletea/v2"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/aimd54/palan/internal/signing"
	"github.com/aimd54/palan/internal/store"
)

// errPickerCancelled reports that the operator chose nothing. It is not a
// failure, so callers return it unwrapped and exit quietly.
var errPickerCancelled = errors.New("no model chosen")

// pickerHeight is the list's height in rows. Small enough to sit inside a
// modest terminal, large enough to show a useful window of a real store.
const pickerHeight = 14

// modelItem is one model in the picker.
type modelItem struct {
	ref  string
	desc string
}

func (i modelItem) Title() string       { return i.ref }
func (i modelItem) Description() string { return i.desc }
func (i modelItem) FilterValue() string { return i.ref }

// pickerModel wraps the list so Enter and Escape mean choose and cancel.
type pickerModel struct {
	list   list.Model
	chosen string
}

func (m pickerModel) Init() tea.Cmd { return nil }

func (m pickerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.list.SetWidth(msg.Width)
		return m, nil
	case tea.KeyPressMsg:
		// While filtering, these keys belong to the filter: escape clears it
		// and enter accepts it, which the list handles itself.
		if m.list.FilterState() != list.Filtering {
			switch msg.String() {
			case "ctrl+c", "esc", "q":
				return m, tea.Quit
			case "enter":
				if it, ok := m.list.SelectedItem().(modelItem); ok {
					m.chosen = it.ref
				}
				return m, tea.Quit
			}
		}
	}
	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m pickerModel) View() tea.View { return tea.NewView(m.list.View()) }

// pickModel asks the operator to choose a model from the local store.
//
// It is only ever reached when a command was given no reference and stdin is a
// terminal, so a script that forgets an argument still gets an error rather
// than a prompt it cannot answer.
func pickModel(ctx context.Context, title string) (string, error) {
	in, out := os.Stdin, os.Stdout
	if !term.IsTerminal(int(in.Fd())) || !term.IsTerminal(int(out.Fd())) {
		return "", errPickerCancelled
	}

	items, err := storeItems(ctx)
	if err != nil {
		return "", err
	}
	if len(items) == 0 {
		return "", errors.New("no models in the local store: pull or pack one first")
	}

	width, height, err := term.GetSize(int(out.Fd()))
	if err != nil || width <= 0 {
		width, height = 80, 24
	}
	if height > pickerHeight {
		height = pickerHeight
	}

	l := list.New(items, list.NewDefaultDelegate(), width, height)
	l.Title = title
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(true)

	final, err := tea.NewProgram(pickerModel{list: l}, tea.WithContext(ctx),
		tea.WithInput(in), tea.WithOutput(out)).Run()
	if err != nil {
		return "", err
	}
	chosen := final.(pickerModel).chosen
	if chosen == "" {
		return "", errPickerCancelled
	}
	return chosen, nil
}

// refOrPick returns the reference the command was given, or opens the picker
// when it was given none.
//
// A command reaching here with no argument at a terminal is treated as a
// question rather than a mistake. Anywhere else the missing argument is still
// an error, and cobra's own message is the right one to show.
func refOrPick(ctx context.Context, cmd *cobra.Command, args []string, title string) (string, error) {
	if len(args) > 0 {
		return args[0], nil
	}
	ref, err := pickModel(ctx, title)
	if errors.Is(err, errPickerCancelled) {
		// Nothing was chosen and nothing went wrong. Say what is missing in
		// the terms the command documents.
		return "", fmt.Errorf("%s requires a model reference", cmd.Name())
	}
	if err != nil {
		return "", err
	}
	return ref, nil
}

// storeItems lists the local store as picker entries, leaving out signatures
// and attestations for the same reason `ls` does: they are attached to a
// model rather than being one.
func storeItems(ctx context.Context) ([]list.Item, error) {
	st, err := openStore(ctx)
	if err != nil {
		return nil, err
	}
	unlock, err := st.RLock(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()

	entries, err := st.List(ctx)
	if err != nil {
		return nil, err
	}
	items := make([]list.Item, 0, len(entries))
	for _, e := range entries {
		if signing.IsSigTag(e.Ref) || signing.IsAttTag(e.Ref) {
			continue
		}
		items = append(items, modelItem{ref: e.Ref, desc: pickerDescription(ctx, st, e)})
	}
	return items, nil
}

// pickerDescription is the second line of an entry: enough to tell two
// quantisations of the same model apart.
func pickerDescription(ctx context.Context, st *store.Store, e store.Entry) string {
	row := describeRef(ctx, st.OCI(), e.Ref, e.Descriptor)
	desc := humanBytes(row.Size)
	if row.Quant != "" {
		desc += "  " + row.Quant
	}
	if row.Params != "" {
		desc += "  " + row.Params
	}
	return fmt.Sprintf("%s  %s", row.Kind, desc)
}
