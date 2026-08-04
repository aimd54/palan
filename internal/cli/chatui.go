// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"charm.land/bubbles/v2/spinner"
	"charm.land/bubbles/v2/textarea"
	tea "charm.land/bubbletea/v2"
	"charm.land/glamour/v2"
	"charm.land/glamour/v2/styles"
	"charm.land/lipgloss/v2"

	"github.com/aimd54/palan/internal/ui"
)

// streamTailLines caps how much of an in-flight reply is shown while it
// streams. The finished reply is printed in full; this only bounds the part
// that is being redrawn on every token, which the terminal cannot scroll.
const streamTailLines = 12

// chatModel drives the interactive chat.
//
// It renders inline rather than taking over the screen, so finished turns are
// pushed into the terminal's own scrollback and the conversation is still
// there after palan exits. Only the prompt, and whatever is currently
// streaming, occupy the live area.
type chatModel struct {
	ctx     context.Context
	baseURL string
	model   string

	input    textarea.Model
	spin     spinner.Model
	renderer *glamour.TermRenderer
	styles   ui.Styles

	history []chatMessage

	streaming bool
	raw       strings.Builder
	started   time.Time
	deltas    int

	deltaCh chan string
	doneCh  chan chatResult

	width int
	quit  bool
}

type (
	// chatDelta is one chunk of a reply as it arrives.
	chatDelta string
	// chatResult ends a turn, successfully or otherwise.
	chatResult struct {
		reply string
		err   error
	}
)

func newChatModel(ctx context.Context, baseURL, model string, s ui.Styles, width int) (*chatModel, error) {
	ta := textarea.New()
	ta.Placeholder = "Ask something. /bye to leave."
	ta.ShowLineNumbers = false
	ta.SetHeight(1)
	ta.SetWidth(width)
	ta.Focus()

	// glamour has no automatic light/dark detection, so dark is the default
	// and GLAMOUR_STYLE overrides it, which is the variable its users
	// already know.
	style := styles.DarkStyle
	if env := glamourStyleFromEnv(); env != "" {
		style = env
	}
	r, err := glamour.NewTermRenderer(
		glamour.WithStandardStyle(style),
		glamour.WithWordWrap(width),
	)
	if err != nil {
		return nil, fmt.Errorf("preparing the markdown renderer: %w", err)
	}

	sp := spinner.New()
	sp.Spinner = spinner.Dot

	return &chatModel{
		ctx:      ctx,
		baseURL:  baseURL,
		model:    model,
		input:    ta,
		spin:     sp,
		renderer: r,
		styles:   s,
		width:    width,
	}, nil
}

func (m *chatModel) Init() tea.Cmd {
	return textarea.Blink
}

// glamourStyleFromEnv returns the style named by GLAMOUR_STYLE, the variable
// glamour's users already set, or "" to accept the default.
func glamourStyleFromEnv() string {
	return os.Getenv("GLAMOUR_STYLE")
}

func (m *chatModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.input.SetWidth(msg.Width)
		return m, nil

	case tea.KeyPressMsg:
		return m.onKey(msg)

	case chatDelta:
		m.deltas++
		m.raw.WriteString(string(msg))
		return m, m.awaitStream()

	case chatResult:
		return m.onReply(msg)

	case spinner.TickMsg:
		if !m.streaming {
			return m, nil
		}
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m *chatModel) onKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "ctrl+d":
		m.quit = true
		return m, tea.Quit
	case "enter":
		if m.streaming {
			return m, nil // a turn is already in flight
		}
		line := strings.TrimSpace(m.input.Value())
		if line == "" {
			return m, nil
		}
		if line == "/bye" {
			m.quit = true
			return m, tea.Quit
		}
		m.input.Reset()
		return m, m.send(line)
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

// send starts a turn and returns the commands that echo the prompt, start the
// spinner, and begin waiting on the stream.
func (m *chatModel) send(line string) tea.Cmd {
	m.history = append(m.history, chatMessage{Role: "user", Content: line})
	m.streaming = true
	m.raw.Reset()
	m.deltas = 0
	m.started = time.Now()
	m.deltaCh = make(chan string, 64)
	m.doneCh = make(chan chatResult, 1)

	deltas, done := m.deltaCh, m.doneCh
	history := append([]chatMessage(nil), m.history...)
	go func() {
		reply, err := streamChat(m.ctx, m.baseURL, m.model, history, channelWriter{deltas})
		close(deltas)
		done <- chatResult{reply: reply, err: err}
	}()

	return tea.Batch(
		tea.Println(m.styles.Accent.Render("› "+line)),
		m.spin.Tick,
		m.awaitStream(),
	)
}

// awaitStream blocks in a command until the next delta or the end of the turn.
func (m *chatModel) awaitStream() tea.Cmd {
	deltas, done := m.deltaCh, m.doneCh
	return func() tea.Msg {
		if d, ok := <-deltas; ok {
			return chatDelta(d)
		}
		return <-done
	}
}

func (m *chatModel) onReply(res chatResult) (tea.Model, tea.Cmd) {
	m.streaming = false
	if res.err != nil {
		// The turn failed, so drop the prompt that produced it: leaving it in
		// the history would resend it with the next message.
		m.history = m.history[:len(m.history)-1]
		return m, tea.Println(m.styles.Error.Render("error: " + res.err.Error()))
	}
	m.history = append(m.history, chatMessage{Role: "assistant", Content: res.reply})

	out := res.reply
	if rendered, err := m.renderer.Render(res.reply); err == nil {
		out = strings.TrimRight(rendered, "\n")
	}
	return m, tea.Println(out + "\n" + m.styles.Dim.Render(m.rate()))
}

// rate describes how fast the reply arrived. It counts stream chunks, which
// are not reliably one token each, so it is reported as an approximation
// rather than as a measurement.
func (m *chatModel) rate() string {
	elapsed := time.Since(m.started).Seconds()
	if elapsed <= 0 || m.deltas == 0 {
		return ""
	}
	return fmt.Sprintf("~%.0f chunks/s over %.1fs", float64(m.deltas)/elapsed, elapsed)
}

func (m *chatModel) View() tea.View {
	if m.quit {
		return tea.NewView("")
	}
	if m.streaming {
		return tea.NewView(m.spin.View() + " " + m.streamTail())
	}
	return tea.NewView(m.input.View())
}

// streamTail is the trailing slice of the reply shown while it streams. The
// whole reply is printed once it is complete; redrawing all of it on every
// token would fight the terminal for the scroll region.
func (m *chatModel) streamTail() string {
	lines := strings.Split(lipgloss.NewStyle().Width(m.width-2).Render(m.raw.String()), "\n")
	if len(lines) > streamTailLines {
		lines = lines[len(lines)-streamTailLines:]
	}
	return strings.Join(lines, "\n")
}

// channelWriter adapts streamChat's io.Writer to the program's message loop,
// so the streaming client needs no knowledge of the interface driving it.
type channelWriter struct{ ch chan<- string }

func (w channelWriter) Write(p []byte) (int, error) {
	w.ch <- string(p)
	return len(p), nil
}

var _ io.Writer = channelWriter{}
