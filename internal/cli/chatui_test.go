// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/aimd54/palan/internal/ui"
)

// streamingServer is an OpenAI-compatible endpoint that streams reply back one
// space-separated chunk at a time, the way llama-server does.
func streamingServer(t *testing.T, reply string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fl, _ := w.(http.Flusher)
		for _, tok := range strings.SplitAfter(reply, " ") {
			fmt.Fprintf(w, "data: {\"choices\":[{\"delta\":{\"content\":%q}}]}\n\n", tok)
			if fl != nil {
				fl.Flush()
			}
		}
		fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newTestChat(t *testing.T, baseURL string) *chatModel {
	t.Helper()
	m, err := newChatModel(context.Background(), baseURL, "test-model", ui.Styles{}, 80)
	if err != nil {
		t.Fatalf("building the chat model: %v", err)
	}
	return m
}

// drain runs the command loop until the turn ends, the way the program would,
// and returns every message that was produced. A command that never yields a
// terminating result would hang here rather than in someone's terminal.
func drain(t *testing.T, m *chatModel, cmd tea.Cmd) []tea.Msg {
	t.Helper()
	var msgs []tea.Msg
	deadline := time.After(10 * time.Second)
	for cmd != nil {
		type result struct{ msg tea.Msg }
		ch := make(chan result, 1)
		go func(c tea.Cmd) { ch <- result{c()} }(cmd)

		var msg tea.Msg
		select {
		case r := <-ch:
			msg = r.msg
		case <-deadline:
			t.Fatal("the chat never finished its turn")
		}
		if msg == nil {
			return msgs
		}
		msgs = append(msgs, msg)

		// Only the stream messages advance the turn; the rest are output.
		switch msg.(type) {
		case chatDelta, chatResult:
			_, cmd = m.Update(msg)
		default:
			return msgs
		}
	}
	return msgs
}

// TestChatTurnRecordsBothSides: a completed turn has to leave the exchange in
// the history, or the next question is asked with no context and the model
// answers as if the conversation had not happened.
func TestChatTurnRecordsBothSides(t *testing.T) {
	srv := streamingServer(t, "**bold** and `code`")
	m := newTestChat(t, srv.URL)

	cmd := m.send("hello")
	if !m.streaming {
		t.Fatal("sending must mark the turn in flight")
	}
	drain(t, m, m.awaitStream())

	if m.streaming {
		t.Error("the turn is still marked in flight after it finished")
	}
	if len(m.history) != 2 {
		t.Fatalf("history holds %d messages, want the question and the answer", len(m.history))
	}
	if m.history[0].Role != "user" || m.history[0].Content != "hello" {
		t.Errorf("first message = %+v, want the user's question", m.history[0])
	}
	if m.history[1].Role != "assistant" || !strings.Contains(m.history[1].Content, "bold") {
		t.Errorf("second message = %+v, want the model's answer", m.history[1])
	}
	if cmd == nil {
		t.Error("sending produced no commands, so the prompt was never echoed")
	}
}

// TestChatRendersMarkdown proves the reply is formatted rather than shown with
// its markers intact, which is the whole reason glamour is here.
func TestChatRendersMarkdown(t *testing.T) {
	srv := streamingServer(t, "# Heading\n\n- one\n- two\n")
	m := newTestChat(t, srv.URL)

	m.send("hi")
	msgs := drain(t, m, m.awaitStream())

	// Only what the chat chose to print. The deltas carry the raw markdown by
	// definition, so including them here would assert nothing.
	var printed string
	for _, msg := range msgs {
		switch msg.(type) {
		case chatDelta, chatResult:
		default:
			printed += fmt.Sprint(msg)
		}
	}
	if printed == "" {
		t.Fatal("the finished reply was never printed")
	}
	if strings.Contains(printed, "# Heading") {
		t.Error("the heading marker survived, so the reply was not rendered")
	}
	if !strings.Contains(printed, "Heading") {
		t.Error("the heading text is missing from the rendered reply")
	}
	if !strings.Contains(printed, "•") {
		t.Error("the list was not rendered as a list")
	}
}

// TestChatFailedTurnDropsTheQuestion: a question whose answer never arrived
// must not stay in the history, or it is silently resent with the next one and
// the model sees it twice.
func TestChatFailedTurnDropsTheQuestion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "model is loading", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)

	m := newTestChat(t, srv.URL)
	m.send("hello")
	drain(t, m, m.awaitStream())

	if m.streaming {
		t.Error("a failed turn left the chat marked in flight, so it accepts no further input")
	}
	if len(m.history) != 0 {
		t.Errorf("history holds %d messages after a failure, want none", len(m.history))
	}
}

// TestChatQuitKeys covers the documented ways out. A chat that cannot be left
// is worse than one that is plain.
func TestChatQuitKeys(t *testing.T) {
	for _, key := range []string{"ctrl+c", "ctrl+d"} {
		t.Run(key, func(t *testing.T) {
			m := newTestChat(t, "http://127.0.0.1:1")
			_, cmd := m.onKey(tea.KeyPressMsg{Code: keyCodeFor(key), Mod: tea.ModCtrl})
			if !m.quit || cmd == nil {
				t.Errorf("%s did not quit", key)
			}
		})
	}

	t.Run("/bye", func(t *testing.T) {
		m := newTestChat(t, "http://127.0.0.1:1")
		m.input.SetValue("/bye")
		_, cmd := m.onKey(tea.KeyPressMsg{Code: tea.KeyEnter})
		if !m.quit || cmd == nil {
			t.Error("/bye did not quit")
		}
	})
}

func keyCodeFor(key string) rune {
	switch key {
	case "ctrl+c":
		return 'c'
	case "ctrl+d":
		return 'd'
	}
	return 0
}

// TestChatIgnoresInputMidTurn: sending a second question while the first is
// still streaming would start a second goroutine writing to a channel the
// model has stopped reading, and the reply channels would cross.
func TestChatIgnoresInputMidTurn(t *testing.T) {
	m := newTestChat(t, "http://127.0.0.1:1")
	m.streaming = true
	m.input.SetValue("second question")

	_, cmd := m.onKey(tea.KeyPressMsg{Code: tea.KeyEnter})
	if cmd != nil {
		t.Error("a question sent mid-turn started another turn")
	}
	if len(m.history) != 0 {
		t.Error("a question sent mid-turn reached the history")
	}
}
