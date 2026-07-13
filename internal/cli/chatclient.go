// Copyright The moci Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// chatMessage is one OpenAI-style chat turn.
type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// streamChat posts a streaming chat completion to an OpenAI-compatible
// endpoint and writes deltas to w as they arrive, returning the full reply.
func streamChat(ctx context.Context, baseURL, model string, messages []chatMessage, w io.Writer) (string, error) {
	body, err := json.Marshal(map[string]any{
		"model":    model,
		"messages": messages,
		"stream":   true,
	})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("chat request failed: %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}

	var reply strings.Builder
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		data, ok := strings.CutPrefix(line, "data: ")
		if !ok || data == "[DONE]" {
			continue
		}
		var chunk struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			continue // tolerate keep-alives and vendor extras
		}
		for _, c := range chunk.Choices {
			if c.Delta.Content != "" {
				reply.WriteString(c.Delta.Content)
				fmt.Fprint(w, c.Delta.Content)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return reply.String(), err
	}
	return reply.String(), nil
}
