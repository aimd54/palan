// Copyright The moci Authors
// SPDX-License-Identifier: Apache-2.0

// Command fakellama mimics llama-server's CLI and HTTP surface for tests:
// it accepts (and mostly ignores) llama-server flags, serves /health with a
// configurable loading delay, and answers OpenAI-style completion requests
// with deterministic fake content, including SSE streaming. Supervisor and
// router tests drive this binary instead of a real llama.cpp build.
//
// Environment knobs:
//
//	FAKELLAMA_STARTUP_DELAY  duration before /health flips to 200 (default 0)
//	FAKELLAMA_EXIT_AFTER     duration after which the process exits 7 (crash)
//	FAKELLAMA_RESPONSE_DELAY duration each completion waits before answering
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

func main() {
	var modelPath, host, port string
	host, port = "127.0.0.1", "8080"
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		val := func() string {
			if i+1 < len(args) {
				i++
				return args[i]
			}
			return ""
		}
		switch args[i] {
		case "-m", "--model":
			modelPath = val()
		case "--host":
			host = val()
		case "--port":
			port = val()
		default:
			if strings.Contains(args[i], "=") {
				continue // --flag=value form, ignored
			}
			// Ignore other value-taking llama-server flags conservatively:
			// unknown flags with a following non-flag token consume it.
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
			}
		}
	}
	modelName := filepath.Base(modelPath)

	var ready atomic.Bool
	delay, _ := time.ParseDuration(os.Getenv("FAKELLAMA_STARTUP_DELAY"))
	go func() {
		time.Sleep(delay)
		ready.Store(true)
	}()
	if d, err := time.ParseDuration(os.Getenv("FAKELLAMA_EXIT_AFTER")); err == nil && d > 0 {
		go func() {
			time.Sleep(d)
			fmt.Fprintln(os.Stderr, "fakellama: simulated crash")
			os.Exit(7)
		}()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		if !ready.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":{"message":"Loading model"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("/v1/models", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"object": "list",
			"data":   []map[string]any{{"id": modelName, "object": "model"}},
		})
	})
	complete := func(w http.ResponseWriter, r *http.Request) {
		if d, err := time.ParseDuration(os.Getenv("FAKELLAMA_RESPONSE_DELAY")); err == nil && d > 0 {
			select {
			case <-time.After(d):
			case <-r.Context().Done():
				return
			}
		}
		var req struct {
			Model    string `json:"model"`
			Stream   bool   `json:"stream"`
			Prompt   string `json:"prompt"`
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		last := req.Prompt
		for _, m := range req.Messages {
			if m.Role == "user" {
				last = m.Content
			}
		}
		reply := "fake(" + modelName + "): " + last

		if req.Stream {
			w.Header().Set("Content-Type", "text/event-stream")
			fl, _ := w.(http.Flusher)
			for _, tok := range strings.SplitAfter(reply, " ") {
				chunk, _ := json.Marshal(map[string]any{
					"object": "chat.completion.chunk",
					"model":  req.Model,
					"choices": []map[string]any{
						{"index": 0, "delta": map[string]string{"content": tok}},
					},
				})
				_, _ = fmt.Fprintf(w, "data: %s\n\n", chunk)
				if fl != nil {
					fl.Flush()
				}
			}
			_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":     "chatcmpl-fake",
			"object": "chat.completion",
			"model":  req.Model,
			"choices": []map[string]any{
				{
					"index":         0,
					"message":       map[string]string{"role": "assistant", "content": reply},
					"finish_reason": "stop",
				},
			},
			"usage": map[string]int{"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
		})
	}
	mux.HandleFunc("/v1/chat/completions", complete)
	mux.HandleFunc("/v1/completions", complete)
	mux.HandleFunc("/v1/embeddings", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"object": "list",
			"data":   []map[string]any{{"object": "embedding", "index": 0, "embedding": []float64{0.1, 0.2}}},
		})
	})

	srv := &http.Server{Addr: host + ":" + port, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sig
		os.Exit(0) // llama-server exits promptly on SIGTERM
	}()
	fmt.Fprintf(os.Stderr, "fakellama listening on %s (model %s, pid %s)\n",
		srv.Addr, modelName, strconv.Itoa(os.Getpid()))
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, "fakellama:", err)
		os.Exit(1)
	}
}
