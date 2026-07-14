// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Spec describes one llama-server process to supervise.
type Spec struct {
	// Bin is the llama-server executable path.
	Bin string
	// ModelPath is the GGUF blob path (raw layer straight from the store).
	ModelPath string
	// Alias names the process in logs, e.g. the model reference.
	Alias string
	// Host defaults to 127.0.0.1; the child is never exposed directly.
	Host string
	// Port 0 picks a free ephemeral port.
	Port int
	// CtxSize and NGL map to --ctx-size / --n-gpu-layers when > 0.
	CtxSize int
	NGL     int
	// ExtraArgs are appended last (io.palan.serve.defaults flags, overrides).
	ExtraArgs []string
	// LogDir receives <alias>-<port>.log; empty discards logs.
	LogDir string
	// StartTimeout bounds model loading (default 5 min: big models mmap
	// slowly on first touch).
	StartTimeout time.Duration
}

// Server is a running llama-server child process.
type Server struct {
	spec    Spec
	cmd     *exec.Cmd
	port    int
	logPath string
	exited  chan struct{} // closed when the process exits
	exitErr error         // valid once exited is closed
}

// Start spawns llama-server and waits until /health reports ready.
func Start(ctx context.Context, spec Spec) (*Server, error) {
	if spec.Host == "" {
		spec.Host = "127.0.0.1"
	}
	if spec.StartTimeout <= 0 {
		spec.StartTimeout = 5 * time.Minute
	}
	port := spec.Port
	if port == 0 {
		var err error
		if port, err = freePort(spec.Host); err != nil {
			return nil, err
		}
	}

	args := []string{"-m", spec.ModelPath, "--host", spec.Host, "--port", strconv.Itoa(port)}
	if spec.CtxSize > 0 {
		args = append(args, "--ctx-size", strconv.Itoa(spec.CtxSize))
	}
	if spec.NGL > 0 {
		args = append(args, "--n-gpu-layers", strconv.Itoa(spec.NGL))
	}
	args = append(args, spec.ExtraArgs...)

	cmd := exec.Command(spec.Bin, args...) // #nosec G204 -- spawning the resolved inference runtime is this package's purpose (ADR-0003)
	var logPath string
	if spec.LogDir != "" {
		if err := os.MkdirAll(spec.LogDir, 0o750); err != nil {
			return nil, err
		}
		logPath = filepath.Join(spec.LogDir, fmt.Sprintf("%s-%d.log", sanitizeAlias(spec.Alias), port))
		logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G304 -- path derived from sanitized alias under the state dir
		if err != nil {
			return nil, err
		}
		cmd.Stdout = logFile
		cmd.Stderr = logFile
		defer func() { _ = logFile.Close() }() // child holds its own fd after Start
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting %s: %w", spec.Bin, err)
	}
	s := &Server{spec: spec, cmd: cmd, port: port, logPath: logPath, exited: make(chan struct{})}
	go func() {
		s.exitErr = cmd.Wait()
		close(s.exited)
	}()

	if err := s.waitReady(ctx); err != nil {
		_ = s.Stop(context.Background())
		return nil, fmt.Errorf("%s for %s did not become ready: %w%s", filepath.Base(spec.Bin), spec.Alias, err, s.logTail())
	}
	return s, nil
}

// waitReady polls /health until 200, process exit, or timeout.
func (s *Server) waitReady(ctx context.Context) error {
	deadline := time.NewTimer(s.spec.StartTimeout)
	defer deadline.Stop()
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	client := &http.Client{Timeout: 2 * time.Second}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.exited:
			return fmt.Errorf("process exited during startup: %w", s.exitErr)
		case <-deadline.C:
			return fmt.Errorf("timeout after %s", s.spec.StartTimeout)
		case <-tick.C:
			resp, err := client.Get(s.BaseURL() + "/health")
			if err == nil {
				_ = resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					return nil
				}
			}
		}
	}
}

// Stop terminates the child: SIGTERM, then SIGKILL after 10s or ctx expiry.
// Stop is idempotent and safe to call from multiple goroutines.
func (s *Server) Stop(ctx context.Context) error {
	if s.cmd.Process == nil {
		return nil
	}
	select {
	case <-s.exited:
		return nil // already gone
	default:
	}
	_ = s.cmd.Process.Signal(syscall.SIGTERM)
	grace := time.NewTimer(10 * time.Second)
	defer grace.Stop()
	select {
	case <-s.exited:
		return nil
	case <-ctx.Done():
	case <-grace.C:
	}
	_ = s.cmd.Process.Kill()
	<-s.exited
	return nil
}

// Done is closed when the process exits; ExitErr is valid afterwards.
func (s *Server) Done() <-chan struct{} { return s.exited }

// ExitErr returns the process exit error; only meaningful once Done is
// closed (nil means clean exit).
func (s *Server) ExitErr() error {
	select {
	case <-s.exited:
		return s.exitErr
	default:
		return nil
	}
}

// BaseURL is the child's HTTP endpoint.
func (s *Server) BaseURL() string {
	return fmt.Sprintf("http://%s", net.JoinHostPort(s.spec.Host, strconv.Itoa(s.port)))
}

// Port returns the bound port.
func (s *Server) Port() int { return s.port }

// LogPath returns the child's log file ("" when logging is disabled).
func (s *Server) LogPath() string { return s.logPath }

// logTail returns the last part of the child's log for error messages.
func (s *Server) logTail() string {
	if s.logPath == "" {
		return ""
	}
	b, err := os.ReadFile(s.logPath) // #nosec G304 -- our own log file
	if err != nil || len(b) == 0 {
		return ""
	}
	const tail = 2048
	if len(b) > tail {
		b = b[len(b)-tail:]
	}
	return "\n--- log tail (" + s.logPath + ") ---\n" + string(b)
}

func sanitizeAlias(alias string) string {
	r := strings.NewReplacer("/", "_", ":", "_", "@", "_")
	if alias == "" {
		return "model"
	}
	return r.Replace(alias)
}

func freePort(host string) (int, error) {
	l, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		return 0, err
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port, nil
}
