// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

// Package router is palan's multi-model serving core (design §9.2): one
// OpenAI-compatible endpoint that lazily spawns a llama-server per model,
// unloads idle ones, and evicts least-recently-used instances when the
// memory budget would overflow — so loading model B on a 10 GB GPU evicts
// model A instead of OOMing it.
package router

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/aimd54/palan/internal/runtime"
)

// DefaultAddr is the router's default listen address (design §16.3: 11500,
// deliberately not Ollama's 11434 to allow coexistence).
const DefaultAddr = ":11500"

// DefaultIdleTimeout unloads models after this much inactivity (§9.2).
const DefaultIdleTimeout = 10 * time.Minute

// Backend supplies servable models to the router.
type Backend interface {
	// List returns the servable model references.
	List(ctx context.Context) ([]string, error)
	// Spec returns the process spec and estimated memory footprint (bytes)
	// for one model.
	Spec(ctx context.Context, ref string) (runtime.Spec, int64, error)
}

// Options configures the router.
type Options struct {
	// Backend is required.
	Backend Backend
	// MemoryBudget bounds the sum of loaded models' estimated footprints.
	// <= 0 disables the guard (not recommended; the CLI always sets one).
	MemoryBudget int64
	// IdleTimeout unloads inactive models; <= 0 means DefaultIdleTimeout.
	IdleTimeout time.Duration
	// BearerToken, when set, is required on every request.
	BearerToken string
	// KeepLoaded lists refs immune to idle unload and eviction.
	KeepLoaded []string
	// SweepInterval is how often the idle sweeper runs (tests shrink it);
	// <= 0 means 30s.
	SweepInterval time.Duration
	// Metrics receives router events; nil disables instrumentation.
	Metrics *Metrics
}

// Router implements http.Handler.
type Router struct {
	opts    Options
	keep    map[string]bool
	mu      sync.Mutex
	loaded  map[string]*instance
	flight  singleflight.Group
	stopped chan struct{}
	stopSw  context.CancelFunc
	metrics *Metrics
}

// instance is one running llama-server.
type instance struct {
	ref      string
	srv      *runtime.Server
	memory   int64
	proxy    *httputil.ReverseProxy
	mu       sync.Mutex
	lastUsed time.Time
	active   int
}

// New builds a Router and starts its idle sweeper.
func New(opts Options) (*Router, error) {
	if opts.Backend == nil {
		return nil, fmt.Errorf("router requires a backend")
	}
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = DefaultIdleTimeout
	}
	if opts.SweepInterval <= 0 {
		opts.SweepInterval = 30 * time.Second
	}
	if opts.Metrics == nil {
		opts.Metrics = NewMetrics(nil)
	}
	keep := map[string]bool{}
	for _, r := range opts.KeepLoaded {
		keep[r] = true
	}
	rt := &Router{
		opts:    opts,
		keep:    keep,
		loaded:  map[string]*instance{},
		stopped: make(chan struct{}),
		metrics: opts.Metrics,
	}
	rt.metrics.budget.Set(float64(opts.MemoryBudget))
	sweepCtx, cancel := context.WithCancel(context.Background())
	rt.stopSw = cancel
	go rt.sweep(sweepCtx)
	return rt, nil
}

// ServeHTTP routes OpenAI-style requests by their "model" field.
func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !rt.authorized(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid or missing bearer token")
		return
	}
	switch {
	case r.URL.Path == "/health":
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	case r.URL.Path == "/v1/models" && r.Method == http.MethodGet:
		rt.handleModels(w, r)
	case strings.HasPrefix(r.URL.Path, "/v1/"):
		rt.handleProxy(w, r)
	default:
		writeOpenAIError(w, http.StatusNotFound, "unknown endpoint "+r.URL.Path)
	}
}

func (rt *Router) authorized(r *http.Request) bool {
	if rt.opts.BearerToken == "" {
		return true
	}
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	return subtle.ConstantTimeCompare([]byte(got), []byte(rt.opts.BearerToken)) == 1
}

func (rt *Router) handleModels(w http.ResponseWriter, r *http.Request) {
	refs, err := rt.opts.Backend.List(r.Context())
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	type m struct {
		ID      string `json:"id"`
		Object  string `json:"object"`
		OwnedBy string `json:"owned_by"`
	}
	out := struct {
		Object string `json:"object"`
		Data   []m    `json:"data"`
	}{Object: "list", Data: []m{}}
	for _, ref := range refs {
		out.Data = append(out.Data, m{ID: ref, Object: "model", OwnedBy: "palan"})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// handleProxy extracts the model, ensures its instance, and reverse-proxies.
func (rt *Router) handleProxy(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 32<<20))
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "reading request body: "+err.Error())
		return
	}
	var meta struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(body, &meta); err != nil || meta.Model == "" {
		writeOpenAIError(w, http.StatusBadRequest, `request must carry a "model" field`)
		return
	}

	inst, status, err := rt.ensure(r.Context(), meta.Model)
	if err != nil {
		writeOpenAIError(w, status, err.Error())
		rt.metrics.requests.WithLabelValues(meta.Model, fmt.Sprint(status)).Inc()
		return
	}

	inst.begin()
	defer inst.end()

	r2 := r.Clone(r.Context())
	r2.Body = io.NopCloser(strings.NewReader(string(body)))
	r2.ContentLength = int64(len(body))

	rw := newStreamRecorder(w)
	inst.proxy.ServeHTTP(rw, r2)
	rt.metrics.observe(meta.Model, rw)
}

// ensure returns a running instance for ref, loading (and possibly
// evicting) under single-flight. The HTTP status accompanies errors.
func (rt *Router) ensure(ctx context.Context, ref string) (*instance, int, error) {
	rt.mu.Lock()
	if inst, ok := rt.loaded[ref]; ok {
		inst.touch()
		rt.mu.Unlock()
		return inst, http.StatusOK, nil
	}
	rt.mu.Unlock()

	v, err, _ := rt.flight.Do(ref, func() (any, error) {
		// Re-check under flight: another request may have loaded it.
		rt.mu.Lock()
		if inst, ok := rt.loaded[ref]; ok {
			rt.mu.Unlock()
			return inst, nil
		}
		rt.mu.Unlock()

		spec, memory, err := rt.opts.Backend.Spec(ctx, ref)
		if err != nil {
			return nil, &httpError{http.StatusNotFound, fmt.Sprintf("model %q not servable: %v", ref, err)}
		}
		if err := rt.makeRoom(memory, ref); err != nil {
			return nil, err
		}
		srv, err := runtime.Start(ctx, spec)
		if err != nil {
			return nil, &httpError{http.StatusBadGateway, err.Error()}
		}
		target, err := url.Parse(srv.BaseURL())
		if err != nil {
			_ = srv.Stop(context.Background())
			return nil, &httpError{http.StatusInternalServerError, err.Error()}
		}
		proxy := httputil.NewSingleHostReverseProxy(target)
		proxy.FlushInterval = -1 // flush every write: SSE tokens must not buffer
		inst := &instance{ref: ref, srv: srv, memory: memory, proxy: proxy, lastUsed: time.Now()}

		rt.mu.Lock()
		rt.loaded[ref] = inst
		rt.mu.Unlock()
		rt.metrics.loads.WithLabelValues(ref).Inc()
		rt.updateGauges()

		// Reap crashed children so the next request respawns cleanly.
		go func() {
			<-srv.Done()
			rt.mu.Lock()
			cur, ok := rt.loaded[ref]
			if ok && cur == inst {
				delete(rt.loaded, ref)
			}
			rt.mu.Unlock()
			if ok && cur == inst {
				rt.metrics.evictions.WithLabelValues(ref, "exit").Inc()
				rt.updateGauges()
			}
		}()
		return inst, nil
	})
	if err != nil {
		var he *httpError
		if ok := asHTTPError(err, &he); ok {
			return nil, he.status, fmt.Errorf("%s", he.msg)
		}
		return nil, http.StatusInternalServerError, err
	}
	inst := v.(*instance)
	inst.touch()
	return inst, http.StatusOK, nil
}

// makeRoom evicts idle LRU instances until `need` fits in the budget.
func (rt *Router) makeRoom(need int64, forRef string) error {
	if rt.opts.MemoryBudget <= 0 {
		return nil
	}
	if need > rt.opts.MemoryBudget {
		return &httpError{http.StatusInsufficientStorage,
			fmt.Sprintf("model %q needs ~%d bytes, over the total budget %d", forRef, need, rt.opts.MemoryBudget)}
	}
	for {
		rt.mu.Lock()
		var used int64
		var lru *instance
		for _, inst := range rt.loaded {
			used += inst.memory
			if rt.keep[inst.ref] || inst.busy() {
				continue
			}
			if lru == nil || inst.last().Before(lru.last()) {
				lru = inst
			}
		}
		if used+need <= rt.opts.MemoryBudget {
			rt.mu.Unlock()
			return nil
		}
		if lru == nil {
			rt.mu.Unlock()
			return &httpError{http.StatusServiceUnavailable,
				fmt.Sprintf("memory budget exhausted (%d used, %d needed) and every loaded model is busy or pinned", used, need)}
		}
		delete(rt.loaded, lru.ref)
		rt.mu.Unlock()
		_ = lru.srv.Stop(context.Background())
		rt.metrics.evictions.WithLabelValues(lru.ref, "memory").Inc()
		rt.updateGauges()
	}
}

// sweep unloads instances idle beyond the timeout.
func (rt *Router) sweep(ctx context.Context) {
	t := time.NewTicker(rt.opts.SweepInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cutoff := time.Now().Add(-rt.opts.IdleTimeout)
			var victims []*instance
			rt.mu.Lock()
			for ref, inst := range rt.loaded {
				if rt.keep[ref] || inst.busy() {
					continue
				}
				if inst.last().Before(cutoff) {
					delete(rt.loaded, ref)
					victims = append(victims, inst)
				}
			}
			rt.mu.Unlock()
			for _, inst := range victims {
				_ = inst.srv.Stop(context.Background())
				rt.metrics.evictions.WithLabelValues(inst.ref, "idle").Inc()
			}
			if len(victims) > 0 {
				rt.updateGauges()
			}
		}
	}
}

// Shutdown stops the sweeper and all children.
func (rt *Router) Shutdown(ctx context.Context) {
	rt.stopSw()
	rt.mu.Lock()
	insts := make([]*instance, 0, len(rt.loaded))
	for ref, inst := range rt.loaded {
		delete(rt.loaded, ref)
		insts = append(insts, inst)
	}
	rt.mu.Unlock()
	var wg sync.WaitGroup
	for _, inst := range insts {
		wg.Go(func() { _ = inst.srv.Stop(ctx) })
	}
	wg.Wait()
}

// updateGauges refreshes loaded-count and used-memory gauges.
func (rt *Router) updateGauges() {
	rt.mu.Lock()
	var used int64
	n := 0
	for _, inst := range rt.loaded {
		used += inst.memory
		n++
	}
	rt.mu.Unlock()
	rt.metrics.loadedGauge.Set(float64(n))
	rt.metrics.usedGauge.Set(float64(used))
}

func (i *instance) touch() {
	i.mu.Lock()
	i.lastUsed = time.Now()
	i.mu.Unlock()
}

func (i *instance) last() time.Time {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.lastUsed
}

func (i *instance) begin() {
	i.mu.Lock()
	i.active++
	i.lastUsed = time.Now()
	i.mu.Unlock()
}

func (i *instance) end() {
	i.mu.Lock()
	i.active--
	i.lastUsed = time.Now()
	i.mu.Unlock()
}

func (i *instance) busy() bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.active > 0
}

// httpError carries a status code through singleflight.
type httpError struct {
	status int
	msg    string
}

func (e *httpError) Error() string { return e.msg }

func asHTTPError(err error, target **httpError) bool {
	he, ok := err.(*httpError) //nolint:errorlint // singleflight returns our sentinel directly
	if ok {
		*target = he
	}
	return ok
}

// writeOpenAIError emits the OpenAI-style error envelope clients expect.
func writeOpenAIError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{"message": msg, "type": "palan_router_error", "code": status},
	})
}
