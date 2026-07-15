// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"bytes"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics instruments the router for any Prometheus-compatible stack (see
// docs/architecture.md, "Serving layer"): loads, evictions, requests,
// TTFT, stream events.
type Metrics struct {
	loads        *prometheus.CounterVec
	evictions    *prometheus.CounterVec
	requests     *prometheus.CounterVec
	ttft         *prometheus.HistogramVec
	streamEvents *prometheus.CounterVec
	loadedGauge  prometheus.Gauge
	usedGauge    prometheus.Gauge
	budget       prometheus.Gauge
}

// NewMetrics builds and registers the metric set; a nil registerer keeps
// the metrics unregistered (tests, disabled instrumentation).
func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		loads: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "palan_model_loads_total", Help: "Model instances started.",
		}, []string{"model"}),
		evictions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "palan_model_evictions_total", Help: "Model instances stopped, by reason (idle, memory, exit).",
		}, []string{"model", "reason"}),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "palan_requests_total", Help: "Proxied requests by model and status code.",
		}, []string{"model", "code"}),
		ttft: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "palan_ttft_seconds",
			Help:    "Time from request arrival to the first response byte.",
			Buckets: prometheus.ExponentialBuckets(0.05, 2, 12),
		}, []string{"model"}),
		streamEvents: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "palan_stream_events_total", Help: "SSE data events proxied (≈ tokens for llama-server streams).",
		}, []string{"model"}),
		loadedGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "palan_models_loaded", Help: "Currently loaded model instances.",
		}),
		usedGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "palan_memory_used_bytes", Help: "Estimated memory of loaded models.",
		}),
		budget: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "palan_memory_budget_bytes", Help: "Configured memory budget.",
		}),
	}
	if reg != nil {
		reg.MustRegister(m.loads, m.evictions, m.requests, m.ttft, m.streamEvents, m.loadedGauge, m.usedGauge, m.budget)
	}
	return m
}

// observe records request metrics from a completed stream.
func (m *Metrics) observe(model string, rec *streamRecorder) {
	m.requests.WithLabelValues(model, rec.codeString()).Inc()
	if !rec.firstByte.IsZero() {
		m.ttft.WithLabelValues(model).Observe(rec.firstByte.Sub(rec.start).Seconds())
	}
	if rec.dataEvents > 0 {
		m.streamEvents.WithLabelValues(model).Add(float64(rec.dataEvents))
	}
}

// streamRecorder wraps the client ResponseWriter to time the first body
// byte (≈ TTFT) and count SSE data events (≈ tokens) without altering the
// stream.
type streamRecorder struct {
	http.ResponseWriter
	start      time.Time
	firstByte  time.Time
	status     int
	dataEvents int
}

func newStreamRecorder(w http.ResponseWriter) *streamRecorder {
	return &streamRecorder{ResponseWriter: w, start: time.Now(), status: http.StatusOK}
}

func (r *streamRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *streamRecorder) Write(p []byte) (int, error) {
	if r.firstByte.IsZero() && len(p) > 0 {
		r.firstByte = time.Now()
	}
	r.dataEvents += bytes.Count(p, []byte("\ndata: "))
	if bytes.HasPrefix(p, []byte("data: ")) {
		r.dataEvents++
	}
	return r.ResponseWriter.Write(p)
}

// Flush keeps the proxy's per-write flushing working through the wrapper.
func (r *streamRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (r *streamRecorder) codeString() string { return strconv.Itoa(r.status) }
