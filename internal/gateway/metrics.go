package gateway

import (
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"sync"
	"time"
)

// Metrics is a minimal Prometheus text-format registry. It is hand-written
// to keep the dependency set to the YAML parser alone.
type Metrics struct {
	mu       sync.Mutex
	counters map[string]map[string]float64 // name -> rendered labels -> value
	help     map[string]string
	hist     map[string]*histogram
}

type histogram struct {
	buckets []float64
	counts  []uint64
	sum     float64
	count   uint64
}

var latencyBuckets = []float64{0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60}

// NewMetrics returns an empty registry with the gateway's metric families.
func NewMetrics() *Metrics {
	m := &Metrics{counters: map[string]map[string]float64{}, help: map[string]string{}, hist: map[string]*histogram{}}
	m.help["gw_requests_total"] = "Requests by final decision."
	m.help["gw_findings_total"] = "Detector findings by direction, kind and action."
	m.help["gw_config_reloads_total"] = "Config reload attempts by result."
	m.help["gw_guard_seconds_total"] = "CPU time spent in detection and redaction."
	m.help["gw_request_duration_seconds"] = "End-to-end request duration."
	m.help["gw_upstream_duration_seconds"] = "Time to upstream response headers."
	m.hist["gw_request_duration_seconds"] = newHistogram()
	m.hist["gw_upstream_duration_seconds"] = newHistogram()
	return m
}

func newHistogram() *histogram {
	return &histogram{buckets: latencyBuckets, counts: make([]uint64, len(latencyBuckets))}
}

// Add increments counter name with alternating label key/value pairs.
func (m *Metrics) Add(name string, v float64, labels ...string) {
	var b strings.Builder
	for i := 0; i+1 < len(labels); i += 2 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%s=%q", labels[i], labels[i+1])
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.counters[name] == nil {
		m.counters[name] = map[string]float64{}
	}
	m.counters[name][b.String()] += v
}

// Observe records a duration in histogram name.
func (m *Metrics) Observe(name string, d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h := m.hist[name]
	s := d.Seconds()
	for i, ub := range h.buckets {
		if s <= ub {
			h.counts[i]++
		}
	}
	h.sum += s
	h.count++
}

// Get returns a counter value (used by tests and the demo).
func (m *Metrics) Get(name string, labels ...string) float64 {
	var b strings.Builder
	for i := 0; i+1 < len(labels); i += 2 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%s=%q", labels[i], labels[i+1])
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.counters[name][b.String()]
}

// WriteTo renders the registry in Prometheus text format.
func (m *Metrics) WriteTo(w io.Writer) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var b strings.Builder
	names := make([]string, 0, len(m.counters))
	for n := range m.counters {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s counter\n", n, m.help[n], n)
		series := m.counters[n]
		keys := make([]string, 0, len(series))
		for k := range series {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if k == "" {
				fmt.Fprintf(&b, "%s %s\n", n, fmtFloat(series[k]))
			} else {
				fmt.Fprintf(&b, "%s{%s} %s\n", n, k, fmtFloat(series[k]))
			}
		}
	}
	hnames := make([]string, 0, len(m.hist))
	for n := range m.hist {
		hnames = append(hnames, n)
	}
	sort.Strings(hnames)
	for _, n := range hnames {
		h := m.hist[n]
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s histogram\n", n, m.help[n], n)
		for i, ub := range h.buckets {
			fmt.Fprintf(&b, "%s_bucket{le=\"%s\"} %d\n", n, fmtFloat(ub), h.counts[i])
		}
		fmt.Fprintf(&b, "%s_bucket{le=\"+Inf\"} %d\n%s_sum %s\n%s_count %d\n", n, h.count, n, fmtFloat(h.sum), n, h.count)
	}
	k, err := io.WriteString(w, b.String())
	return int64(k), err
}

func fmtFloat(f float64) string {
	if f == math.Trunc(f) && math.Abs(f) < 1e15 {
		return fmt.Sprintf("%d", int64(f))
	}
	return fmt.Sprintf("%g", f)
}
