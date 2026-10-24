// Package gateway is the OpenAI-compatible HTTP proxy that applies the
// guardrail pipeline to requests and (streaming or buffered) responses.
package gateway

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/archit2501/guardrail-gw/internal/audit"
	"github.com/archit2501/guardrail-gw/internal/config"
	"github.com/archit2501/guardrail-gw/internal/filter"
	"github.com/archit2501/guardrail-gw/internal/openai"
	"github.com/archit2501/guardrail-gw/internal/ratelimit"
)

// Options carries the gateway's long-lived dependencies.
type Options struct {
	Logger  *slog.Logger
	Audit   *audit.Log
	Hasher  *audit.Hasher
	Limiter *ratelimit.Limiter
	Metrics *Metrics
	// Client calls the upstream; its Timeout should be zero because each
	// exchange is bounded by the configured upstream.timeout instead.
	Client *http.Client
	// Getenv resolves upstream.api_key_env (defaults to os.Getenv).
	Getenv func(string) string
}

// Server is the gateway. The active configuration is an atomically swapped
// immutable snapshot, so a reload never affects in-flight requests.
type Server struct {
	snap atomic.Pointer[config.Compiled]
	o    Options
}

// New creates a gateway serving cfg.
func New(cfg *config.Compiled, o Options) *Server {
	if o.Logger == nil {
		o.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if o.Hasher == nil {
		o.Hasher, _ = audit.NewHasher(nil)
	}
	if o.Limiter == nil {
		o.Limiter = ratelimit.New()
	}
	if o.Metrics == nil {
		o.Metrics = NewMetrics()
	}
	if o.Client == nil {
		o.Client = &http.Client{}
	}
	if o.Getenv == nil {
		o.Getenv = os.Getenv
	}
	s := &Server{o: o}
	s.snap.Store(cfg)
	return s
}

// Config returns the active snapshot.
func (s *Server) Config() *config.Compiled { return s.snap.Load() }

// Metrics returns the metrics registry.
func (s *Server) Metrics() *Metrics { return s.o.Metrics }

// Apply installs a new configuration snapshot (hot reload). Settings bound at
// startup (listen address, audit path) are reported if they changed.
func (s *Server) Apply(c *config.Compiled) {
	old := s.snap.Swap(c)
	if old.Raw.Listen != c.Raw.Listen || old.Raw.Audit.Path != c.Raw.Audit.Path {
		s.o.Logger.Warn("listen and audit.path changes need a restart; keeping the old values")
	}
	s.o.Limiter.Forget(func(name string) bool {
		for _, k := range c.Keys {
			if k.Name == name {
				return true
			}
		}
		return false
	})
	s.o.Metrics.Add("gw_config_reloads_total", 1, "result", "applied")
}

// ReloadFailed records a rejected reload.
func (s *Server) ReloadFailed(error) { s.o.Metrics.Add("gw_config_reloads_total", 1, "result", "rejected") }

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/chat/completions", s.handleChat)
	mux.HandleFunc("GET /v1/models", s.handleModels)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ok","config":"`+s.snap.Load().Hash[:12]+`"}`)
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = s.o.Metrics.WriteTo(w)
	})
	return mux
}

// requestID returns a sanitized client-supplied X-Request-Id or a random one.
func requestID(r *http.Request) string {
	if id := r.Header.Get("X-Request-Id"); id != "" && len(id) <= 64 && strings.Trim(id, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.") == "" {
		return id
	}
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func writeError(w http.ResponseWriter, status int, message, typ, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(openai.ErrorBody(message, typ, code))
}

// authorize resolves the bearer key and applies its rate limit. On failure it
// writes the response, fills rec, and returns false.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request, snap *config.Compiled, rec *audit.Record) (config.Key, bool) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	key, known := snap.Keys[config.HashKey(strings.TrimSpace(tok))]
	if !ok || !known {
		rec.Decision, rec.Status = audit.DecisionUnauthorized, http.StatusUnauthorized
		writeError(w, rec.Status, "invalid or missing API key", "authentication_error", "invalid_api_key")
		return config.Key{}, false
	}
	rec.Key, rec.Policy = key.Name, key.Profile.Name
	d := s.o.Limiter.Allow(key.Name, ratelimit.Rate{PerMinute: key.Rate.RequestsPerMinute, Burst: key.Rate.Burst})
	w.Header().Set("X-RateLimit-Limit", strconv.Itoa(key.Rate.Burst))
	w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(d.Remaining))
	if !d.Allowed {
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(d.RetryAfter.Seconds()))))
		rec.Decision, rec.Status = audit.DecisionRateLimited, http.StatusTooManyRequests
		writeError(w, rec.Status, "rate limit exceeded for key "+key.Name, "rate_limit_error", "rate_limit_exceeded")
		return config.Key{}, false
	}
	return key, true
}

// finish writes the audit record and updates metrics.
func (s *Server) finish(rec *audit.Record, start time.Time) {
	d := time.Since(start)
	rec.DurationMS = roundMS(d)
	s.o.Metrics.Add("gw_requests_total", 1, "decision", rec.Decision)
	s.o.Metrics.Observe("gw_request_duration_seconds", d)
	for _, f := range rec.Findings {
		s.o.Metrics.Add("gw_findings_total", 1, "direction", f.Direction, "kind", f.Kind, "action", f.Action)
	}
	if s.o.Audit != nil {
		if err := s.o.Audit.Append(*rec); err != nil {
			s.o.Logger.Error("audit append failed", "err", err, "request_id", rec.RequestID)
		}
	}
	s.o.Logger.Info("request", "request_id", rec.RequestID, "key", rec.Key, "decision", rec.Decision,
		"status", rec.Status, "findings", len(rec.Findings), "duration_ms", rec.DurationMS)
}

func roundMS(d time.Duration) float64 { return math.Round(float64(d.Microseconds())) / 1000 }

// record appends applied findings to the audit record.
func (s *Server) record(rec *audit.Record, direction, location string, fs []filter.Applied) {
	for _, f := range fs {
		rec.Findings = append(rec.Findings, audit.Finding{
			Direction: direction, Location: location, Kind: string(f.Kind), Category: string(f.Category),
			Action: f.Action.String(), Start: f.Start, End: f.End, ValueHMAC: s.o.Hasher.Digest(string(f.Kind), f.Value),
		})
	}
}

func (s *Server) handleModels(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	snap := s.snap.Load()
	rec := audit.Record{RequestID: requestID(r), Decision: audit.DecisionAllowed}
	defer s.finish(&rec, start)
	if _, ok := s.authorize(w, r, snap, &rec); !ok {
		return
	}
	ctx, cancel := contextWithTimeout(r, snap.Raw.Upstream.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, snap.Raw.Upstream.BaseURL+"/v1/models", nil)
	if err != nil {
		rec.Decision, rec.Status = audit.DecisionUpstreamError, http.StatusBadGateway
		writeError(w, rec.Status, "bad upstream URL", "upstream_error", "upstream_unavailable")
		return
	}
	s.setUpstreamAuth(req, snap)
	resp, err := s.o.Client.Do(req)
	if err != nil {
		rec.Decision, rec.Status = audit.DecisionUpstreamError, http.StatusBadGateway
		writeError(w, rec.Status, "upstream unavailable", "upstream_error", "upstream_unavailable")
		return
	}
	defer resp.Body.Close()
	rec.Status = resp.StatusCode
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(resp.Body, snap.Raw.Limits.MaxResponseBytes))
}

func (s *Server) setUpstreamAuth(req *http.Request, snap *config.Compiled) {
	if env := snap.Raw.Upstream.APIKeyEnv; env != "" {
		if v := s.o.Getenv(env); v != "" {
			req.Header.Set("Authorization", "Bearer "+v)
		}
	}
}
