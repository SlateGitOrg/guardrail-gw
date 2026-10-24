package gateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/archit2501/guardrail-gw/internal/audit"
	"github.com/archit2501/guardrail-gw/internal/config"
	"github.com/archit2501/guardrail-gw/internal/filter"
	"github.com/archit2501/guardrail-gw/internal/injection"
	"github.com/archit2501/guardrail-gw/internal/openai"
	"github.com/archit2501/guardrail-gw/internal/policy"
)

func contextWithTimeout(r *http.Request, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), d)
}

// exchange holds per-request state shared by the request and response guards.
type exchange struct {
	snap    *config.Compiled
	profile *policy.Profile
	namer   *filter.Namer // shared so a value keeps its placeholder end to end
	rec     *audit.Record
}

func (s *Server) handleChat(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	snap := s.snap.Load()
	rec := audit.Record{RequestID: requestID(r), Decision: audit.DecisionAllowed}
	w.Header().Set("X-Request-Id", rec.RequestID)
	defer s.finish(&rec, start)

	key, ok := s.authorize(w, r, snap, &rec)
	if !ok {
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, snap.Raw.Limits.MaxRequestBytes))
	if err != nil {
		rec.Decision, rec.Status = audit.DecisionBadRequest, http.StatusRequestEntityTooLarge
		writeError(w, rec.Status, "request body too large or unreadable", "invalid_request_error", "request_too_large")
		return
	}
	req, err := openai.ParseChatRequest(body)
	if err != nil {
		rec.Decision, rec.Status = audit.DecisionBadRequest, http.StatusBadRequest
		writeError(w, rec.Status, err.Error(), "invalid_request_error", "invalid_request")
		return
	}
	rec.Model, rec.Stream = req.Model, req.Stream
	x := &exchange{snap: snap, profile: key.Profile, namer: filter.NewNamer(), rec: &rec}

	if code, msg := s.guardRequest(x, req); code != "" {
		rec.Decision, rec.Status, rec.Reason = audit.DecisionBlockedRequest, http.StatusBadRequest, code
		writeError(w, rec.Status, msg, "guardrail_violation", code)
		return
	}
	if hasAction(rec.Findings, policy.Redact) {
		rec.Decision = audit.DecisionRedacted
	}

	ctx, cancel := context.WithTimeout(r.Context(), snap.Raw.Upstream.Timeout)
	defer cancel()
	resp, err := s.callUpstream(ctx, snap, req)
	if err != nil {
		rec.Decision, rec.Status, rec.Reason = audit.DecisionUpstreamError, http.StatusBadGateway, err.Error()
		writeError(w, rec.Status, "upstream unavailable", "upstream_error", "upstream_unavailable")
		return
	}
	defer resp.Body.Close()
	rec.UpstreamMS = roundMS(time.Since(start))
	s.o.Metrics.Observe("gw_upstream_duration_seconds", time.Since(start))

	if resp.StatusCode != http.StatusOK {
		// Upstream errors are relayed verbatim (bounded): they describe the
		// failure, not model output.
		rec.Decision, rec.Status = audit.DecisionUpstreamError, resp.StatusCode
		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, io.LimitReader(resp.Body, snap.Raw.Limits.MaxResponseBytes))
		return
	}
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		s.streamResponse(w, cancel, x, resp.Body)
		return
	}
	s.bufferedResponse(w, x, resp.Body)
}

func hasAction(fs []audit.Finding, a policy.Action) bool {
	for _, f := range fs {
		if f.Action == a.String() {
			return true
		}
	}
	return false
}

// guardRequest scans and rewrites every message. It returns an error code
// and message when the request must be rejected.
func (s *Server) guardRequest(x *exchange, req *openai.ChatRequest) (string, string) {
	t0 := time.Now()
	defer func() { s.o.Metrics.Add("gw_guard_seconds_total", time.Since(t0).Seconds()) }()
	rules := x.profile.Request
	dets := rules.Active(x.snap.Detectors)
	var blocked *filter.Applied
	best := injection.Score{}
	for i, m := range req.Messages {
		role := openai.Role(m)
		loc := fmt.Sprintf("messages[%d]", i)
		openai.RewriteTexts(m, func(text string) string {
			// User text and tool results are the injection vectors (direct and
			// indirect); system/assistant turns come from the application.
			if x.profile.Injection.Action > policy.Allow && (role == "user" || role == "tool") {
				if sc := injection.Evaluate(text); sc.Value > best.Value {
					best = sc
				}
			}
			res := filter.Apply(dets, rules.For, x.namer, text)
			s.record(x.rec, "request", loc, res.Findings)
			if res.Blocked != nil && blocked == nil {
				blocked = res.Blocked
			}
			return res.Text
		})
	}
	if blocked != nil {
		return string(blocked.Category) + "_blocked", fmt.Sprintf("request blocked by guardrail: %s detected (%s)", blocked.Kind, blocked.Category)
	}
	inj := x.profile.Injection
	if inj.Action > policy.Allow && best.Value >= inj.Threshold {
		names := make([]string, len(best.Signals))
		for i, sg := range best.Signals {
			names[i] = sg.Name
		}
		x.rec.Injection = &audit.Injection{Score: round3(best.Value), Signals: names, Action: inj.Action.String()}
		if inj.Action == policy.Block {
			return "prompt_injection", fmt.Sprintf("request blocked by guardrail: prompt injection suspected (score %.2f: %s)", best.Value, strings.Join(names, ", "))
		}
	}
	return "", ""
}

func round3(f float64) float64 { return float64(int(f*1000+0.5)) / 1000 }

func (s *Server) callUpstream(ctx context.Context, snap *config.Compiled, req *openai.ChatRequest) (*http.Response, error) {
	body, err := openai.Encode(req.Body)
	if err != nil {
		return nil, err
	}
	up, err := http.NewRequestWithContext(ctx, http.MethodPost, snap.Raw.Upstream.BaseURL+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	up.Header.Set("Content-Type", "application/json")
	if req.Stream {
		up.Header.Set("Accept", "text/event-stream")
	}
	s.setUpstreamAuth(up, snap)
	return s.o.Client.Do(up)
}

// errResponseTooLarge marks an upstream body over limits.max_response_bytes.
var errResponseTooLarge = errors.New("upstream response exceeds max_response_bytes")

// bufferedResponse filters a non-streaming chat completion.
func (s *Server) bufferedResponse(w http.ResponseWriter, x *exchange, body io.Reader) {
	limit := x.snap.Raw.Limits.MaxResponseBytes
	raw, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err == nil && int64(len(raw)) > limit {
		err = errResponseTooLarge
	}
	var o openai.Object
	if err == nil {
		o, err = openai.Decode(raw)
	}
	if err != nil {
		x.rec.Decision, x.rec.Status, x.rec.Reason = audit.DecisionUpstreamError, http.StatusBadGateway, err.Error()
		writeError(w, x.rec.Status, "invalid upstream response", "upstream_error", "bad_upstream_response")
		return
	}
	t0 := time.Now()
	rules := x.profile.Response
	dets := rules.Active(x.snap.Detectors)
	for _, ch := range openai.Choices(o) {
		msg := openai.SubObject(ch, "message")
		text, ok := msg["content"].(string)
		if !ok {
			continue
		}
		res := filter.Apply(dets, rules.For, x.namer, text)
		s.record(x.rec, "response", fmt.Sprintf("choices[%d]", openai.Index(ch)), res.Findings)
		msg["content"] = res.Text
		if res.Blocked != nil {
			ch["finish_reason"] = openai.ContentFilter
			x.rec.Decision, x.rec.Reason = audit.DecisionBlockedResponse, string(res.Blocked.Kind)
		}
	}
	s.o.Metrics.Add("gw_guard_seconds_total", time.Since(t0).Seconds())
	if x.rec.Decision == audit.DecisionAllowed && hasAction(x.rec.Findings, policy.Redact) {
		x.rec.Decision = audit.DecisionRedacted
	}
	out, err := openai.Encode(o)
	if err != nil {
		x.rec.Decision, x.rec.Status = audit.DecisionUpstreamError, http.StatusBadGateway
		writeError(w, x.rec.Status, "could not encode response", "upstream_error", "bad_upstream_response")
		return
	}
	x.rec.Status = http.StatusOK
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}
