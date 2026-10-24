package gateway

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/archit2501/guardrail-gw/internal/audit"
	"github.com/archit2501/guardrail-gw/internal/filter"
	"github.com/archit2501/guardrail-gw/internal/openai"
	"github.com/archit2501/guardrail-gw/internal/policy"
	"github.com/archit2501/guardrail-gw/internal/sse"
)

// maxEventBytes bounds one upstream SSE event.
const maxEventBytes = 1 << 20

// streamState tracks one choice's filter.
type streamState struct {
	f       *filter.Stream
	blocked bool
	closed  bool
}

// streamProxy relays an upstream SSE chat stream through per-choice filters.
type streamProxy struct {
	s       *Server
	x       *exchange
	w       io.Writer
	flush   func()
	r       *sse.Reader
	choices map[int]*streamState
	meta    openai.Object // id/object/created/model from the latest chunk
	guard   time.Duration
}

func (s *Server) streamResponse(w http.ResponseWriter, cancel func(), x *exchange, body io.Reader) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	x.rec.Status = http.StatusOK
	flusher, _ := w.(http.Flusher)
	p := &streamProxy{s: s, x: x, w: w, choices: map[int]*streamState{}, meta: openai.Object{}, flush: func() {
		if flusher != nil {
			flusher.Flush()
		}
	}}
	defer func() {
		s.o.Metrics.Add("gw_guard_seconds_total", p.guard.Seconds())
		if x.rec.Decision == audit.DecisionAllowed && hasAction(x.rec.Findings, policy.Redact) {
			x.rec.Decision = audit.DecisionRedacted
		}
	}()
	p.r = sse.NewReader(body, maxEventBytes)
	err := p.run()
	cancel() // stop the upstream once we are done (normally or after a block)
	if err != nil {
		x.rec.Reason = err.Error()
		s.o.Logger.Warn("stream ended abnormally", "request_id", x.rec.RequestID, "err", err)
	}
}

func (p *streamProxy) state(idx int) *streamState {
	st, ok := p.choices[idx]
	if !ok {
		rules := p.x.profile.Response
		st = &streamState{f: filter.NewStream(rules.Active(p.x.snap.Detectors), rules.For, p.x.namer)}
		p.choices[idx] = st
	}
	return st
}

func (p *streamProxy) run() error {
	for {
		ev, err := p.r.Next()
		if err != nil {
			// Upstream ended without [DONE]: flush what is held, then stop.
			ferr := p.flushAll()
			if errors.Is(err, io.EOF) {
				return ferr
			}
			return errors.Join(fmt.Errorf("upstream stream: %w", err), ferr)
		}
		if ev.Data == "[DONE]" {
			if err := p.flushAll(); err != nil {
				return err
			}
			return p.emit(sse.Event{Data: "[DONE]"})
		}
		o, err := openai.Decode([]byte(ev.Data))
		if err != nil {
			// Never relay what we cannot inspect.
			p.s.o.Logger.Warn("dropping unparseable stream event", "request_id", p.x.rec.RequestID)
			continue
		}
		if _, isErr := o["error"]; isErr {
			if err := p.emit(sse.Event{Name: ev.Name, Data: ev.Data}); err != nil {
				return err
			}
			continue
		}
		done, err := p.chunk(o)
		if err != nil || done {
			return err
		}
	}
}

// chunk filters one upstream chunk. It reports done when every choice seen
// so far has been blocked (the stream is then terminated).
func (p *streamProxy) chunk(o openai.Object) (bool, error) {
	for _, k := range []string{"id", "object", "created", "model", "system_fingerprint"} {
		if v, ok := o[k]; ok {
			p.meta[k] = v
		}
	}
	src := openai.Choices(o)
	kept := make([]any, 0, len(src))
	for _, ch := range src {
		if p.filterChoice(ch) {
			kept = append(kept, ch)
		}
	}
	if len(src) > 0 && len(kept) == 0 {
		return p.allBlocked(), nil // nothing to send for this chunk
	}
	if len(src) > 0 {
		o["choices"] = kept
	}
	b, err := openai.Encode(o)
	if err != nil {
		return false, err
	}
	if err := p.emit(sse.Event{Data: string(b)}); err != nil {
		return false, err
	}
	if p.allBlocked() {
		return true, p.emit(sse.Event{Data: "[DONE]"})
	}
	return false, nil
}

func (p *streamProxy) allBlocked() bool {
	if len(p.choices) == 0 {
		return false
	}
	for _, st := range p.choices {
		if !st.blocked {
			return false
		}
	}
	return true
}

// filterChoice rewrites ch in place and reports whether it should be sent.
func (p *streamProxy) filterChoice(ch openai.Object) bool {
	idx := openai.Index(ch)
	st := p.state(idx)
	if st.blocked || st.closed {
		return false
	}
	delta := openai.SubObject(ch, "delta")
	text := ""
	if delta != nil {
		if c, ok := delta["content"].(string); ok {
			t0 := time.Now()
			res := st.f.Write(c)
			p.guard += time.Since(t0)
			text = p.apply(st, idx, res)
		}
	}
	if !st.blocked && openai.FinishReason(ch) != "" {
		t0 := time.Now()
		res := st.f.Close()
		p.guard += time.Since(t0)
		text += p.apply(st, idx, res)
		st.closed = true
	}
	if st.blocked {
		ch["finish_reason"] = openai.ContentFilter
	}
	if delta == nil {
		if text == "" {
			return openai.FinishReason(ch) != ""
		}
		delta = openai.Object{}
		ch["delta"] = delta
	}
	if _, had := delta["content"]; had || text != "" {
		delta["content"] = text
	}
	return text != "" || openai.FinishReason(ch) != "" || hasNonContent(delta)
}

// hasNonContent reports whether a delta carries anything besides content
// (role, tool_calls, refusal...).
func hasNonContent(delta openai.Object) bool {
	for k := range delta {
		if k != "content" {
			return true
		}
	}
	return false
}

func (p *streamProxy) apply(st *streamState, idx int, res filter.Result) string {
	p.s.record(p.x.rec, "response", fmt.Sprintf("choices[%d]", idx), res.Findings)
	if res.Blocked != nil {
		st.blocked = true
		p.x.rec.Decision, p.x.rec.Reason = audit.DecisionBlockedResponse, string(res.Blocked.Kind)
	}
	return res.Text
}

// flushAll closes every open choice filter and emits held text in one
// synthetic chunk.
func (p *streamProxy) flushAll() error {
	var choices []any
	for idx := 0; idx <= maxIndex(p.choices); idx++ {
		st, ok := p.choices[idx]
		if !ok || st.blocked || st.closed {
			continue
		}
		res := st.f.Close()
		st.closed = true
		text := p.apply(st, idx, res)
		if text == "" && !st.blocked {
			continue
		}
		ch := openai.Object{"index": idx, "delta": openai.Object{"content": text}, "finish_reason": nil}
		if st.blocked {
			ch["finish_reason"] = openai.ContentFilter
		}
		choices = append(choices, ch)
	}
	if len(choices) == 0 {
		return nil
	}
	o := openai.Object{"choices": choices}
	for k, v := range p.meta {
		o[k] = v
	}
	b, err := openai.Encode(o)
	if err != nil {
		return err
	}
	return p.emit(sse.Event{Data: string(b)})
}

func maxIndex(m map[int]*streamState) int {
	mx := -1
	for k := range m {
		mx = max(mx, k)
	}
	return mx
}

// emit writes one event. It flushes only when no further upstream bytes are
// already buffered, so bursts are coalesced into one write without delaying
// any event behind an upstream wait.
func (p *streamProxy) emit(ev sse.Event) error {
	if err := sse.Write(p.w, ev); err != nil {
		return fmt.Errorf("client write: %w", err)
	}
	if p.r.Buffered() == 0 || ev.Data == "[DONE]" {
		p.flush()
	}
	return nil
}
