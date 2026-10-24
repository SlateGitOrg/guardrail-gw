// Package fakeupstream is a deterministic OpenAI-compatible chat server used
// by tests, the offline demo and the overhead benchmark in place of Ollama.
package fakeupstream

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Server implements /v1/chat/completions and /v1/models.
type Server struct {
	// Reply computes the assistant text from the last user message.
	Reply func(lastUser string) string
	// Pieces splits the reply into content deltas (default: 4-byte pieces).
	Pieces func(reply string) []string
	// ByteSplits, when set, splits the raw SSE byte stream into writes of the
	// returned sizes, flushing after each, to exercise network fragmentation.
	ByteSplits func(total int) []int
	// Delay is slept before each streamed chunk.
	Delay time.Duration

	mu   sync.Mutex
	last []byte
}

// DefaultReply is the scripted assistant used by the demo.
func DefaultReply(lastUser string) string {
	l := strings.ToLower(lastUser)
	switch {
	case strings.Contains(l, "card on file"):
		return "Sure. The card on file is 4111 1111 1111 1111 and receipts go to billing.ops@example.com."
	case strings.Contains(l, "deploy key"):
		return "The deploy script uses AKIAIOSFODNN7EXAMPLE as its access key id."
	case strings.Contains(l, "contact"):
		return "You can reach Dana at +1 415-555-0132 or dana.r@example.org."
	}
	return "Echo: " + lastUser
}

// FixedPieces splits s into pieces of n bytes (the last may be shorter).
func FixedPieces(n int) func(string) []string {
	return func(s string) []string {
		var out []string
		for len(s) > n {
			out = append(out, s[:n])
			s = s[n:]
		}
		if s != "" {
			out = append(out, s)
		}
		return out
	}
}

// LastRequest returns the most recent request body the server received.
func (s *Server) LastRequest() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.last...)
}

// ServeHTTP routes requests.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/models":
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"object":"list","data":[{"id":"fake-model","object":"model","owned_by":"fakeupstream"}]}`)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/chat/completions":
		s.chat(w, r)
	default:
		http.Error(w, `{"error":{"message":"not found"}}`, http.StatusNotFound)
	}
}

type message struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

func (s *Server) chat(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.last = body
	s.mu.Unlock()
	var req struct {
		Model    string    `json:"model"`
		Stream   bool      `json:"stream"`
		Messages []message `json:"messages"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":{"message":"bad json"}}`, http.StatusBadRequest)
		return
	}
	last := ""
	for _, m := range req.Messages {
		if m.Role == "user" {
			var str string
			if json.Unmarshal(m.Content, &str) == nil {
				last = str
			}
		}
	}
	reply := DefaultReply
	if s.Reply != nil {
		reply = s.Reply
	}
	text := reply(last)
	if !req.Stream {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "chatcmpl-fake", "object": "chat.completion", "created": 1700000000, "model": req.Model,
			"choices": []any{map[string]any{"index": 0, "finish_reason": "stop",
				"message": map[string]any{"role": "assistant", "content": text}}},
			"usage": map[string]int{"prompt_tokens": len(last) / 4, "completion_tokens": len(text) / 4},
		})
		return
	}
	s.stream(w, req.Model, text)
}

func (s *Server) stream(w http.ResponseWriter, model, text string) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	pieces := FixedPieces(4)
	if s.Pieces != nil {
		pieces = s.Pieces
	}
	var raw strings.Builder
	chunk := func(delta map[string]any, finish any) {
		b, _ := json.Marshal(map[string]any{
			"id": "chatcmpl-fake", "object": "chat.completion.chunk", "created": 1700000000, "model": model,
			"choices": []any{map[string]any{"index": 0, "delta": delta, "finish_reason": finish}},
		})
		fmt.Fprintf(&raw, "data: %s\n\n", b)
	}
	chunk(map[string]any{"role": "assistant", "content": ""}, nil)
	for _, p := range pieces(text) {
		chunk(map[string]any{"content": p}, nil)
	}
	chunk(map[string]any{}, "stop")
	raw.WriteString("data: [DONE]\n\n")

	data := raw.String()
	sizes := []int{}
	if s.ByteSplits != nil {
		sizes = s.ByteSplits(len(data))
	} else {
		// One write per SSE event.
		for _, ev := range strings.SplitAfter(data, "\n\n") {
			if ev != "" {
				sizes = append(sizes, len(ev))
			}
		}
	}
	flusher, _ := w.(http.Flusher)
	for _, n := range sizes {
		if n > len(data) {
			n = len(data)
		}
		if s.Delay > 0 {
			time.Sleep(s.Delay)
		}
		if _, err := io.WriteString(w, data[:n]); err != nil {
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
		data = data[n:]
	}
	if data != "" {
		_, _ = io.WriteString(w, data)
	}
}
