// Package openai manipulates OpenAI-compatible chat payloads generically, so
// fields the gateway does not understand (tools, response_format, vendor
// extensions) pass through untouched.
package openai

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// Object is a decoded JSON object. Numbers are json.Number to keep precision.
type Object = map[string]any

// Decode parses a JSON object.
func Decode(b []byte) (Object, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var o Object
	if err := dec.Decode(&o); err != nil {
		return nil, err
	}
	if o == nil {
		return nil, errors.New("expected a JSON object")
	}
	if dec.More() {
		return nil, errors.New("trailing data after JSON object")
	}
	return o, nil
}

// Encode serializes an object without HTML escaping.
func Encode(o Object) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(o); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// ChatRequest is a parsed /v1/chat/completions request.
type ChatRequest struct {
	Body     Object
	Model    string
	Stream   bool
	Messages []Object
}

// ParseChatRequest validates the minimal shape of a chat request.
func ParseChatRequest(b []byte) (*ChatRequest, error) {
	o, err := Decode(b)
	if err != nil {
		return nil, fmt.Errorf("invalid JSON body: %w", err)
	}
	r := &ChatRequest{Body: o}
	if m, ok := o["model"].(string); ok {
		r.Model = m
	}
	if s, ok := o["stream"].(bool); ok {
		r.Stream = s
	}
	msgs, ok := o["messages"].([]any)
	if !ok || len(msgs) == 0 {
		return nil, errors.New("messages must be a non-empty array")
	}
	for i, m := range msgs {
		mo, ok := m.(Object)
		if !ok {
			return nil, fmt.Errorf("messages[%d] must be an object", i)
		}
		if _, ok := mo["role"].(string); !ok {
			return nil, fmt.Errorf("messages[%d].role must be a string", i)
		}
		r.Messages = append(r.Messages, mo)
	}
	return r, nil
}

// Role returns a message's role.
func Role(m Object) string {
	r, _ := m["role"].(string)
	return r
}

// RewriteTexts calls fn for every text segment of a message's content (a
// string, or an array of parts with type "text") and stores the result.
// Non-text parts (images, audio) are left unchanged.
func RewriteTexts(m Object, fn func(string) string) {
	switch c := m["content"].(type) {
	case string:
		m["content"] = fn(c)
	case []any:
		for _, p := range c {
			po, ok := p.(Object)
			if !ok {
				continue
			}
			if t, ok := po["type"].(string); ok && t == "text" {
				if s, ok := po["text"].(string); ok {
					po["text"] = fn(s)
				}
			}
		}
	}
}

// Choices returns the "choices" array of a response or stream chunk.
func Choices(o Object) []Object {
	arr, _ := o["choices"].([]any)
	out := make([]Object, 0, len(arr))
	for _, c := range arr {
		if co, ok := c.(Object); ok {
			out = append(out, co)
		}
	}
	return out
}

// Index returns a choice's "index" (0 when absent).
func Index(choice Object) int {
	if n, ok := choice["index"].(json.Number); ok {
		if i, err := n.Int64(); err == nil {
			return int(i)
		}
	}
	return 0
}

// SubObject returns choice[key] as an object ("message" or "delta").
func SubObject(choice Object, key string) Object {
	o, _ := choice[key].(Object)
	return o
}

// FinishReason returns the finish_reason or "" when null/absent.
func FinishReason(choice Object) string {
	s, _ := choice["finish_reason"].(string)
	return s
}

// ContentFilter is the finish_reason used when the gateway truncates output.
const ContentFilter = "content_filter"

// ErrorBody renders an OpenAI-style error object.
func ErrorBody(message, typ, code string) []byte {
	b, _ := Encode(Object{"error": Object{"message": message, "type": typ, "code": code}})
	return b
}
