package openai

import (
	"strings"
	"testing"
)

func TestParseAndRewrite(t *testing.T) {
	body := `{"model":"llama3.1:8b","stream":true,"temperature":0.2,"seed":12345678901234567890,
	"messages":[{"role":"system","content":"be nice <b>"},
	{"role":"user","content":[{"type":"text","text":"hi a@b.io"},{"type":"image_url","image_url":{"url":"x"}},"junk"]},
	{"role":"assistant","content":null,"tool_calls":[]}]}`
	r, err := ParseChatRequest([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if r.Model != "llama3.1:8b" || !r.Stream || len(r.Messages) != 3 || Role(r.Messages[1]) != "user" {
		t.Fatalf("%+v", r)
	}
	for _, m := range r.Messages {
		RewriteTexts(m, strings.ToUpper)
	}
	out, err := Encode(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{`"BE NICE <B>"`, `"HI A@B.IO"`, `"url":"x"`, `12345678901234567890`, `"tool_calls":[]`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s in %s", want, s)
		}
	}
}

func TestParseErrors(t *testing.T) {
	for _, b := range []string{
		``, `[]`, `null`, `{"messages":[]}`, `{"messages":"x"}`, `{"messages":[1]}`,
		`{"messages":[{"content":"x"}]}`, `{"messages":[{"role":"user"}]} {}`,
	} {
		if _, err := ParseChatRequest([]byte(b)); err == nil {
			t.Errorf("%q: expected error", b)
		}
	}
}

func TestChoices(t *testing.T) {
	o, err := Decode([]byte(`{"choices":[{"index":2,"delta":{"content":"x"},"finish_reason":"stop"},"bad",{"index":"z"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	cs := Choices(o)
	if len(cs) != 2 || Index(cs[0]) != 2 || Index(cs[1]) != 0 || FinishReason(cs[0]) != "stop" || FinishReason(cs[1]) != "" {
		t.Fatalf("%+v", cs)
	}
	if SubObject(cs[0], "delta")["content"] != "x" || SubObject(cs[1], "delta") != nil {
		t.Fatal("SubObject")
	}
	if len(Choices(Object{})) != 0 {
		t.Fatal("empty choices")
	}
}

func TestErrorBody(t *testing.T) {
	got := string(ErrorBody("blocked <x>", "guardrail_violation", "secret_blocked"))
	want := `{"error":{"code":"secret_blocked","message":"blocked <x>","type":"guardrail_violation"}}`
	if got != want {
		t.Fatalf("got %s", got)
	}
}
