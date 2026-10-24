package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestDemoRuns(t *testing.T) {
	var out bytes.Buffer
	if err := run(t.TempDir(), &out); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	for _, want := range []string{
		`upstream actually received: "Please email [EMAIL_1] or call +1 415-555-0132; card [CREDIT_CARD_1]."`,
		"HTTP 400 secret_blocked",
		"HTTP 400 prompt_injection",
		`assembled (finish=stop): "Sure. The card on file is [CREDIT_CARD_1] and receipts go to [EMAIL_1]."`,
		`assembled (finish=content_filter): "The deploy script uses "`,
		"reloaded: false",
		"request 3 -> HTTP 429",
		"9 records, chain verified",
		"hash mismatch",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("demo output missing %q", want)
		}
	}
	if strings.Contains(s, "4111 1111 1111 1111\"") && !strings.Contains(s, "upstream sends") {
		t.Error("raw card leaked to client output")
	}
}
