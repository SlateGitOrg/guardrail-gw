package audit

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestChainRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	for i := 0; i < 5; i++ {
		err := l.Append(Record{RequestID: "r", Decision: DecisionAllowed, Status: 200,
			Findings: []Finding{{Direction: "request", Kind: "email", Action: "redact", ValueHMAC: "ab"}}})
		if err != nil {
			t.Fatal(err)
		}
	}
	n, err := Verify(bytes.NewReader(buf.Bytes()))
	if err != nil || n != 5 {
		t.Fatalf("verify: n=%d err=%v", n, err)
	}
	if strings.Contains(buf.String(), "value\"") {
		t.Fatal("raw value field must not exist")
	}
}

func TestTamperDetection(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	for i := 0; i < 3; i++ {
		_ = l.Append(Record{RequestID: "r", Decision: DecisionBlockedRequest, Status: 400})
	}
	lines := strings.SplitAfter(strings.TrimSuffix(buf.String(), "\n"), "\n")
	cases := map[string]string{
		"edited":    strings.Replace(buf.String(), DecisionBlockedRequest, DecisionAllowed, 1),
		"deleted":   lines[0] + lines[2],
		"reordered": lines[1] + lines[0] + lines[2],
		"truncated": strings.Replace(buf.String(), `,"hash":"`, `,"hsh":"`, 1),
	}
	for name, tampered := range cases {
		if _, err := Verify(strings.NewReader(tampered)); err == nil {
			t.Errorf("%s: tampering not detected", name)
		}
	}
}

func TestOpenResumesChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	for round := 0; round < 2; round++ {
		l, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 3; i++ {
			if err := l.Append(Record{RequestID: "x", Decision: DecisionAllowed}); err != nil {
				t.Fatal(err)
			}
		}
		if err := l.Close(); err != nil {
			t.Fatal(err)
		}
	}
	f, _ := os.Open(path)
	defer f.Close()
	if n, err := Verify(f); err != nil || n != 6 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	// A corrupted existing log refuses to open rather than silently forking.
	b, _ := os.ReadFile(path)
	_ = os.WriteFile(path, bytes.Replace(b, []byte(`"x"`), []byte(`"y"`), 1), 0o600)
	if _, err := Open(path); err == nil {
		t.Fatal("expected error opening tampered log")
	}
	if _, err := Open(filepath.Join(t.TempDir(), "missing-dir", "a.jsonl")); err == nil {
		t.Fatal("expected error for missing directory")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestAppendErrorKeepsSequence(t *testing.T) {
	l := New(failWriter{})
	if err := l.Append(Record{}); err == nil {
		t.Fatal("expected error")
	}
	if l.seq != 0 {
		t.Fatalf("seq advanced on failure: %d", l.seq)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestHasher(t *testing.T) {
	h, keyed := NewHasher([]byte("k"))
	if !keyed {
		t.Fatal("expected keyed")
	}
	a, b := h.Digest("email", "a@b.io"), h.Digest("email", "a@b.io")
	if a != b || len(a) != 24 {
		t.Fatalf("digest %q %q", a, b)
	}
	if h.Digest("phone", "a@b.io") == a {
		t.Fatal("kind must be part of the digest")
	}
	r, keyed := NewHasher(nil)
	if keyed || r.Digest("email", "a@b.io") == a {
		t.Fatal("random key expected")
	}
}
