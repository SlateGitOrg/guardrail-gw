package sse

import (
	"bytes"
	"errors"
	"io"
	"math/rand/v2"
	"reflect"
	"strings"
	"testing"
)

// chunkReader returns at most the next cut's worth of bytes per Read.
type chunkReader struct {
	data []byte
	r    *rand.Rand
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if len(c.data) == 0 {
		return 0, io.EOF
	}
	n := min(len(p), 1+c.r.IntN(7), len(c.data))
	copy(p, c.data[:n])
	c.data = c.data[n:]
	return n, nil
}

func readAll(t *testing.T, r io.Reader) []Event {
	t.Helper()
	sr := NewReader(r, 1<<16)
	var out []Event
	for {
		ev, err := sr.Next()
		if err == io.EOF || errors.Is(err, io.ErrUnexpectedEOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, ev)
	}
}

func TestParse(t *testing.T) {
	in := ": keepalive\r\n" +
		"data: {\"a\":1}\n\n" +
		"event: ping\rdata:x\rdata: y\r\r" +
		"id: 7\r\ndata: [DONE]\r\n\r\n" +
		"\n\n" +
		"data: unterminated"
	got := readAll(t, strings.NewReader(in))
	want := []Event{{Data: `{"a":1}`}, {Name: "ping", Data: "x\ny"}, {ID: "7", Data: "[DONE]"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

func TestRoundTripRandomSplits(t *testing.T) {
	events := []Event{{Data: `{"choices":[{"delta":{"content":"héllo 🔐"}}]}`}, {Name: "x", ID: "1", Data: "a\nb"}, {Data: "[DONE]"}}
	var buf bytes.Buffer
	for _, ev := range events {
		if err := Write(&buf, ev); err != nil {
			t.Fatal(err)
		}
	}
	for seed := uint64(0); seed < 200; seed++ {
		got := readAll(t, &chunkReader{data: buf.Bytes(), r: rand.New(rand.NewPCG(seed, 1))})
		if !reflect.DeepEqual(got, events) {
			t.Fatalf("seed %d: got %+v", seed, got)
		}
	}
}

func TestLimits(t *testing.T) {
	r := NewReader(strings.NewReader("data: "+strings.Repeat("x", 100)+"\n\n"), 50)
	if _, err := r.Next(); !errors.Is(err, ErrEventTooLarge) {
		t.Fatalf("err=%v", err)
	}
	r = NewReader(strings.NewReader("data: aaaa\ndata: bbbb\ndata: cccc\n\n"), 25)
	if _, err := r.Next(); !errors.Is(err, ErrEventTooLarge) {
		t.Fatalf("multi-line err=%v", err)
	}
}

type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errors.New("closed") }

func TestWriteError(t *testing.T) {
	if Write(errWriter{}, Event{Data: "x"}) == nil {
		t.Fatal("expected error")
	}
}

func TestBuffered(t *testing.T) {
	r := NewReader(strings.NewReader("data: a\n\ndata: b\n\n"), 100)
	if _, err := r.Next(); err != nil {
		t.Fatal(err)
	}
	if r.Buffered() == 0 {
		t.Fatal("second event should already be buffered")
	}
	if _, err := r.Next(); err != nil || r.Buffered() != 0 {
		t.Fatalf("err=%v buffered=%d", err, r.Buffered())
	}
}
