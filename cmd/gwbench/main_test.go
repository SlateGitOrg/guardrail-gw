package main

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBenchSmoke(t *testing.T) {
	var out bytes.Buffer
	path := filepath.Join(t.TempDir(), "bench.md")
	if err := run(options{n: 20, c: 2, warmup: 5, piece: 16, out: path}, &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"| buffered | 20 | 2 |", "streaming (16-byte deltas)", "overhead p99 ms"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in %s", want, out.String())
		}
	}
	if b, err := os.ReadFile(path); err != nil || !bytes.Equal(b, out.Bytes()) {
		t.Fatal("report file not written")
	}
}

func TestPercentile(t *testing.T) {
	d := []time.Duration{5, 1, 4, 2, 3, 6, 7, 8, 9, 10}
	if p := percentile(d, 0.5); p != 5 {
		t.Fatalf("p50=%v", p)
	}
	if p := percentile(d, 0.99); p != 10 {
		t.Fatalf("p99=%v", p)
	}
	if p := percentile(d[:1], 0.99); p != 5 {
		t.Fatalf("single=%v", p)
	}
}

func TestLoadError(t *testing.T) {
	if _, err := load(&http.Client{}, "http://127.0.0.1:9", nil, 3, 2); err == nil {
		t.Fatal("expected connection error")
	}
}
