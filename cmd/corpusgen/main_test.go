package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestCommittedCorpusMatchesGenerator guards against silent drift between
// the committed evaluation data and the generator code.
func TestCommittedCorpusMatchesGenerator(t *testing.T) {
	for _, s := range Specs() {
		var buf bytes.Buffer
		if err := s.Write(&buf); err != nil {
			t.Fatal(err)
		}
		committed, err := os.ReadFile(filepath.Join("..", "..", "testdata", "corpus", s.File))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(buf.Bytes(), committed) {
			t.Errorf("%s differs from generator output; run `make corpus`", s.File)
		}
	}
}

func TestGenerate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "c")
	if err := generate(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "injection-heldout.jsonl")); err != nil {
		t.Fatal(err)
	}
	if err := generate("/dev/null/x"); err == nil {
		t.Fatal("expected error")
	}
}
