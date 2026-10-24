// Command corpusgen regenerates the committed synthetic evaluation corpus.
// Output is deterministic: the same seeds always produce identical files.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/archit2501/guardrail-gw/internal/corpus"
)

// Spec fixes the seed and size of every corpus file.
type Spec struct {
	File  string
	Write func(io.Writer) error
}

// Specs lists the committed corpus files (also used by the drift test).
func Specs() []Spec {
	return []Spec{
		{"detection-dev.jsonl", func(w io.Writer) error { return corpus.WriteJSONL(w, corpus.Detection("dev", 101, 1500)) }},
		{"detection-heldout.jsonl", func(w io.Writer) error { return corpus.WriteJSONL(w, corpus.Detection("heldout", 202, 1500)) }},
		{"injection-dev.jsonl", func(w io.Writer) error { return corpus.WriteJSONL(w, corpus.Injection("dev", 303, 600)) }},
		{"injection-heldout.jsonl", func(w io.Writer) error { return corpus.WriteJSONL(w, corpus.Injection("heldout", 404, 600)) }},
	}
}

func main() {
	out := flag.String("out", "testdata/corpus", "output directory")
	flag.Parse()
	if err := generate(*out); err != nil {
		fmt.Fprintln(os.Stderr, "corpusgen:", err)
		os.Exit(1)
	}
}

func generate(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, s := range Specs() {
		f, err := os.Create(filepath.Join(dir, s.File))
		if err != nil {
			return err
		}
		if err := s.Write(f); err != nil {
			_ = f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		fmt.Println("wrote", filepath.Join(dir, s.File))
	}
	return nil
}
