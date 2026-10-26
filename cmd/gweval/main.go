// Command gweval measures detector precision/recall and injection-scorer
// quality on the committed synthetic corpus.
//
// Thresholds are tuned with -sweep on the dev split only; the reported
// numbers come from the held-out split, which uses disjoint templates and
// vocabularies.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/SlateGitOrg/guardrail-gw/internal/config"
	"github.com/SlateGitOrg/guardrail-gw/internal/corpus"
	"github.com/SlateGitOrg/guardrail-gw/internal/detect"
	"github.com/SlateGitOrg/guardrail-gw/internal/eval"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "gweval:", err)
		os.Exit(1)
	}
}

func load[T any](path string) ([]T, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return corpus.ReadJSONL[T](f)
}

func run(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("gweval", flag.ContinueOnError)
	dir := fs.String("corpus", "testdata/corpus", "corpus directory")
	split := fs.String("split", "heldout", "dev or heldout")
	sweep := fs.Bool("sweep", false, "print threshold sweeps (dev split only)")
	threshold := fs.Float64("threshold", config.DefaultInjection, "injection threshold to report")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *split != "dev" && *split != "heldout" {
		return fmt.Errorf("split must be dev or heldout")
	}
	if *sweep && *split != "dev" {
		return errors.New("refusing to sweep thresholds on the held-out split (tune on dev)")
	}
	det, err := load[corpus.Sample](filepath.Join(*dir, "detection-"+*split+".jsonl"))
	if err != nil {
		return err
	}
	inj, err := load[corpus.InjectionSample](filepath.Join(*dir, "injection-"+*split+".jsonl"))
	if err != nil {
		return err
	}
	set, err := detect.NewSet(detect.Options{})
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "## Evaluation on the %s split\n\n", *split)
	eval.WriteDetectionMarkdown(stdout, "Detectors", eval.Detection(set, det))
	scores := eval.Scores(inj)
	eval.WriteInjectionMarkdown(stdout, "Injection scorer", eval.Injection(inj, scores, *threshold))
	if *sweep {
		return writeSweeps(stdout, det, inj, scores)
	}
	return nil
}

func writeSweeps(w io.Writer, det []corpus.Sample, inj []corpus.InjectionSample, scores []float64) error {
	fmt.Fprintln(w, "### Entropy threshold sweep (dev)")
	fmt.Fprintln(w, "\n| min_bits | high_entropy P | high_entropy R | secret overlap P | secret overlap R |")
	fmt.Fprintln(w, "|---:|---:|---:|---:|---:|")
	for _, bits := range []float64{3.5, 3.75, 4.0, 4.25, 4.5, 4.75} {
		cfg := detect.DefaultEntropyConfig()
		cfg.MinBits = bits
		set, err := detect.NewSet(detect.Options{Entropy: cfg})
		if err != nil {
			return err
		}
		r := eval.Detection(set, det)
		he, sec := r.Strict[detect.KindHighEntropy], r.Covered[detect.CategorySecret]
		fmt.Fprintf(w, "| %.2f | %.3f | %.3f | %.3f | %.3f |\n", bits, he.Precision(), he.Recall(), sec.Precision(), sec.Recall())
	}
	var cands []float64
	for t := 0.30; t < 0.951; t += 0.05 {
		cands = append(cands, t)
	}
	fmt.Fprintln(w, "\n### Injection threshold sweep (dev)")
	fmt.Fprintln(w, "\n| threshold | precision | recall | F1 |")
	fmt.Fprintln(w, "|---:|---:|---:|---:|")
	for _, t := range cands {
		c := eval.Injection(inj, scores, t).Counts
		fmt.Fprintf(w, "| %.2f | %.3f | %.3f | %.3f |\n", t, c.Precision(), c.Recall(), c.F1())
	}
	best, f1 := eval.BestThreshold(inj, scores, cands)
	fmt.Fprintf(w, "\nBest dev F1 %.3f at threshold %.2f.\n", f1, best)
	return nil
}
