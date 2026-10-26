// Package eval scores the detectors and the injection scorer against the
// labeled synthetic corpus.
package eval

import (
	"fmt"
	"io"
	"math"
	"sort"

	"github.com/SlateGitOrg/guardrail-gw/internal/corpus"
	"github.com/SlateGitOrg/guardrail-gw/internal/detect"
	"github.com/SlateGitOrg/guardrail-gw/internal/filter"
	"github.com/SlateGitOrg/guardrail-gw/internal/injection"
	"github.com/SlateGitOrg/guardrail-gw/internal/policy"
)

// Counts holds confusion counts.
type Counts struct {
	TP, FP, FN int
}

// Precision returns TP/(TP+FP) (1 when nothing was predicted).
func (c Counts) Precision() float64 { return ratio(c.TP, c.TP+c.FP) }

// Recall returns TP/(TP+FN) (1 when nothing was expected).
func (c Counts) Recall() float64 { return ratio(c.TP, c.TP+c.FN) }

// F1 is the harmonic mean of precision and recall.
func (c Counts) F1() float64 {
	p, r := c.Precision(), c.Recall()
	if p+r == 0 {
		return 0
	}
	return 2 * p * r / (p + r)
}

func ratio(a, b int) float64 {
	if b == 0 {
		return 1
	}
	return float64(a) / float64(b)
}

// DetectionReport summarizes span-level detector quality.
type DetectionReport struct {
	Samples int
	Gold    int
	// Strict: same kind and exact span.
	Strict map[detect.Kind]*Counts
	// Covered: a gold span counts as found when any prediction of the same
	// category overlaps it; a prediction is correct when it overlaps a gold
	// span of its category. This is what matters for redaction.
	Covered map[detect.Category]*Counts
}

// Detection evaluates every detector in set (all actions = log) on samples.
func Detection(set *detect.Set, samples []corpus.Sample) DetectionReport {
	rep := DetectionReport{Samples: len(samples), Strict: map[detect.Kind]*Counts{}, Covered: map[detect.Category]*Counts{}}
	for _, k := range detect.AllKinds() {
		rep.Strict[k] = &Counts{}
	}
	for _, c := range []detect.Category{detect.CategoryPII, detect.CategorySecret} {
		rep.Covered[c] = &Counts{}
	}
	logAll := func(detect.Kind, detect.Category) policy.Action { return policy.Log }
	for _, s := range samples {
		pred := filter.Apply(set.Detectors(), logAll, filter.NewNamer(), s.Text).Findings
		rep.Gold += len(s.Spans)
		matched := make([]bool, len(pred))
		for _, g := range s.Spans {
			gcat, _ := detect.CategoryOf(g.Kind)
			exact, covered := false, false
			for i, p := range pred {
				if p.Start == g.Start && p.End == g.End && p.Kind == g.Kind {
					exact = true
				}
				if p.Category == gcat && p.Start < g.End && g.Start < p.End {
					covered = true
					matched[i] = true
				}
			}
			if exact {
				rep.Strict[g.Kind].TP++
			} else {
				rep.Strict[g.Kind].FN++
			}
			if covered {
				rep.Covered[gcat].TP++
			} else {
				rep.Covered[gcat].FN++
			}
		}
		for i, p := range pred {
			exact := false
			for _, g := range s.Spans {
				if p.Start == g.Start && p.End == g.End && p.Kind == g.Kind {
					exact = true
				}
			}
			if !exact {
				rep.Strict[p.Kind].FP++
			}
			if !matched[i] {
				rep.Covered[p.Category].FP++
			}
		}
	}
	return rep
}

// InjectionReport summarizes scorer quality at a threshold.
type InjectionReport struct {
	Samples   int
	Threshold float64
	Counts    Counts
	TN        int
	AUC       float64
}

// Scores returns the scorer's value for each sample.
func Scores(samples []corpus.InjectionSample) []float64 {
	out := make([]float64, len(samples))
	for i, s := range samples {
		out[i] = injection.Evaluate(s.Text).Value
	}
	return out
}

// Injection evaluates at threshold t.
func Injection(samples []corpus.InjectionSample, scores []float64, t float64) InjectionReport {
	rep := InjectionReport{Samples: len(samples), Threshold: t, AUC: AUC(samples, scores)}
	for i, s := range samples {
		hit := scores[i] >= t
		switch {
		case hit && s.Label == 1:
			rep.Counts.TP++
		case hit:
			rep.Counts.FP++
		case s.Label == 1:
			rep.Counts.FN++
		default:
			rep.TN++
		}
	}
	return rep
}

// AUC computes the ROC area via the Mann-Whitney U statistic (ties = 1/2).
func AUC(samples []corpus.InjectionSample, scores []float64) float64 {
	var pos, neg []float64
	for i, s := range samples {
		if s.Label == 1 {
			pos = append(pos, scores[i])
		} else {
			neg = append(neg, scores[i])
		}
	}
	if len(pos) == 0 || len(neg) == 0 {
		return math.NaN()
	}
	sort.Float64s(neg)
	u := 0.0
	for _, p := range pos {
		lo := sort.SearchFloat64s(neg, p)
		hi := sort.Search(len(neg), func(i int) bool { return neg[i] > p })
		u += float64(lo) + 0.5*float64(hi-lo)
	}
	return u / float64(len(pos)*len(neg))
}

// BestThreshold returns the candidate threshold with the highest F1 (ties
// favor the higher threshold, i.e. fewer false positives).
func BestThreshold(samples []corpus.InjectionSample, scores []float64, candidates []float64) (float64, float64) {
	best, bestF1 := candidates[0], -1.0
	for _, t := range candidates {
		if f := Injection(samples, scores, t).Counts.F1(); f >= bestF1 {
			best, bestF1 = t, f
		}
	}
	return best, bestF1
}

// WriteDetectionMarkdown renders a report as Markdown tables.
func WriteDetectionMarkdown(w io.Writer, title string, r DetectionReport) {
	fmt.Fprintf(w, "### %s\n\n%d samples, %d gold spans.\n\n", title, r.Samples, r.Gold)
	fmt.Fprintln(w, "| category (overlap match) | TP | FP | FN | precision | recall | F1 |")
	fmt.Fprintln(w, "|---|---:|---:|---:|---:|---:|---:|")
	for _, c := range []detect.Category{detect.CategoryPII, detect.CategorySecret} {
		x := r.Covered[c]
		fmt.Fprintf(w, "| %s | %d | %d | %d | %.3f | %.3f | %.3f |\n", c, x.TP, x.FP, x.FN, x.Precision(), x.Recall(), x.F1())
	}
	fmt.Fprintln(w, "\n| kind (exact span + kind) | TP | FP | FN | precision | recall | F1 |")
	fmt.Fprintln(w, "|---|---:|---:|---:|---:|---:|---:|")
	for _, k := range detect.AllKinds() {
		x := r.Strict[k]
		fmt.Fprintf(w, "| %s | %d | %d | %d | %.3f | %.3f | %.3f |\n", k, x.TP, x.FP, x.FN, x.Precision(), x.Recall(), x.F1())
	}
	fmt.Fprintln(w)
}

// WriteInjectionMarkdown renders an injection report.
func WriteInjectionMarkdown(w io.Writer, title string, r InjectionReport) {
	c := r.Counts
	fmt.Fprintf(w, "### %s\n\n", title)
	fmt.Fprintln(w, "| samples | threshold | TP | FP | FN | TN | precision | recall | F1 | ROC-AUC |")
	fmt.Fprintln(w, "|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
	fmt.Fprintf(w, "| %d | %.2f | %d | %d | %d | %d | %.3f | %.3f | %.3f | %.3f |\n\n",
		r.Samples, r.Threshold, c.TP, c.FP, c.FN, r.TN, c.Precision(), c.Recall(), c.F1(), r.AUC)
}
