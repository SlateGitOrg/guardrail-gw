package filter

import (
	"testing"

	"github.com/archit2501/guardrail-gw/internal/corpus"
	"github.com/archit2501/guardrail-gw/internal/policy"
)

func benchText() string {
	return "Here is a draft reply for the customer. " + corpus.NewGen("heldout", 7).NoisyText(180)
}

// BenchmarkApply measures whole-text filtering throughput (all detectors).
func BenchmarkApply(b *testing.B) {
	dets := allDetectors(b)
	text := benchText()
	b.SetBytes(int64(len(text)))
	for b.Loop() {
		Apply(dets, constant(policy.Redact), NewNamer(), text)
	}
}

// BenchmarkStream4 measures streaming with 4-byte deltas (~1 token each).
func BenchmarkStream4(b *testing.B) {
	dets := allDetectors(b)
	text := benchText()
	b.SetBytes(int64(len(text)))
	for b.Loop() {
		s := NewStream(dets, constant(policy.Redact), NewNamer())
		for i := 0; i < len(text); i += 4 {
			s.Write(text[i:min(i+4, len(text))])
		}
		s.Close()
	}
}
