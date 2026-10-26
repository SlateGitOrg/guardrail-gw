package injection

import (
	"testing"

	"github.com/SlateGitOrg/guardrail-gw/internal/corpus"
)

// BenchmarkEvaluate scores a ~1.6 KB prompt.
func BenchmarkEvaluate(b *testing.B) {
	text := "Please review this support thread and draft a reply. " + corpus.NewGen("heldout", 7).NoisyText(120)
	b.SetBytes(int64(len(text)))
	for b.Loop() {
		Evaluate(text)
	}
}
