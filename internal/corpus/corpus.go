package corpus

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/archit2501/guardrail-gw/internal/detect"
)

// Span is a gold label.
type Span struct {
	Start int         `json:"start"`
	End   int         `json:"end"`
	Kind  detect.Kind `json:"kind"`
}

// Sample is one labeled detector example.
type Sample struct {
	ID    string `json:"id"`
	Text  string `json:"text"`
	Spans []Span `json:"spans"`
}

// InjectionSample is one labeled prompt (Label 1 = injection attempt).
type InjectionSample struct {
	ID    string `json:"id"`
	Text  string `json:"text"`
	Label int    `json:"label"`
}

var slotRE = regexp.MustCompile(`\{([a-z_]+)\}`)

// fill expands one template at offset base, appending gold spans.
func (g *Gen) fill(tpl string, base int, spans *[]Span) string {
	var b strings.Builder
	last := 0
	for _, m := range slotRE.FindAllStringSubmatchIndex(tpl, -1) {
		b.WriteString(tpl[last:m[0]])
		slot := tpl[m[2]:m[3]]
		var v string
		if slot == "benign" {
			v = g.Benign()
		} else {
			k := detect.Kind(slot)
			v = g.Value(k)
			start := base + b.Len()
			*spans = append(*spans, Span{Start: start, End: start + len(v), Kind: k})
		}
		b.WriteString(v)
		last = m[1]
	}
	b.WriteString(tpl[last:])
	return b.String()
}

// Detection generates n labeled samples for split ("dev" or "heldout").
func Detection(split string, seed uint64, n int) []Sample {
	g := NewGen(split, seed)
	tpls := devTemplates
	if split == "heldout" {
		tpls = heldoutTemplates
	}
	out := make([]Sample, 0, n)
	for i := 0; i < n; i++ {
		var text strings.Builder
		spans := []Span{}
		parts := 1 + g.R.IntN(3)
		for p := 0; p < parts; p++ {
			if p > 0 {
				text.WriteString([]string{" ", "\n", " — ", "\n\n"}[g.R.IntN(4)])
			}
			text.WriteString(g.fill(tpls[g.R.IntN(len(tpls))], text.Len(), &spans))
		}
		out = append(out, Sample{ID: fmt.Sprintf("%s-%05d", split, i), Text: text.String(), Spans: spans})
	}
	return out
}

// Injection generates n labeled prompts (about 40% attacks) for split.
func Injection(split string, seed uint64, n int) []InjectionSample {
	g := NewGen(split, seed)
	attacks, benign := devInjectionAttacks, devBenignPrompts
	if split == "heldout" {
		attacks, benign = heldoutInjectionAttacks, heldoutBenignPrompts
	}
	out := make([]InjectionSample, 0, n)
	for i := 0; i < n; i++ {
		var text string
		label := 0
		if g.R.IntN(10) < 4 {
			label = 1
			a := strings.ReplaceAll(g.pick(attacks), "{goal}", g.pick(injectionGoals))
			text = fmt.Sprintf(g.pick(carriers), a)
		} else {
			text = fmt.Sprintf(g.pick(carriers), g.pick(benign))
		}
		out = append(out, InjectionSample{ID: fmt.Sprintf("%s-inj-%05d", split, i), Text: text, Label: label})
	}
	return out
}

// NoisyText returns random text interleaving prose, unicode, punctuation,
// hard negatives and sensitive values; used by streaming property tests.
func (g *Gen) NoisyText(parts int) string {
	words := []string{"the", "report", "is", "ready", "café", "naïve", "数据", "🔐", "ok", "and", "to", "id", "#42",
		"password:", "key=", "ssn", "aadhaar", "call", "Bearer", "2024", "v1.2", "@", "+", "-", ".", "x", "\n", "\t"}
	kinds := detect.AllKinds()
	var b strings.Builder
	for i := 0; i < parts; i++ {
		switch r := g.R.IntN(10); {
		case r < 5:
			b.WriteString(g.pick(words))
		case r < 7:
			b.WriteString(g.Value(kinds[g.R.IntN(len(kinds))]))
		case r < 8:
			b.WriteString(g.Benign())
		default:
			b.WriteString(g.digits(1 + g.R.IntN(20)))
		}
		b.WriteString([]string{" ", "", ", ", ". ", "\n", "-", "  "}[g.R.IntN(7)])
	}
	return b.String()
}

// WriteJSONL writes one JSON value per line.
func WriteJSONL[T any](w io.Writer, rows []T) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for _, r := range rows {
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	return nil
}

// ReadJSONL reads one JSON value per line.
func ReadJSONL[T any](r io.Reader) ([]T, error) {
	var out []T
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		if strings.TrimSpace(sc.Text()) == "" {
			continue
		}
		var v T
		if err := json.Unmarshal(sc.Bytes(), &v); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		out = append(out, v)
	}
	return out, sc.Err()
}
