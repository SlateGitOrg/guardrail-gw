// Package detect implements the PII and secret detectors used by the gateway.
//
// Every detector satisfies a contract that makes streaming redaction exact:
//
//   - A match is at most MaxLen bytes long and consists only of bytes in the
//     detector's alphabet (InAlphabet).
//   - Whether a candidate starting at s is accepted depends only on
//     text[s-LeftContext : j+1], where j is the first byte at or after s that is
//     outside the alphabet (or s+MaxLen, whichever comes first).
//   - FindFrom scans leftmost-first and is deterministic.
//
// Regular-expression detectors derive MaxLen and the alphabet from the pattern
// itself (see AnalyzePattern), so the contract cannot drift from the regex.
package detect

import (
	"fmt"
	"regexp"
)

// Category groups detector kinds for policy purposes.
type Category string

// Detector categories.
const (
	CategoryPII    Category = "pii"
	CategorySecret Category = "secret"
)

// Kind identifies a specific detector.
type Kind string

// PII kinds.
const (
	KindEmail      Kind = "email"
	KindPhone      Kind = "phone"
	KindCreditCard Kind = "credit_card"
	KindIBAN       Kind = "iban"
	KindUSSSN      Kind = "us_ssn"
	KindAadhaar    Kind = "in_aadhaar"
	KindSpanishID  Kind = "es_dni"
	KindChineseRIC Kind = "cn_ric"
)

// Secret kinds.
const (
	KindAWSAccessKey   Kind = "aws_access_key"
	KindGitHubToken    Kind = "github_token"
	KindSlackToken     Kind = "slack_token"
	KindStripeKey      Kind = "stripe_key"
	KindGoogleAPIKey   Kind = "google_api_key"
	KindLLMAPIKey      Kind = "llm_api_key"
	KindJWT            Kind = "jwt"
	KindPrivateKey     Kind = "private_key"
	KindCredentialPair Kind = "credential_assignment"
	KindHighEntropy    Kind = "high_entropy_token"
)

// Finding is a detected span in absolute byte offsets [Start, End).
type Finding struct {
	Kind     Kind
	Category Category
	Priority int
	Start    int
	End      int
}

// Detector finds matches of one kind.
type Detector interface {
	Kind() Kind
	Category() Category
	// Priority breaks ties when findings of different kinds overlap.
	Priority() int
	// MaxLen is the maximum match length in bytes.
	MaxLen() int
	// LeftContext is how many bytes before a candidate the detector inspects.
	LeftContext() int
	// InAlphabet reports whether b can occur inside a match.
	InAlphabet(b byte) bool
	// FindFrom returns the leftmost accepted match with start >= from.
	// Bytes before from are available as left context.
	FindFrom(text string, from int) (start, end int, ok bool)
}

// acceptFunc inspects the regex match text[s:e] and returns the accepted end
// (which may be shorter than e) or ok=false to reject the candidate.
type acceptFunc func(text string, s, e int) (end int, ok bool)

// patternDetector is a Detector backed by a bounded, unanchored regexp plus a
// validation function.
type patternDetector struct {
	kind     Kind
	category Category
	priority int
	leftCtx  int
	re       *regexp.Regexp
	info     PatternInfo
	accept   acceptFunc
}

func newPattern(kind Kind, cat Category, prio, leftCtx int, expr string, accept acceptFunc) (Detector, error) {
	info, err := AnalyzePattern(expr)
	if err != nil {
		return nil, fmt.Errorf("detector %s: %w", kind, err)
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		return nil, fmt.Errorf("detector %s: %w", kind, err)
	}
	if accept == nil {
		accept = func(_ string, _, e int) (int, bool) { return e, true }
	}
	return &patternDetector{kind: kind, category: cat, priority: prio, leftCtx: leftCtx, re: re, info: info, accept: accept}, nil
}

func (p *patternDetector) Kind() Kind             { return p.kind }
func (p *patternDetector) Category() Category     { return p.category }
func (p *patternDetector) Priority() int          { return p.priority }
func (p *patternDetector) MaxLen() int            { return p.info.MaxLen }
func (p *patternDetector) LeftContext() int       { return p.leftCtx }
func (p *patternDetector) InAlphabet(b byte) bool { return p.info.Alphabet.Contains(b) }

func (p *patternDetector) FindFrom(text string, from int) (int, int, bool) {
	for from <= len(text) {
		loc := p.re.FindStringIndex(text[from:])
		if loc == nil {
			return 0, 0, false
		}
		s, e := from+loc[0], from+loc[1]
		if e > s {
			if end, ok := p.accept(text, s, e); ok && end > s && end <= e {
				return s, end, true
			}
		}
		from = s + 1
	}
	return 0, 0, false
}

// FindAll runs d over a complete text and returns every accepted match.
func FindAll(d Detector, text string) []Finding {
	var out []Finding
	from := 0
	for {
		s, e, ok := d.FindFrom(text, from)
		if !ok {
			return out
		}
		out = append(out, Finding{Kind: d.Kind(), Category: d.Category(), Priority: d.Priority(), Start: s, End: e})
		from = e
	}
}

// byteAt returns text[i] or 0 when i is out of range (0 acts as a boundary).
func byteAt(text string, i int) byte {
	if i < 0 || i >= len(text) {
		return 0
	}
	return text[i]
}

// leftWordBoundary: the byte before s is not alphanumeric.
func leftWordBoundary(text string, s int) bool { return !isAlnum(byteAt(text, s-1)) }

// rightWordBoundary: the byte at e is not alphanumeric.
func rightWordBoundary(text string, e int) bool { return !isAlnum(byteAt(text, e)) }

func isNumSep(c byte) bool { return c == ' ' || c == '-' || c == '.' }

// leftNumericBoundary rejects starts inside a longer digit group sequence such
// as "12 3456..." (a separator preceded by a digit) or after '+'.
func leftNumericBoundary(text string, s int) bool {
	p := byteAt(text, s-1)
	if isAlnum(p) || p == '+' || p == '_' {
		return false
	}
	if isNumSep(p) && isDigit(byteAt(text, s-2)) {
		return false
	}
	return true
}

// rightNumericBoundary rejects ends followed by more digit groups.
func rightNumericBoundary(text string, e int) bool {
	n := byteAt(text, e)
	if isAlnum(n) || n == '_' {
		return false
	}
	if isNumSep(n) && isDigit(byteAt(text, e+1)) {
		return false
	}
	return true
}

// separators returns the distinct separator bytes (space, '-', '.') in s.
func separators(s string) string {
	var seen [3]bool
	out := make([]byte, 0, 3)
	for i := 0; i < len(s); i++ {
		idx := -1
		switch s[i] {
		case ' ':
			idx = 0
		case '-':
			idx = 1
		case '.':
			idx = 2
		}
		if idx >= 0 && !seen[idx] {
			seen[idx] = true
			out = append(out, s[i])
		}
	}
	return string(out)
}

// withLookahead returns a constructor wrapper that widens a detector's
// alphabet with bytes its accept function peeks at beyond the match end
// (for example the separator in "123-45-6789-0"). Keeping such bytes in the
// alphabet preserves the streaming contract.
func withLookahead(extra string) func(Detector, error) (Detector, error) {
	return func(d Detector, err error) (Detector, error) {
		if err != nil {
			return nil, err
		}
		p := d.(*patternDetector)
		for i := 0; i < len(extra); i++ {
			p.info.Alphabet[extra[i]] = true
		}
		return p, nil
	}
}
