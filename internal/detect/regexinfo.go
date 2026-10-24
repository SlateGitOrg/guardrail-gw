package detect

import (
	"errors"
	"fmt"
	"regexp/syntax"
	"unicode"
	"unicode/utf8"
)

// Alphabet is the set of bytes that can occur inside a detector match.
// The streaming engine uses it to decide how much trailing text is still
// "open" (could become part of a match once more text arrives).
type Alphabet [256]bool

// Contains reports whether b may occur inside a match.
func (a *Alphabet) Contains(b byte) bool { return a[b] }

func (a *Alphabet) addRange(lo, hi rune) {
	if lo < 0 {
		lo = 0
	}
	for r := lo; r <= hi && r < utf8.RuneSelf; r++ {
		a[byte(r)] = true
	}
	if hi >= utf8.RuneSelf {
		// Any multi-byte rune: mark every non-ASCII byte as possible.
		for b := utf8.RuneSelf; b < 256; b++ {
			a[byte(b)] = true
		}
	}
}

// AlphabetOf builds an alphabet from an explicit list of ASCII bytes and ranges
// written as "a-z" style pairs, e.g. AlphabetOf("A-Z", "0-9", "+/=").
func AlphabetOf(parts ...string) Alphabet {
	var a Alphabet
	for _, p := range parts {
		if len(p) == 3 && p[1] == '-' {
			a.addRange(rune(p[0]), rune(p[2]))
			continue
		}
		for i := 0; i < len(p); i++ {
			a[p[i]] = true
		}
	}
	return a
}

// ErrUnboundedPattern is returned when a pattern can match arbitrarily long
// text; streaming redaction requires a finite maximum match length.
var ErrUnboundedPattern = errors.New("pattern has unbounded repetition")

// ErrAnchoredPattern is returned for patterns that use zero-width assertions
// (^, $, \b, \B). Boundaries are checked in code with explicit context so
// that a scan resumed mid-text behaves identically to a full scan.
var ErrAnchoredPattern = errors.New("pattern uses zero-width assertions")

// PatternInfo is the static analysis of a detector regular expression.
type PatternInfo struct {
	MaxLen   int // maximum match length in bytes
	Alphabet Alphabet
	// First holds every byte a non-empty match can start with; scanning
	// skips positions whose byte is not in it.
	First Alphabet
}

// AnalyzePattern parses expr and derives its maximum match length and the
// alphabet of bytes it can consume. It rejects unbounded or anchored patterns.
func AnalyzePattern(expr string) (PatternInfo, error) {
	re, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return PatternInfo{}, fmt.Errorf("parse %q: %w", expr, err)
	}
	var info PatternInfo
	n, err := walk(re, &info.Alphabet)
	if err != nil {
		return PatternInfo{}, fmt.Errorf("analyze %q: %w", expr, err)
	}
	info.MaxLen = n
	info.First, _ = first(re)
	return info, nil
}

// first returns the set of bytes that can begin a match of re and whether
// re can match the empty string. Only called on patterns walk accepted.
func first(re *syntax.Regexp) (Alphabet, bool) {
	var a Alphabet
	switch re.Op {
	case syntax.OpLiteral:
		if len(re.Rune) == 0 {
			return a, true
		}
		addRune(&a, re.Rune[0], re.Flags&syntax.FoldCase != 0)
		return a, false
	case syntax.OpCharClass:
		for i := 0; i+1 < len(re.Rune); i += 2 {
			a.addRange(re.Rune[i], re.Rune[i+1])
		}
		return a, false
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		a.addRange(0, unicode.MaxRune)
		return a, false
	case syntax.OpCapture:
		return first(re.Sub[0])
	case syntax.OpQuest:
		f, _ := first(re.Sub[0])
		return f, true
	case syntax.OpRepeat:
		f, nullable := first(re.Sub[0])
		return f, nullable || re.Min == 0
	case syntax.OpConcat:
		for _, sub := range re.Sub {
			f, nullable := first(sub)
			for i := range a {
				a[i] = a[i] || f[i]
			}
			if !nullable {
				return a, false
			}
		}
		return a, true
	case syntax.OpAlternate:
		any := false
		for _, sub := range re.Sub {
			f, nullable := first(sub)
			for i := range a {
				a[i] = a[i] || f[i]
			}
			any = any || nullable
		}
		return a, any
	}
	return a, true // OpEmptyMatch, OpNoMatch
}

func walk(re *syntax.Regexp, a *Alphabet) (int, error) {
	switch re.Op {
	case syntax.OpEmptyMatch, syntax.OpNoMatch:
		return 0, nil
	case syntax.OpLiteral:
		n := 0
		for _, r := range re.Rune {
			addRune(a, r, re.Flags&syntax.FoldCase != 0)
			n += utf8.RuneLen(r)
		}
		return n, nil
	case syntax.OpCharClass:
		width := 0
		for i := 0; i+1 < len(re.Rune); i += 2 {
			lo, hi := re.Rune[i], re.Rune[i+1]
			a.addRange(lo, hi)
			if w := utf8.RuneLen(min(hi, unicode.MaxRune)); w > width {
				width = w
			}
		}
		return width, nil
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		a.addRange(0, unicode.MaxRune)
		return utf8.UTFMax, nil
	case syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText,
		syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return 0, ErrAnchoredPattern
	case syntax.OpCapture:
		return walk(re.Sub[0], a)
	case syntax.OpStar, syntax.OpPlus:
		return 0, ErrUnboundedPattern
	case syntax.OpQuest:
		return walk(re.Sub[0], a)
	case syntax.OpRepeat:
		if re.Max < 0 {
			return 0, ErrUnboundedPattern
		}
		n, err := walk(re.Sub[0], a)
		return n * re.Max, err
	case syntax.OpConcat:
		total := 0
		for _, s := range re.Sub {
			n, err := walk(s, a)
			if err != nil {
				return 0, err
			}
			total += n
		}
		return total, nil
	case syntax.OpAlternate:
		best := 0
		for _, s := range re.Sub {
			n, err := walk(s, a)
			if err != nil {
				return 0, err
			}
			best = max(best, n)
		}
		return best, nil
	default:
		return 0, fmt.Errorf("unsupported regexp op %v", re.Op)
	}
}

func addRune(a *Alphabet, r rune, fold bool) {
	a.addRange(r, r)
	if fold {
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			a.addRange(f, f)
		}
	}
}
