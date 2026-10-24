package detect

import (
	"math"
)

// EntropyConfig tunes the generic high-entropy token detector.
type EntropyConfig struct {
	// MinLen is the minimum token length scored without keyword context.
	MinLen int
	// MaxLen bounds token length; longer runs (data URIs, blobs) are skipped.
	MaxLen int
	// MinBits is the Shannon entropy (bits/char) required without context.
	MinBits float64
	// KeywordBits is the lower threshold used when a credential keyword
	// precedes the token.
	KeywordBits float64
}

// DefaultEntropyConfig returns thresholds chosen on the dev split of the
// synthetic corpus (see DECISIONS.md and cmd/gweval).
func DefaultEntropyConfig() EntropyConfig {
	return EntropyConfig{MinLen: 20, MaxLen: 512, MinBits: 4.0, KeywordBits: 3.0}
}

var entropyKeywords = []string{"key", "token", "secret", "passw", "pwd", "credential", "auth", "bearer"}

// '=' is excluded so "KEY=value" splits into two runs; base64 padding is
// simply left outside the redacted span.
var tokenAlphabet = AlphabetOf("A-Z", "a-z", "0-9", "+/_-")

type entropyDetector struct{ cfg EntropyConfig }

// NewHighEntropy returns the generic random-token detector. A token is a
// maximal run of base64/base64url characters scored by Shannon entropy and
// character-class mix. Pure hex runs (hashes, UUID parts) require keyword
// context because commit SHAs and digests are common and harmless.
func NewHighEntropy(cfg EntropyConfig) Detector { return &entropyDetector{cfg: cfg} }

func (d *entropyDetector) Kind() Kind             { return KindHighEntropy }
func (d *entropyDetector) Category() Category     { return CategorySecret }
func (d *entropyDetector) Priority() int          { return 80 }
func (d *entropyDetector) MaxLen() int            { return d.cfg.MaxLen }
func (d *entropyDetector) LeftContext() int       { return keywordWindow }
func (d *entropyDetector) InAlphabet(b byte) bool { return tokenAlphabet.Contains(b) }

func (d *entropyDetector) FindFrom(text string, from int) (int, int, bool) {
	i := from
	// Starting inside a run means the run's start lies before `from`; the
	// run was already considered, so skip to its end.
	if i > 0 && i < len(text) && tokenAlphabet.Contains(text[i-1]) {
		for i < len(text) && tokenAlphabet.Contains(text[i]) {
			i++
		}
	}
	for i < len(text) {
		if !tokenAlphabet.Contains(text[i]) {
			i++
			continue
		}
		j := i
		for j < len(text) && tokenAlphabet.Contains(text[j]) && j-i <= d.cfg.MaxLen {
			j++
		}
		if j-i > d.cfg.MaxLen {
			for j < len(text) && tokenAlphabet.Contains(text[j]) {
				j++
			}
			i = j
			continue
		}
		if d.accept(text, i, j) {
			return i, j, true
		}
		i = j
	}
	return 0, 0, false
}

func (d *entropyDetector) accept(text string, s, e int) bool {
	tok := text[s:e]
	n := len(tok)
	if n < 16 {
		return false
	}
	keyword := hasKeywordBefore(text, s, entropyKeywords...)
	h := ShannonEntropy(tok)
	if isHex(tok) {
		return keyword && n >= 32 && h >= d.cfg.KeywordBits
	}
	if keyword {
		return h >= d.cfg.KeywordBits && (hasDigit(tok) || charClasses(tok) >= 2)
	}
	if n < d.cfg.MinLen {
		return false
	}
	var lower, upper, other int
	for i := 0; i < n; i++ {
		switch c := tok[i]; {
		case isLower(c):
			lower++
		case isUpper(c):
			upper++
		case isDigit(c), c == '+', c == '/':
			other++
		}
	}
	// Random base62/base64 strings mix cases with digits or '+' '/';
	// identifiers and words rarely carry several of those at once. Long
	// tokens with very high entropy pass even with a single digit.
	return lower > 0 && upper > 0 && h >= d.cfg.MinBits && (other >= 2 || (n >= 32 && h >= d.cfg.MinBits+0.5))
}

// ShannonEntropy returns the empirical entropy of s in bits per byte.
func ShannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	h := 0.0
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isDigit(c) && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') && c != '-' {
			return false
		}
	}
	return true
}
