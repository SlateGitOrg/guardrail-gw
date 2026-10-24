// Package injection scores text for prompt-injection attempts with weighted,
// explainable heuristics. It is a cheap first line of defense, not a
// classifier: see docs/THREAT_MODEL.md for what it cannot catch.
package injection

import (
	"math"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Signal is one heuristic that fired.
type Signal struct {
	Name   string  `json:"name"`
	Weight float64 `json:"weight"`
}

// Score is the scorer's verdict for a text.
type Score struct {
	Value   float64  `json:"score"` // in [0,1)
	Signals []Signal `json:"signals,omitempty"`
}

type rule struct {
	name   string
	weight float64
	re     *regexp.Regexp
}

// Rules are matched against normalized text (lowercase, homoglyphs folded,
// zero-width characters removed, spaced-out letters joined) and against a
// de-leeted view of it.
var rules = []rule{
	{"instruction_override", 3.0, regexp.MustCompile(
		`\b(ignore|disregard|forget|skip|bypass|override|stop following)\b.{0,40}?\b(previous|prior|above|earlier|preceding|initial|original|system|your|all|the)\b.{0,30}?\b(instructions?|prompts?|rules|directions|guidelines|directives)\b`)},
	{"prompt_exfiltration", 2.5, regexp.MustCompile(
		`\b(reveal|show|print|repeat|output|display|leak|dump|tell me)\b.{0,40}?(system prompt|initial prompt|hidden (instructions|prompt)|your (instructions|prompt|configuration|rules)|instructions you were given|everything above|text above|above this line)`)},
	{"jailbreak_persona", 2.0, regexp.MustCompile(
		`\b(dan|do anything now|developer mode|jailbreak mode|jailbroken|unfiltered|unrestricted assistant|no (restrictions|rules|limits|content policy)|without (any )?(restrictions|rules|limits|filters))\b`)},
	{"role_reassignment", 0.8, regexp.MustCompile(
		`\b(you are now|from now on,? you|pretend (you are|to be|you have)|roleplay as)\b`)},
	{"delimiter_injection", 2.0, regexp.MustCompile(
		`(</?(system|user|assistant)>|<\|im_(start|end)\|>|\[/?inst\]|###\s*(new )?(system|instructions?)\b|begin system prompt)`)},
	{"false_authority", 1.5, regexp.MustCompile(
		`\b(system override|admin(istrator)? (says|mode|override)|as your (developer|creator|admin)|i am (your|the) (developer|admin|creator)|i authori[sz]e you)\b`)},
	{"safety_bypass", 2.0, regexp.MustCompile(
		`\b(bypass|disable|turn off|override|ignore|disregard)\b.{0,20}?\b(safety|content filters?|filters?|guardrails?|moderation|content polic(y|ies)|system prompt|safety settings)\b`)},
	{"exfiltration_link", 2.0, regexp.MustCompile(
		`!\[[^\]]*\]\(https?://[^)\s]*\?[^)\s]*=|append (the|this|our) (conversation|chat|history)`)},
	{"new_instructions", 1.0, regexp.MustCompile(`\b(new|updated|real|actual) (instructions|policy|rules|task)\b`)},
	{"coercion", 0.5, regexp.MustCompile(`\b(you must now|nothing else matters|instead,)`)},
}

// Scale converts the summed weights into a score: 1 - exp(-sum/Scale).
const Scale = 2.0

// Evaluate scores text. It is safe for concurrent use.
func Evaluate(text string) Score {
	norm, obf := normalize(text)
	views := []string{norm}
	if dl := deleet(norm); dl != norm {
		views = append(views, dl)
	}
	var sigs []Signal
	total := 0.0
	for _, r := range rules {
		for _, v := range views {
			if r.re.MatchString(v) {
				sigs = append(sigs, Signal{Name: r.name, Weight: r.weight})
				total += r.weight
				break
			}
		}
	}
	if obf.zeroWidth > 0 {
		sigs = append(sigs, Signal{Name: "zero_width_chars", Weight: 1.0})
		total += 1.0
	}
	if obf.spaced && total > 0 {
		// Spacing out letters is only suspicious when it hides a trigger.
		sigs = append(sigs, Signal{Name: "spaced_letters", Weight: 1.0})
		total += 1.0
	}
	if len(views) > 1 && total > 0 && !anyMatch(norm) {
		sigs = append(sigs, Signal{Name: "leetspeak", Weight: 0.5})
		total += 0.5
	}
	sort.SliceStable(sigs, func(i, j int) bool { return sigs[i].Weight > sigs[j].Weight })
	return Score{Value: 1 - math.Exp(-total/Scale), Signals: sigs}
}

func anyMatch(s string) bool {
	for _, r := range rules {
		if r.re.MatchString(s) {
			return true
		}
	}
	return false
}

type obfuscation struct {
	zeroWidth int
	spaced    bool
}

// homoglyphs folds common Cyrillic/Greek look-alikes to Latin.
var homoglyphs = map[rune]rune{
	'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ѕ': 's',
	'ο': 'o', 'ι': 'i', 'α': 'a', 'ν': 'v', 'τ': 't',
}

func isZeroWidth(r rune) bool {
	switch r {
	case '\u200b', '\u200c', '\u200d', '\u2060', '\ufeff', '\u00ad':
		return true
	}
	return false
}

// normalize lowercases, folds full-width and homoglyph characters, strips
// zero-width characters, joins spaced-out letters and collapses whitespace.
func normalize(s string) (string, obfuscation) {
	var o obfuscation
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case isZeroWidth(r):
			o.zeroWidth++
			continue
		case r >= '\uff01' && r <= '\uff5e': // full-width ASCII block
			r -= 0xFEE0
		case unicode.IsSpace(r):
			r = ' '
		}
		r = unicode.ToLower(r)
		if h, ok := homoglyphs[r]; ok {
			r = h
		}
		b.WriteRune(r)
	}
	joined, spaced := joinSpacedLetters(b.String())
	o.spaced = spaced
	return strings.Join(strings.Fields(joined), " "), o
}

// joinSpacedLetters rewrites runs like "i g n o r e" (at least four single
// letters separated by single spaces) into "ignore". Two or more spaces
// separate words, so "i g n o r e  p r e v" becomes "ignore prev".
func joinSpacedLetters(s string) (string, bool) {
	toks := strings.Split(s, " ")
	out := make([]string, 0, len(toks))
	joined := false
	for i := 0; i < len(toks); {
		j := i
		for j < len(toks) && utf8.RuneCountInString(toks[j]) == 1 && isLetterWord(toks[j]) {
			j++
		}
		if j-i >= 4 {
			out = append(out, strings.Join(toks[i:j], ""))
			joined = true
			i = j
			continue
		}
		out = append(out, toks[i])
		i++
	}
	return strings.Join(out, " "), joined
}

func isLetterWord(w string) bool {
	r, _ := utf8.DecodeRuneInString(w)
	return unicode.IsLetter(r)
}

var leet = strings.NewReplacer("0", "o", "1", "i", "3", "e", "4", "a", "5", "s", "7", "t", "@", "a", "$", "s")

func deleet(s string) string { return leet.Replace(s) }
