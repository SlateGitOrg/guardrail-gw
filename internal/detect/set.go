package detect

import (
	"fmt"
	"sort"
)

// Options configures which detectors are built and how they are tuned.
type Options struct {
	// Disabled kinds are not constructed at all.
	Disabled map[Kind]bool
	Entropy  EntropyConfig
}

// Set is an immutable collection of detectors, safe for concurrent use.
type Set struct {
	dets   []Detector
	byKind map[Kind]Detector
}

type constructor struct {
	kind Kind
	cat  Category
	make func(Options) (Detector, error)
}

func wrap(f func() (Detector, error)) func(Options) (Detector, error) {
	return func(Options) (Detector, error) { return f() }
}

var constructors = []constructor{
	{KindEmail, CategoryPII, wrap(NewEmail)},
	{KindPhone, CategoryPII, wrap(NewPhone)},
	{KindCreditCard, CategoryPII, wrap(NewCreditCard)},
	{KindIBAN, CategoryPII, wrap(NewIBAN)},
	{KindUSSSN, CategoryPII, wrap(NewUSSSN)},
	{KindAadhaar, CategoryPII, wrap(NewAadhaar)},
	{KindSpanishID, CategoryPII, wrap(NewSpanishID)},
	{KindChineseRIC, CategoryPII, wrap(NewChineseRIC)},
	{KindAWSAccessKey, CategorySecret, wrap(NewAWSAccessKey)},
	{KindGitHubToken, CategorySecret, wrap(NewGitHubToken)},
	{KindSlackToken, CategorySecret, wrap(NewSlackToken)},
	{KindStripeKey, CategorySecret, wrap(NewStripeKey)},
	{KindGoogleAPIKey, CategorySecret, wrap(NewGoogleAPIKey)},
	{KindLLMAPIKey, CategorySecret, wrap(NewLLMAPIKey)},
	{KindJWT, CategorySecret, wrap(NewJWT)},
	{KindPrivateKey, CategorySecret, wrap(NewPrivateKey)},
	{KindCredentialPair, CategorySecret, wrap(NewCredentialAssignment)},
	{KindHighEntropy, CategorySecret, func(o Options) (Detector, error) {
		cfg := o.Entropy
		if cfg == (EntropyConfig{}) {
			cfg = DefaultEntropyConfig()
		}
		if cfg.MinLen < 1 || cfg.MaxLen < cfg.MinLen {
			return nil, fmt.Errorf("entropy: invalid length bounds min=%d max=%d", cfg.MinLen, cfg.MaxLen)
		}
		return NewHighEntropy(cfg), nil
	}},
}

// AllKinds lists every detector kind in a stable order.
func AllKinds() []Kind {
	out := make([]Kind, len(constructors))
	for i, c := range constructors {
		out[i] = c.kind
	}
	return out
}

// CategoryOf returns the category of a known kind.
func CategoryOf(k Kind) (Category, bool) {
	for _, c := range constructors {
		if c.kind == k {
			return c.cat, true
		}
	}
	return "", false
}

// NewSet builds the enabled detectors.
func NewSet(opts Options) (*Set, error) {
	s := &Set{byKind: map[Kind]Detector{}}
	for _, c := range constructors {
		if opts.Disabled[c.kind] {
			continue
		}
		d, err := c.make(opts)
		if err != nil {
			return nil, err
		}
		s.dets = append(s.dets, d)
		s.byKind[c.kind] = d
	}
	return s, nil
}

// Detectors returns the detectors in the set (callers must not modify it).
func (s *Set) Detectors() []Detector { return s.dets }

// Select returns the detectors for which keep returns true.
func (s *Set) Select(keep func(Detector) bool) []Detector {
	var out []Detector
	for _, d := range s.dets {
		if keep(d) {
			out = append(out, d)
		}
	}
	return out
}

// Get returns the detector for a kind, if enabled.
func (s *Set) Get(k Kind) (Detector, bool) {
	d, ok := s.byKind[k]
	return d, ok
}

// ScanAll runs every detector over a complete text and returns all findings
// sorted by start offset (overlaps between kinds are kept).
func (s *Set) ScanAll(text string) []Finding {
	var out []Finding
	for _, d := range s.dets {
		out = append(out, FindAll(d, text)...)
	}
	SortFindings(out)
	return out
}

// SortFindings orders findings by start, then longer first, then priority.
func SortFindings(f []Finding) {
	sort.SliceStable(f, func(i, j int) bool {
		if f[i].Start != f[j].Start {
			return f[i].Start < f[j].Start
		}
		if f[i].End != f[j].End {
			return f[i].End > f[j].End
		}
		return f[i].Priority > f[j].Priority
	})
}
