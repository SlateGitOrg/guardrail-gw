// Package filter applies detectors and policy actions to text, either in one
// shot or incrementally over a stream of chunks.
//
// The streaming algorithm guarantees that, for any way of splitting a text
// into chunks, the concatenated output, the findings and the block decision
// are identical to processing the whole text at once. See
// docs/ARCHITECTURE.md ("Chunk-boundary-exact streaming") for the proof sketch.
package filter

import (
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/archit2501/guardrail-gw/internal/detect"
	"github.com/archit2501/guardrail-gw/internal/policy"
)

// Resolver maps a finding's kind and category to an action.
type Resolver func(detect.Kind, detect.Category) policy.Action

// Applied is a finding after policy resolution. Overlapping findings of
// different kinds are merged into one Applied whose span is their union.
type Applied struct {
	Kind        detect.Kind
	Category    detect.Category
	Action      policy.Action
	Start, End  int    // absolute byte offsets in the input text
	Placeholder string // set when Action == Redact
	// Value is the raw matched text. It stays in memory only (the audit log
	// stores a keyed hash) and must never be written anywhere.
	Value string `json:"-"`
}

// Result is the output of one Write or Close call.
type Result struct {
	Text     string    // text safe to forward
	Findings []Applied // findings emitted by this call, in order
	Blocked  *Applied  // non-nil when a Block action fired; the stream is finished
}

// Namer assigns stable, typed placeholders such as "[EMAIL_1]". The same
// value of the same kind always gets the same placeholder. Safe for
// concurrent use.
type Namer struct {
	mu     sync.Mutex
	counts map[detect.Kind]int
	seen   map[string]string
}

// NewNamer returns an empty Namer.
func NewNamer() *Namer {
	return &Namer{counts: map[detect.Kind]int{}, seen: map[string]string{}}
}

// Name returns the placeholder for value of kind k.
func (n *Namer) Name(k detect.Kind, value string) string {
	n.mu.Lock()
	defer n.mu.Unlock()
	key := string(k) + "\x00" + value
	if p, ok := n.seen[key]; ok {
		return p
	}
	n.counts[k]++
	p := "[" + strings.ToUpper(string(k)) + "_" + strconv.Itoa(n.counts[k]) + "]"
	n.seen[key] = p
	return p
}

// Stream incrementally filters text. It is not safe for concurrent use.
type Stream struct {
	dets    []detect.Detector
	resolve Resolver
	namer   *Namer
	horizon []int // per detector: MaxLen + lookahead
	leftCtx int

	pos     []int  // per detector: absolute scan position
	buf     string // text[base:], includes leftCtx bytes before emitted
	base    int
	emitted int
	pending []detect.Finding
	done    bool
}

// lookahead is the number of bytes past a match end an accept function may
// inspect (see detect.rightNumericBoundary).
const lookahead = 2

// NewStream creates a stream filter over dets. resolve must return an action
// stronger than Allow for every detector passed in.
func NewStream(dets []detect.Detector, resolve Resolver, namer *Namer) *Stream {
	s := &Stream{
		dets:    dets,
		resolve: resolve,
		namer:   namer,
		horizon: make([]int, len(dets)),
		pos:     make([]int, len(dets)),
	}
	for i, d := range dets {
		s.horizon[i] = d.MaxLen() + lookahead
		s.leftCtx = max(s.leftCtx, d.LeftContext()+lookahead)
	}
	return s
}

// Done reports whether the stream was closed or blocked.
func (s *Stream) Done() bool { return s.done }

// Pending returns the number of bytes received but not yet emitted.
func (s *Stream) Pending() int { return s.base + len(s.buf) - s.emitted }

// Write appends chunk and returns whatever text has become safe to emit.
func (s *Stream) Write(chunk string) Result {
	if s.done {
		return Result{}
	}
	s.buf += chunk
	return s.advance(false)
}

// Close flushes all remaining text. Further writes are ignored.
func (s *Stream) Close() Result {
	if s.done {
		return Result{}
	}
	r := s.advance(true)
	s.done = true
	return r
}

// Apply filters a complete text in one call.
func Apply(dets []detect.Detector, resolve Resolver, namer *Namer, text string) Result {
	s := NewStream(dets, resolve, namer)
	a := s.Write(text)
	if a.Blocked != nil {
		return a
	}
	b := s.Close()
	a.Text += b.Text
	a.Findings = append(a.Findings, b.Findings...)
	a.Blocked = b.Blocked
	return a
}

func (s *Stream) advance(final bool) Result {
	end := s.base + len(s.buf)
	frontier := end
	for i, d := range s.dets {
		s.scan(i, d, final)
		frontier = min(frontier, s.pos[i])
	}
	if final {
		frontier = end
	}
	detect.SortFindings(s.pending)
	clusters := clusterize(s.pending)

	cut := frontier
	for _, c := range clusters {
		if c.start < cut && cut < c.end {
			cut = c.start
			break
		}
	}
	for cut > s.emitted && cut < end && !utf8.RuneStart(s.buf[cut-s.base]) {
		cut--
	}
	res := s.render(cut, clusters)

	// Forget emitted findings and trim the buffer down to the left context.
	k := 0
	for _, f := range s.pending {
		if f.Start >= s.emitted {
			s.pending[k] = f
			k++
		}
	}
	s.pending = s.pending[:k]
	keep := max(s.base, s.emitted-s.leftCtx)
	s.buf = s.buf[keep-s.base:]
	s.base = keep
	return res
}

// scan commits every match of detector i that can no longer change as more
// text arrives, and advances its scan position.
func (s *Stream) scan(i int, d detect.Detector, final bool) {
	text := s.buf
	from := s.pos[i] - s.base
	limit := len(text)
	if !final {
		limit = s.openStart(i, d, text)
	}
	// Nothing can be committed when every possible start is still open.
	for from < limit {
		st, en, ok := d.FindFrom(text, from)
		if !ok || st >= limit {
			break
		}
		s.pending = append(s.pending, detect.Finding{
			Kind: d.Kind(), Category: d.Category(), Priority: d.Priority(),
			Start: st + s.base, End: en + s.base,
		})
		from = en
	}
	if final {
		from = len(text)
	} else {
		from = max(from, limit)
	}
	s.pos[i] = from + s.base
}

// openStart returns the smallest offset at which a match of d could still
// depend on bytes that have not arrived yet: the start of the trailing run of
// alphabet bytes, but never earlier than len-horizon.
func (s *Stream) openStart(i int, d detect.Detector, text string) int {
	lo := max(0, len(text)-s.horizon[i])
	t := len(text)
	for t > lo && d.InAlphabet(text[t-1]) {
		t--
	}
	return t
}

type cluster struct {
	start, end int
	members    []detect.Finding
}

// clusterize merges overlapping findings (sorted by start) into clusters.
func clusterize(fs []detect.Finding) []cluster {
	var out []cluster
	for _, f := range fs {
		if n := len(out); n > 0 && f.Start < out[n-1].end {
			c := &out[n-1]
			c.end = max(c.end, f.End)
			c.members = append(c.members, f)
			continue
		}
		out = append(out, cluster{start: f.Start, end: f.End, members: []detect.Finding{f}})
	}
	return out
}

// decide picks the strongest action in the cluster and the member that
// labels it (strongest action, then priority, then length).
func (s *Stream) decide(c cluster) (policy.Action, detect.Finding) {
	best := c.members[0]
	bestAct := s.resolve(best.Kind, best.Category)
	for _, m := range c.members[1:] {
		a := s.resolve(m.Kind, m.Category)
		switch {
		case a > bestAct,
			a == bestAct && m.Priority > best.Priority,
			a == bestAct && m.Priority == best.Priority && m.End-m.Start > best.End-best.Start:
			best, bestAct = m, a
		}
	}
	return bestAct, best
}

func (s *Stream) slice(a, b int) string { return s.buf[a-s.base : b-s.base] }

// render emits text up to cut, applying actions to every cluster before it.
func (s *Stream) render(cut int, clusters []cluster) Result {
	var res Result
	var out strings.Builder
	at := s.emitted
	for _, c := range clusters {
		if c.start >= cut {
			break
		}
		out.WriteString(s.slice(at, c.start))
		act, label := s.decide(c)
		ap := Applied{
			Kind: label.Kind, Category: label.Category, Action: act,
			Start: c.start, End: c.end, Value: s.slice(c.start, c.end),
		}
		switch act {
		case policy.Block:
			res.Findings = append(res.Findings, ap)
			res.Blocked = &res.Findings[len(res.Findings)-1]
			res.Text = out.String()
			s.emitted = c.start
			s.done = true
			return res
		case policy.Redact:
			ap.Placeholder = s.namer.Name(label.Kind, ap.Value)
			out.WriteString(ap.Placeholder)
		default:
			out.WriteString(ap.Value)
		}
		res.Findings = append(res.Findings, ap)
		at = c.end
	}
	out.WriteString(s.slice(at, cut))
	s.emitted = cut
	res.Text = out.String()
	return res
}
