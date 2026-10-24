package filter

import (
	"math/rand/v2"
	"reflect"
	"strings"
	"testing"

	"github.com/archit2501/guardrail-gw/internal/corpus"
	"github.com/archit2501/guardrail-gw/internal/detect"
	"github.com/archit2501/guardrail-gw/internal/policy"
)

func allDetectors(t testing.TB) []detect.Detector {
	t.Helper()
	s, err := detect.NewSet(detect.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return s.Detectors()
}

func constant(a policy.Action) Resolver {
	return func(detect.Kind, detect.Category) policy.Action { return a }
}

// oracle filters the whole text with the obvious non-incremental algorithm:
// run every detector over the full text, merge overlaps, render.
func oracle(dets []detect.Detector, resolve Resolver, text string) Result {
	var fs []detect.Finding
	for _, d := range dets {
		fs = append(fs, detect.FindAll(d, text)...)
	}
	detect.SortFindings(fs)
	s := &Stream{resolve: resolve, namer: NewNamer(), buf: text}
	return s.render(len(text), clusterize(fs))
}

// runChunks feeds text split at the given cut points and concatenates results.
func runChunks(dets []detect.Detector, resolve Resolver, text string, cuts []int) Result {
	s := NewStream(dets, resolve, NewNamer())
	var out Result
	prev := 0
	add := func(r Result) {
		out.Text += r.Text
		out.Findings = append(out.Findings, r.Findings...)
		if r.Blocked != nil {
			out.Blocked = r.Blocked
		}
	}
	for _, c := range append(cuts, len(text)) {
		add(s.Write(text[prev:c]))
		prev = c
	}
	add(s.Close())
	return out
}

func randomCuts(r *rand.Rand, n int) []int {
	if n == 0 {
		return nil
	}
	var cuts []int
	switch r.IntN(3) {
	case 0: // byte-at-a-time (worst case, splits UTF-8 runes too)
		for i := 1; i < n; i++ {
			cuts = append(cuts, i)
		}
	default:
		for p := 0; ; {
			p += 1 + r.IntN(12)
			if p >= n {
				break
			}
			cuts = append(cuts, p)
		}
	}
	return cuts
}

func randomResolver(r *rand.Rand) Resolver {
	acts := map[detect.Kind]policy.Action{}
	for _, k := range detect.AllKinds() {
		acts[k] = policy.Action(1 + r.IntN(3)) // log, redact or block
	}
	return func(k detect.Kind, _ detect.Category) policy.Action { return acts[k] }
}

func sameResult(a, b Result) bool {
	if a.Text != b.Text || !reflect.DeepEqual(a.Findings, b.Findings) {
		return false
	}
	return (a.Blocked == nil) == (b.Blocked == nil) && (a.Blocked == nil || *a.Blocked == *b.Blocked)
}

// TestChunkBoundaryProperty is the core streaming guarantee: for random texts
// full of sensitive values and random chunkings (including one byte at a
// time), the streamed output equals the whole-text oracle exactly.
func TestChunkBoundaryProperty(t *testing.T) {
	dets := allDetectors(t)
	r := rand.New(rand.NewPCG(1, 2))
	cases := 1500
	if testing.Short() {
		cases = 200
	}
	for i := 0; i < cases; i++ {
		g := corpus.NewGen("dev", uint64(i))
		text := g.NoisyText(5 + r.IntN(40))
		resolve := randomResolver(r)
		want := oracle(dets, resolve, text)
		cuts := randomCuts(r, len(text))
		got := runChunks(dets, resolve, text, cuts)
		if !sameResult(got, want) {
			t.Fatalf("case %d mismatch\ntext=%q\ncuts=%v\ngot =%q %+v\nwant=%q %+v", i, text, cuts, got.Text, got.Findings, want.Text, want.Findings)
		}
		if one := Apply(dets, resolve, NewNamer(), text); !sameResult(one, want) {
			t.Fatalf("case %d: Apply differs from oracle", i)
		}
	}
}

func FuzzChunkBoundary(f *testing.F) {
	f.Add("card 4111 1111 1111 1111 mail a.b@example.com", uint64(1))
	f.Add("ssn 123456789 key AKIAIOSFODNN7EXAMPLE", uint64(7))
	f.Add("password: hunter2! +1 415-555-0132 GB82WEST12345698765432", uint64(3))
	f.Add("数据 eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig 🔐", uint64(9))
	dets := allDetectors(f)
	f.Fuzz(func(t *testing.T, text string, seed uint64) {
		if len(text) > 4096 {
			return
		}
		r := rand.New(rand.NewPCG(seed, 0))
		resolve := randomResolver(r)
		want := oracle(dets, resolve, text)
		got := runChunks(dets, resolve, text, randomCuts(r, len(text)))
		if !sameResult(got, want) {
			t.Fatalf("mismatch for %q: got %q want %q", text, got.Text, want.Text)
		}
	})
}

func TestRedactPlaceholdersStable(t *testing.T) {
	dets := allDetectors(t)
	n := NewNamer()
	text := "mail a@x.io, then b@x.io, then a@x.io again"
	r := Apply(dets, constant(policy.Redact), n, text)
	want := "mail [EMAIL_1], then [EMAIL_2], then [EMAIL_1] again"
	if r.Text != want {
		t.Fatalf("got %q want %q", r.Text, want)
	}
	if len(r.Findings) != 3 || r.Findings[0].Value != "a@x.io" || r.Findings[0].Placeholder != "[EMAIL_1]" {
		t.Fatalf("findings %+v", r.Findings)
	}
	// The namer is shared across calls (e.g. across messages of a request).
	if r2 := Apply(dets, constant(policy.Redact), n, "b@x.io"); r2.Text != "[EMAIL_2]" {
		t.Fatalf("shared namer: %q", r2.Text)
	}
}

func TestLogPassesThrough(t *testing.T) {
	text := "key AKIAIOSFODNN7EXAMPLE ok"
	r := Apply(allDetectors(t), constant(policy.Log), NewNamer(), text)
	if r.Text != text || len(r.Findings) != 1 || r.Findings[0].Action != policy.Log {
		t.Fatalf("%+v", r)
	}
}

func TestBlockStopsStream(t *testing.T) {
	s := NewStream(allDetectors(t), constant(policy.Block), NewNamer())
	var out strings.Builder
	var blocked *Applied
	for _, c := range []string{"hello there, my key is AKIA", "IOSFODNN7EXAMPLE and more", " text"} {
		r := s.Write(c)
		out.WriteString(r.Text)
		if r.Blocked != nil {
			blocked = r.Blocked
		}
	}
	if blocked == nil || blocked.Kind != detect.KindAWSAccessKey {
		t.Fatalf("expected aws block, got %+v", blocked)
	}
	if out.String() != "hello there, my key is " {
		t.Fatalf("emitted %q", out.String())
	}
	if !s.Done() || s.Write("x").Text != "" || s.Close().Text != "" {
		t.Fatal("stream should be finished")
	}
}

func TestOverlapUnionAndLabel(t *testing.T) {
	// A GitHub token embedded in an e-mail-shaped URL credential: both
	// detectors fire; the union is redacted and labeled by the stronger kind.
	tok := "ghp_" + strings.Repeat("aB3", 12)
	text := "url https://" + tok + "@git.example.com/r.git"
	resolve := func(k detect.Kind, _ detect.Category) policy.Action {
		if k == detect.KindEmail {
			return policy.Log
		}
		return policy.Redact
	}
	r := Apply(allDetectors(t), resolve, NewNamer(), text)
	if r.Text != "url https://[GITHUB_TOKEN_1]/r.git" {
		t.Fatalf("got %q", r.Text)
	}
}

func TestStreamingLatencyOnProse(t *testing.T) {
	// Holdback should be limited to the trailing partial token for plain prose.
	s := NewStream(allDetectors(t), constant(policy.Redact), NewNamer())
	r := s.Write("The quick brown fox jumps over the lazy dog. Next")
	if !strings.HasPrefix(r.Text, "The quick brown fox jumps over the lazy dog.") {
		t.Fatalf("emitted only %q", r.Text)
	}
	if s.Pending() > len(" Next") {
		t.Fatalf("pending %d bytes", s.Pending())
	}
	if c := s.Close(); r.Text+c.Text != "The quick brown fox jumps over the lazy dog. Next" {
		t.Fatalf("close: %q", c.Text)
	}
}

func TestNoDetectors(t *testing.T) {
	r := Apply(nil, constant(policy.Redact), NewNamer(), "anything 4111111111111111")
	if r.Text != "anything 4111111111111111" {
		t.Fatal(r.Text)
	}
}
