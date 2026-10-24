package corpus

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/archit2501/guardrail-gw/internal/detect"
)

func TestDeterministicAndWellFormed(t *testing.T) {
	a, b := Detection("dev", 7, 200), Detection("dev", 7, 200)
	if !reflect.DeepEqual(a, b) {
		t.Fatal("generator is not deterministic")
	}
	set, _ := detect.NewSet(detect.Options{})
	for _, s := range a {
		for _, sp := range s.Spans {
			if sp.Start < 0 || sp.End > len(s.Text) || sp.Start >= sp.End {
				t.Fatalf("bad span %+v in %q", sp, s.Text)
			}
			// Every generated positive must be detectable in isolation.
			d, _ := set.Get(sp.Kind)
			v := s.Text[sp.Start:sp.End]
			ctx := map[detect.Kind]string{detect.KindCredentialPair: "password: "}[sp.Kind]
			if fs := detect.FindAll(d, ctx+v); len(fs) == 0 {
				t.Fatalf("%s value %q not detected", sp.Kind, v)
			}
		}
	}
}

func TestSplitsDiffer(t *testing.T) {
	dev, held := Detection("dev", 1, 50), Detection("heldout", 1, 50)
	if reflect.DeepEqual(dev, held) {
		t.Fatal("splits must differ")
	}
	pairs := [][2][]string{
		{devTemplates, heldoutTemplates},
		{devInjectionAttacks, heldoutInjectionAttacks},
		{devBenignPrompts, heldoutBenignPrompts},
	}
	for _, p := range pairs {
		seen := map[string]bool{}
		for _, x := range p[0] {
			seen[x] = true
		}
		for _, x := range p[1] {
			if seen[x] {
				t.Fatalf("template shared by dev and held-out: %q", x)
			}
		}
	}
}

func TestInjectionAndNoise(t *testing.T) {
	inj := Injection("heldout", 3, 300)
	pos := 0
	for _, s := range inj {
		pos += s.Label
		if strings.Contains(s.Text, "{goal}") {
			t.Fatal("unfilled goal")
		}
	}
	if pos < 80 || pos > 160 {
		t.Fatalf("unexpected positive count %d", pos)
	}
	if NewGen("dev", 1).NoisyText(30) == "" {
		t.Fatal("empty noise")
	}
}

func TestJSONLRoundTrip(t *testing.T) {
	rows := Detection("heldout", 9, 20)
	var buf bytes.Buffer
	if err := WriteJSONL(&buf, rows); err != nil {
		t.Fatal(err)
	}
	buf.WriteString("\n")
	got, err := ReadJSONL[Sample](&buf)
	if err != nil || !reflect.DeepEqual(got, rows) {
		t.Fatalf("round trip: %v", err)
	}
	if _, err := ReadJSONL[Sample](strings.NewReader("{bad")); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestValuesCoverAllKinds(t *testing.T) {
	g := NewGen("dev", 5)
	for _, k := range detect.AllKinds() {
		if g.Value(k) == "" {
			t.Fatalf("empty value for %s", k)
		}
	}
	defer func() {
		if recover() == nil {
			t.Fatal("unknown kind should panic")
		}
	}()
	g.Value("nope")
}
