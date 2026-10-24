package policy

import (
	"testing"

	"github.com/archit2501/guardrail-gw/internal/detect"
)

func TestParseAndMarshal(t *testing.T) {
	for i, n := range []string{"allow", "LOG", "Redact", "block"} {
		a, err := ParseAction(n)
		if err != nil || a != Action(i) {
			t.Fatalf("%s: %v %v", n, a, err)
		}
		b, _ := a.MarshalText()
		var back Action
		if err := back.UnmarshalText(b); err != nil || back != a {
			t.Fatalf("round trip %s", b)
		}
	}
	if _, err := ParseAction("shred"); err == nil {
		t.Fatal("expected error")
	}
	var a Action
	if a.UnmarshalText([]byte("nope")) == nil {
		t.Fatal("expected unmarshal error")
	}
	if Action(9).String() != "action(9)" || Block <= Redact || Redact <= Log || Log <= Allow {
		t.Fatal("ordering/String")
	}
}

func TestRules(t *testing.T) {
	r := Rules{
		Categories: map[detect.Category]Action{detect.CategoryPII: Redact, detect.CategorySecret: Block},
		Kinds:      map[detect.Kind]Action{detect.KindPhone: Allow},
	}
	if r.For(detect.KindPhone, detect.CategoryPII) != Allow || r.For(detect.KindEmail, detect.CategoryPII) != Redact {
		t.Fatal("kind override")
	}
	set, _ := detect.NewSet(detect.Options{})
	for _, d := range r.Active(set) {
		if d.Kind() == detect.KindPhone {
			t.Fatal("allowed kind must not be active")
		}
	}
	if len(r.Active(set)) != len(set.Detectors())-1 {
		t.Fatal("active count")
	}
}
