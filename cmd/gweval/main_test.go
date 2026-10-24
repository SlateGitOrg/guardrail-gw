package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunDevSweep(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"-corpus", "../../testdata/corpus", "-split", "dev", "-sweep"}, &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Evaluation on the dev split", "Entropy threshold sweep", "Best dev F1"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestRunErrors(t *testing.T) {
	for _, args := range [][]string{
		{"-split", "heldout", "-sweep"},
		{"-split", "test"},
		{"-corpus", "/nonexistent"},
		{"-corpus", "../../testdata", "-split", "dev"},
		{"-bogus"},
	} {
		if err := run(args, &bytes.Buffer{}); err == nil {
			t.Errorf("%v: expected error", args)
		}
	}
}
