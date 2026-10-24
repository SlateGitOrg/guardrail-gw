#!/usr/bin/env bash
# Shows the chunk-boundary property test is sensitive to the two safety
# margins of the streaming filter: each mutant must make it FAIL. The source
# file is restored on exit.
set -euo pipefail
cd "$(dirname "$0")/.."
src=internal/filter/filter.go
backup="$(mktemp)"
cp "$src" "$backup"
trap 'cp "$backup" "$src"; rm -f "$backup"' EXIT

mutate() { # $1 = description, $2 = sed expression
  cp "$backup" "$src"
  sed -i.orig "$2" "$src" && rm -f "$src.orig"
  if cmp -s "$backup" "$src"; then echo "mutant '$1' did not apply"; exit 1; fi
  if go test -count=1 -run TestChunkBoundaryProperty ./internal/filter/ >/dev/null 2>&1; then
    echo "SURVIVED: $1"; exit 1
  fi
  echo "killed:   $1"
}
mutate "no lookahead past match end" 's/const lookahead = 2/const lookahead = 0/'
mutate "half-length hold-back horizon" 's/lo := max(0, len(text)-s.horizon\[i\])/lo := max(0, len(text)-s.horizon[i]\/2)/'
mutate "ignore open trailing run" 's/for t > lo \&\& d.InAlphabet(text\[t-1\]) {/for t > lo \&\& d.InAlphabet(text[t-1]) \&\& t > len(text)-3 {/'
