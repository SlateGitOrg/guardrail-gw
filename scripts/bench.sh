#!/usr/bin/env bash
# Committed load script: measures the latency the gateway adds (p50/p99) by
# replaying one workload directly against the fake upstream and through the
# gateway, buffered and token-sized streaming. Results go to docs/results/.
#   N=2000 C=4 ./scripts/bench.sh
set -euo pipefail
cd "$(dirname "$0")/.."
N="${N:-2000}"
C="${C:-4}"
mkdir -p docs/results
go run ./cmd/gwbench -n "$N" -c "$C" -out docs/results/bench.md
go test -run '^$' -bench . -benchtime 2s ./internal/filter/ ./internal/injection/ | tee docs/results/microbench.txt
