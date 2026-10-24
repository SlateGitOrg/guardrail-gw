#!/usr/bin/env bash
# Runs the full test suite and gates statement coverage of internal/ (the
# core logic; cmd/ packages are thin wiring) at the given minimum percent.
set -euo pipefail
min="${1:-80}"
cd "$(dirname "$0")/.."
go test -count=1 -coverpkg=./internal/... -coverprofile=coverage.out ./...
total="$(go tool cover -func=coverage.out | awk '/^total:/ {sub("%", "", $3); print $3}')"
echo "internal/ statement coverage: ${total}% (minimum ${min}%)"
awk -v t="$total" -v m="$min" 'BEGIN { exit (t + 0 < m + 0) ? 1 : 0 }' || { echo "coverage below minimum"; exit 1; }
