# guardrail-gw — every gate runs offline (no Docker, no network, no model).
GO        ?= go
GOFLAGS   ?= -p=3
export GOFLAGS
COVER_MIN ?= 80

.PHONY: check fmt-check vet lint test-race cover build demo demo-ollama eval eval-dev bench fuzz mutation corpus clean

## check: format + vet + lint + race tests + coverage gate (what CI runs)
check: fmt-check vet lint test-race cover

fmt-check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	$(GO) vet ./...

lint:
	golangci-lint run ./...

## test-race: all tests under the race detector (-short trims property-test case counts)
test-race:
	$(GO) test -race -short -count=1 ./...

## cover: full test suite with coverage of internal/ (core logic), gated at COVER_MIN%
cover:
	./scripts/coverage.sh $(COVER_MIN)

build:
	$(GO) build -o bin/guardrail-gw ./cmd/guardrail-gw

## demo: offline end-to-end tour (fake upstream, real gateway, hot reload, audit)
demo:
	$(GO) run ./cmd/gwdemo .demo

## demo-ollama: short real-model run against local Ollama (skips if unavailable)
demo-ollama: build
	./scripts/demo-ollama.sh

## eval: detector + injection metrics on the held-out split
eval:
	@mkdir -p docs/results
	$(GO) run ./cmd/gweval -split heldout | tee docs/results/eval-heldout.md

## eval-dev: dev split with threshold sweeps (the only place thresholds are tuned)
eval-dev:
	@mkdir -p docs/results
	$(GO) run ./cmd/gweval -split dev -sweep | tee docs/results/eval-dev.md

## bench: p50/p99 overhead load test + micro-benchmarks
bench:
	./scripts/bench.sh

## fuzz: fuzz the chunk-boundary invariant (FUZZTIME, default 60s)
fuzz:
	$(GO) test -run '^$$' -fuzz FuzzChunkBoundary -fuzztime $${FUZZTIME:-60s} ./internal/filter/

## mutation: show the streaming property test kills hold-back/lookahead mutants
mutation:
	./scripts/mutation-check.sh

## corpus: regenerate the committed synthetic corpus (deterministic)
corpus:
	$(GO) run ./cmd/corpusgen -out testdata/corpus

clean:
	rm -rf bin coverage.out .demo
