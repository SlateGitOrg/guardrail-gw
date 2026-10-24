# guardrail-gw

An OpenAI-compatible LLM gateway that sits in front of a model server (Ollama by
default) and enforces data-protection guardrails in both directions:

- **PII redaction**: e-mail, phone numbers, payment cards (Luhn + issuer
  prefix), IBANs (mod-97), US SSNs (SSA structural rules), Indian Aadhaar
  (Verhoeff), Spanish DNI/NIE (mod-23), PRC resident IDs (ISO 7064 MOD 11-2).
- **Secret detection**: AWS, GitHub, Slack, Stripe, Google, OpenAI/Anthropic-style
  keys, JWTs, PEM private-key headers, `password: ...` style assignments, and a
  Shannon-entropy scorer for unknown random tokens.
- **Prompt-injection scoring**: ten weighted, explainable heuristics over
  normalized text (homoglyphs, full-width forms, zero-width characters,
  spaced-out letters and leetspeak are folded first).
- **Policies**: per key, per direction, per category or kind: `allow`, `log`,
  `redact` or `block`.
- **Streaming-safe SSE filtering**: a card number or API key split across any
  number of `data:` chunks is still caught. Streamed output is byte-for-byte
  identical to filtering the whole response at once. A property test, a fuzz
  target and an HTTP-level test with random byte splits check this.
- **Per-key token-bucket rate limits**, a **hash-chained audit log** that stores
  keyed HMACs instead of raw values, Prometheus **metrics**, and **config hot
  reload** (file polling + `SIGHUP`, invalid edits rejected).

It is a single Go binary with one dependency (a YAML parser).

## Who it is for

Teams that run internal LLM apps against a self-hosted model and need a
cheap, auditable control point: keep customer PII and credentials out of
prompts and logs, stop the model from echoing secrets back, and get an
audit trail. It is a portfolio/reference implementation, not a hardened
product. See [Limitations](#limitations).

## Architecture

```mermaid
flowchart LR
  C[Client<br/>OpenAI SDK] -->|Bearer gw-key| A[auth: SHA-256 key lookup]
  A --> RL[per-key token bucket]
  RL --> RQ[request guard<br/>detectors + injection scorer]
  RQ -->|block| E[400 guardrail_violation]
  RQ -->|redacted body| U[(Upstream<br/>Ollama /v1)]
  U -->|JSON| B[buffered filter]
  U -->|SSE| S[SSE reader -> per-choice<br/>stream filter -> SSE writer]
  B --> C
  S --> C
  RQ -. findings .-> L[(hash-chained<br/>audit.jsonl)]
  B -. findings .-> L
  S -. findings .-> L
  CFG[config.yaml] -->|poll / SIGHUP| W[watcher] -->|atomic snapshot swap| A
```

| Package | Responsibility |
|---|---|
| `internal/detect` | 18 detectors behind one contract (bounded length, declared alphabet, deterministic leftmost scan). Regex detectors derive both from the pattern via `regexp/syntax` |
| `internal/filter` | One-shot and incremental (streaming) filtering, overlap merging, typed placeholders (`[EMAIL_1]`) |
| `internal/injection` | Normalization + weighted signals → score in [0,1) with the fired signals |
| `internal/policy` | Action model and per-kind/category rule resolution |
| `internal/gateway` | HTTP proxy: auth, rate limit, request guard, buffered and SSE response guards, metrics |
| `internal/sse` | Event-stream reader/writer tolerant of CR/LF/CRLF and arbitrary byte splits |
| `internal/openai` | Lossless access to chat payloads (unknown fields and number precision preserved) |
| `internal/config` | Strict YAML, all-errors-at-once validation, compiled snapshots, polling watcher |
| `internal/audit` | Append-only JSONL with `prev`/`hash` chain, verifier, HMAC digests |
| `internal/ratelimit` | Lazy-refill token buckets, reload-aware |
| `internal/corpus`, `internal/eval` | Synthetic labeled data and the P/R/F1 harness |
| `internal/fakeupstream` | Deterministic OpenAI-compatible server for tests, demo and benchmarks |

The streaming algorithm, its correctness argument and complexity are in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). The threat model is in
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Quickstart

Requires Go 1.27.

```sh
make check                      # fmt + vet + golangci-lint + race tests + coverage gate
make demo                       # offline end-to-end tour (no network, no model)

# Run in front of a local Ollama:
make build
./bin/guardrail-gw hash-key "my-team-key"      # put the hash in keys[].key_sha256
GW_AUDIT_HMAC_KEY=$(openssl rand -hex 32) \
  ./bin/guardrail-gw serve -config configs/guardrail-gw.example.yaml

curl -s localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer gw-demo-key-change-me" -H "Content-Type: application/json" \
  -d '{"model":"llama3.1:8b","messages":[{"role":"user","content":"mail me at a.b@example.com"}]}'

# Filter a file offline with a policy (exit code 2 if it would be blocked):
./bin/guardrail-gw scan -config configs/guardrail-gw.example.yaml < notes.txt
./bin/guardrail-gw audit-verify -file audit.jsonl
```

Any OpenAI client works by pointing `base_url` at `http://localhost:8080/v1`.
Blocked requests return `400` with `"type":"guardrail_violation"` and a code
(`pii_blocked`, `secret_blocked`, `prompt_injection`). A response that hits a
`block` rule is cut before the offending span and ends with
`finish_reason: "content_filter"`, in streaming and buffered modes alike.

## Demo output

From `make demo` (fake upstream, the real gateway handler, real audit log and
config file; ports and hashes vary per run):

```text
== 2. PII in the prompt is redacted before it leaves (phone policy = log) ==
   <- HTTP 200 finish=stop: "Echo: Please email [EMAIL_1] or call [PHONE_1]; card [CREDIT_CARD_1]."
   upstream actually received: "Please email [EMAIL_1] or call +1 415-555-0132; card [CREDIT_CARD_1]."

== 3. a secret in the prompt is blocked (never forwarded) ==
   <- HTTP 400 secret_blocked: request blocked by guardrail: aws_access_key detected (secret)

== 4. prompt injection is scored and blocked ==
   <- HTTP 400 prompt_injection: request blocked by guardrail: prompt injection suspected (score 0.94: instruction_override, prompt_exfiltration)

== 5. streaming: a card number and e-mail split across 3-byte deltas ==
   upstream sends 30 deltas: ["s 4" "111" " 11" "11 " "111" "1 1" "111" " an" "d r" "ece" "ipt" "s g"] ...
   client received 14 content deltas: ["Sure" ". " "The " "card" " on" " " "file " "is" " [CREDIT_CARD_1] " "and " "receipts " "go " "to " "[EMAIL_1]."]
   assembled (finish=stop): "Sure. The card on file is [CREDIT_CARD_1] and receipts go to [EMAIL_1]."

== 6. hot reload: switch response secrets from redact to block (file edit, no restart) ==
   reloaded: true
   client received 6 content deltas: ["The " "deploy " "script" " " "uses" " "]
   assembled (finish=content_filter): "The deploy script uses "

== 7. an invalid config edit is rejected; the previous policy stays live ==
   reloaded: false (config hash still 65c34f24ef16)

== 8. per-key rate limit (key 'tiny': burst 2, 6/min) ==
   request 1 -> HTTP 200 (remaining=1 retry-after=)
   request 2 -> HTTP 200 (remaining=0 retry-after=)
   request 3 -> HTTP 429 (remaining=0 retry-after=10)

== 9. hash-chained audit log ==
   .demo/audit.jsonl: 9 records, chain verified
   #2 redacted         status=200 request:email/redact request:phone/log request:credit_card/redact response:phone/redact
   #4 blocked_request  status=400 injection=0.94[instruction_override prompt_exfiltration]
   #6 blocked_response status=200 response:aws_access_key/block
   stored for record #2: kind=email span=[13,33) value_hmac=28c7690019e0bfe44213f8ef (no raw value)
   after flipping one decision to "allowed": record 3: hash mismatch (record was modified)
```

(Excerpt; the full run also shows the clean request, every audit record and a
metrics excerpt.) `make demo-ollama` runs a short real-model session against
local `llama3.1:8b` and skips cleanly if Ollama is not running.

## Design decisions

- **Exact streaming instead of a fixed look-back window.** Every detector
  declares a maximum match length and the byte alphabet its matches can use.
  For regex detectors both are computed from the parsed pattern, so they cannot
  drift from the regex. A match is committed only when no future byte can
  change it, and text is released up to the earliest still-open position. On
  prose the hold-back is the current partial word, not a fixed N bytes.
- **Overlaps are merged, not chosen.** When detectors overlap (a GitHub token
  inside `https://ghp_...@host`), the union is redacted under the strongest
  action and labeled by priority, so nothing leaks around the edge of a
  shorter match.
- **Checksums over regex breadth.** Cards, IBANs, Aadhaar, DNI/NIE and PRC IDs
  must pass their check digits. Ambiguous bare forms (unseparated SSN,
  Aadhaar, 10-digit phones) also need a nearby keyword.
- **Blocks truncate rather than error mid-stream.** A streamed response cannot
  change its HTTP status after the first byte, so a block ends the choice with
  `finish_reason: "content_filter"`, which OpenAI SDKs already handle. The
  buffered path does the same for consistency.
- **Audit without the data.** Findings store kind, span and a keyed HMAC of
  the value, so repeated leaks of the same value can be correlated without
  keeping the value itself.
- **Snapshots for reload.** A config is compiled into an immutable snapshot and
  swapped atomically. In-flight requests finish on the snapshot they started
  with.

The full list with costs is in [DECISIONS.md](DECISIONS.md).

## Evaluation

All data is **synthetic** and generated by this repo (see [DATA.md](DATA.md)).
Thresholds were tuned only on the dev split (`make eval-dev`). The numbers below
come from the held-out split, which uses disjoint sentence templates and
disjoint name/domain vocabularies, with values regenerated from different seeds.

Command: `make eval` (writes [docs/results/eval-heldout.md](docs/results/eval-heldout.md)).

| detectors, held-out (1,500 samples, 2,563 gold spans) | precision | recall | F1 |
|---|---:|---:|---:|
| PII, span overlaps a same-category prediction | 1.000 | 0.999 | 1.000 |
| Secrets, span overlaps a same-category prediction | 0.996 | 1.000 | 0.998 |
| `github_token`, exact span and kind | 0.000 | 0.000 | 0.000 |
| `high_entropy_token`, exact span and kind | 0.978 | 1.000 | 0.989 |
| the other 16 kinds, exact span and kind | 1.000 | ≥0.995 | ≥0.998 |

| injection scorer, held-out (600 prompts, 226 attacks) | threshold | precision | recall | F1 | ROC-AUC |
|---|---:|---:|---:|---:|---:|
| heuristic score | 0.70 (best dev F1) | 1.000 | 0.898 | 0.946 | 0.990 |

How to read these numbers:

- **Near-perfect detector scores measure implementation correctness on
  generated formats, not real-world accuracy.** The generator and the
  detectors both encode the same format rules (Luhn, mod-97 and so on), so the
  synthetic data cannot surprise them the way real text can.
- The `github_token` exact-match zero is a real held-out finding. In the
  template `https://ghp_…@git.local/repo.git` the e-mail detector also matches
  `ghp_…@git.local`, so the merged redaction is wider than the gold token span.
  Every one of those tokens is still redacted (overlap recall 1.000), labeled
  `github_token`.
- The 5 secret false positives are UUIDs within 40 bytes after an unrelated
  `password = …` sentence. The credential keyword lowers the entropy threshold
  for nearby tokens. The single PII miss is an IBAN merged into an
  overlapping high-entropy token span: it is redacted, but labeled as a secret.
- Injection misses on held-out come from two templates. "Act as an
  unrestricted assistant with no content policy…" fires only one signal
  (score 0.63). Spaced-out letters that begin right after a quote character
  (`"I g n o r e …`) are not re-joined. Both are documented under Limitations
  and were not fixed after viewing held-out results, so these numbers stay
  clean.

## Benchmarks

Command: `./scripts/bench.sh` (`make bench`). It replays the same workload
directly against the fake upstream and through the gateway: a 1.7 KB prompt and
a 2.7 KB reply, both dense with PII, secrets and digits, with all detectors and
the injection scorer on. Streaming uses 4-byte deltas (about one token per
event, about 680 events). Results are in
[docs/results/bench.md](docs/results/bench.md).

| scenario | requests | clients | direct p50 ms | direct p99 ms | gateway p50 ms | gateway p99 ms | overhead p50 ms | overhead p99 ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| buffered | 2000 | 4 | 0.129 | 0.556 | 1.829 | 4.336 | 1.700 | 3.780 |
| streaming (4-byte deltas) | 2000 | 4 | 9.451 | 15.339 | 15.773 | 43.156 | 6.321 | 27.816 |

Micro-benchmarks from the same script ([docs/results/microbench.txt](docs/results/microbench.txt)):
whole-text filtering of the 2.7 KB reply takes 0.35 ms (`BenchmarkApply`). The
same text streamed in 4-byte writes takes 0.64 ms (`BenchmarkStream4`).
Injection scoring of the 1.7 KB prompt takes 0.084 ms (`BenchmarkEvaluate`).

These are local measurements on an Apple M1 Pro (darwin/arm64, 8 CPUs). The
upstream, the gateway and the load generator share one process and the
loopback interface, and other jobs were running on the machine. Treat them as
relative numbers. In the streaming case most of the added time is the extra
proxy hop: one JSON decode, one re-encode and one write per event.

## Tests and quality gates

`make check` runs gofmt, `go vet`, golangci-lint (zero findings), the full suite
under `-race`, and the coverage gate. The gate reports **96.0%** statement
coverage of `internal/` and fails below 80% (`./scripts/coverage.sh`).
Highlights:

- `internal/filter`: **chunk-boundary property test**. 1,500 random texts packed with
  valid and near-miss values, random action mixes, random chunkings including
  byte-at-a-time (splitting UTF-8 runes). The streamed result, findings and
  block decision must equal a naive whole-text oracle. A native Go fuzz target
  (`make fuzz`) checks the same invariant. `make mutation` applies three
  mutants to the hold-back logic and confirms the property test fails on each.
- `internal/gateway`: **HTTP-level SSE property test**. Random replies, random
  delta sizes and random raw byte splits of the SSE wire format. The client's
  assembled stream must equal whole-text filtering and the buffered endpoint,
  in both redact and block modes. Also covers auth, rate limits, hot reload,
  upstream failures, multi-choice streams, malformed events and streams that
  end without `[DONE]`.
- `cmd/guardrail-gw`: starts the real server, edits the config, sends `SIGHUP`,
  observes the new policy, shuts down gracefully and verifies the audit chain.
- `cmd/corpusgen`: the committed corpus must equal fresh generator output (drift guard).

CI (`.github/workflows/ci.yml`) runs the same gates plus `make eval` and `make demo`.
It has not been executed yet because the repository has not been pushed.

## Limitations

- **Heuristics, not understanding.** The injection scorer matches phrasing. It
  will miss paraphrased, multilingual, or encoded attacks (base64, ROT13), and
  attacks split across messages. Treat it as a tripwire, not a defense.
- **Synthetic evaluation.** The data is generated from templates by the same
  person who wrote the detectors. Real chat logs will have formats,
  languages and contexts that are not covered here. No public PII or
  injection benchmark was used.
- **Formats covered are a subset.** One national-ID scheme per country (US,
  IN, ES, CN), IBANs for 47 registry countries, uppercase IBANs only, no
  names or street addresses, and no free-form PII such as health data. Phone
  validation is strict NANP for North American numbers. Model-invented
  numbers such as `(800) 123-4567` have an invalid exchange and are **not**
  redacted, which `make demo-ollama` shows.
- **Only `content` is filtered.** Streamed and buffered `tool_calls`
  arguments, image parts and the legacy `/v1/completions` endpoint are not
  inspected. Only `/v1/chat/completions` and `/v1/models` are served.
- **Length bounds.** Secrets longer than a detector's bound are not detected:
  random runs over 512 bytes, credential values over 64, JWT segments over
  1,000. Overlong runs are skipped on purpose (data URIs, blobs) rather than
  half-redacted.
- **Keyword context is coarse.** A credential keyword anywhere in the 40
  bytes before a token lowers the entropy threshold, which causes the
  false positives described above.
- **Single process.** Rate-limit buckets and metrics live in memory, so they
  are not shared across replicas and reset on restart. Audit appends are not
  fsynced. Opening the log verifies the whole chain, which is O(file size).
- **Upstream errors are relayed verbatim** (bounded in size) and are not
  filtered.
- **Benchmarks** are single-machine, loopback and in-process. Network,
  TLS, and a real model's token cadence change the picture.

## Roadmap

- Fix the two documented injection-normalizer gaps. Re-tune on dev and
  evaluate on a fresh held-out split.
- Filter `tool_calls` arguments with the same streaming engine (it already
  handles arbitrary text).
- Optional reversible pseudonymization: restore request placeholders in
  responses for the same caller.
- Shared state (Redis) for rate limits across replicas. OpenTelemetry traces.
- Evaluate against public datasets (for example a prompt-injection
  benchmark and a PII NER corpus), with licenses recorded in DATA.md.

## License

MIT, see [LICENSE](LICENSE).
