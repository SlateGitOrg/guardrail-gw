# Threat model

guardrail-gw is a defensive control between internal LLM applications and a
self-hosted model server. This document states what it protects, from whom,
and where its guarantees stop. All testing in this repository runs against
local fixtures (`internal/fakeupstream`) or a local Ollama instance. Nothing
targets third-party systems.

## Assets

| Asset | Why it matters |
|---|---|
| PII in prompts (customer e-mails, phones, cards, IBANs, national IDs) | Must not reach the model, its logs, or downstream fine-tuning data |
| Credentials pasted into prompts (cloud keys, tokens, passwords) | High-impact if logged or echoed back |
| Model output | May echo or invent PII/secrets; may be steered by injected instructions |
| Client API keys | Gate access and select policy |
| Audit log | Evidence of what was blocked or redacted, and must itself not leak data |
| Configuration | Controls every decision. A bad edit must not open the gate |

## Actors

- **Well-meaning users** who paste sensitive data by accident. This is the
  primary case.
- **Prompt-injection authors**, either direct users or third parties whose
  content arrives as a `tool` message or a quoted document (indirect
  injection).
- **A model that leaks.** It repeats data from context, hallucinates
  plausible secrets, or follows injected instructions.
- **A curious insider with log access.** They should learn that a leak
  happened, not what leaked.
- **Out of scope:** an attacker with the gateway host, its config file or the
  HMAC key, and a malicious upstream operator.

## Trust boundaries

1. Client → gateway: authenticated by a bearer key, compared as a SHA-256
   hash. Raw keys are never stored in config. The client key is never
   forwarded upstream.
2. Gateway → upstream: the request has already been redacted. Upstream
   credentials come from an environment variable.
3. Upstream → gateway: untrusted. Every content delta is filtered, events
   that are not JSON are dropped, and sizes are bounded (events at 1 MiB,
   buffered bodies at `limits.max_response_bytes`).
4. Gateway → audit log: append-only and hash-chained, with values stored only
   as keyed HMACs.

## Threats and mitigations

| # | Threat | Mitigation | Residual risk |
|---|---|---|---|
| T1 | PII in a prompt reaches the model | Request redaction with typed placeholders, or a block | Formats not covered (names, addresses, other countries' IDs); obfuscated numbers ("four one one one ...") |
| T2 | Secret in a prompt is logged upstream | Default request action for secrets is `block` | Unknown secret formats with low entropy; values over the length bounds |
| T3 | Model output leaks PII or secrets | Response filtering, buffered and streaming | Only `content` is filtered, not `tool_calls` arguments |
| T4 | Leak split across SSE chunks evades a per-chunk filter | Chunk-boundary-exact streaming algorithm, proven in ARCHITECTURE.md and tested at the filter and HTTP levels | None known within the detector contract |
| T5 | Direct prompt injection | Weighted heuristic scorer on `user` messages, block at threshold | Paraphrases, other languages, encodings. The scorer is a tripwire, not a guarantee |
| T6 | Indirect injection via tool output | `tool` messages are scored too | Same as T5. Injected text inside documents the app puts in `system` messages is not scored |
| T7 | Unicode tricks (homoglyphs, zero-width, full-width, spacing, leetspeak) | Normalization before matching. Zero-width characters are a signal on their own | Other scripts and confusables beyond the mapped set. Spacing that begins right after punctuation (see README) |
| T8 | Gateway resource exhaustion | Per-key token buckets; body and event size limits; bounded detector work per byte; upstream timeout bounds whole exchanges | No global concurrency cap, no per-IP limits, in-memory buckets per replica |
| T9 | Audit log reveals data | Values stored as `HMAC-SHA256(key, kind‖value)`, truncated | Low-entropy values (phone numbers) can be brute-forced by anyone who holds the HMAC key |
| T10 | Audit tampering (hiding a leak) | Hash chain detects edits, deletions, reordering. `audit-verify` command. Startup refuses a broken chain | An attacker who can rewrite the whole file can recompute the chain. Anchor the head hash externally for stronger guarantees |
| T11 | Bad config disables protection | Strict schema (unknown keys rejected), all-errors validation, invalid reloads ignored, previous snapshot kept | A *valid* but permissive edit (for example `pii: allow`) is applied. Protect the file with OS permissions and review |
| T12 | Key theft or replay | Keys hashed at rest; removing a key from config revokes it on the next reload | No key expiry or rotation workflow; bearer keys over plain HTTP if TLS is not added in front |
| T13 | Placeholder confusion (model output contains fake `[EMAIL_1]`) | Placeholders are informational. Values are never restored, so a fake placeholder cannot extract data | None |

## Explicit non-goals

- No TLS termination (put a reverse proxy in front), no user identity beyond
  API keys, no content moderation (toxicity, self-harm). Those are separate
  controls.
- No evasion or stealth features, and no offensive capability. The
  repository's "attacks" are benign strings in a synthetic corpus, used to
  measure detection.

## Safe test data

Every sensitive-looking value in tests, the corpus and the demo is fabricated
or a published documentation example: AWS's `AKIAIOSFODNN7EXAMPLE`, Luhn-valid
test PANs such as `4111 1111 1111 1111`, and the jwt.io sample token.
Generated values follow checksum rules but are random and do not belong to
real people.
