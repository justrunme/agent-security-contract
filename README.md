# agent-security-contract

[![CI](https://github.com/justrunme/agent-security-contract/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/justrunme/agent-security-contract/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Fail-closed security contract for AI agents and MCP tool calls.

ASC is a **platform gate**: given an approved policy and a tool-call trace, it emits a CI-grade evidence envelope with verdict `ALLOW` | `BLOCK` | `REQUIRE_APPROVAL`. It is backed by an executable abuse-case corpus. Numbers in [`docs/EVIDENCE.md`](docs/EVIDENCE.md) are generated from `results/results.json` — never hand-typed.

**Claims are scoped:** metrics and pass/fail statements apply **on this corpus of N scenarios** only. They do not imply general agent safety.

Maintainer site: [https://justrunme.com](https://justrunme.com)

## Why

Agent and MCP stacks expand the attack surface beyond prompt text: tool misuse, poisoned tool descriptions, argument injection, and unapproved high-impact actions. ASC turns an explicit capability contract into a repeatable **pre-execution** CI / admission check.

Aligned with (complementary, not a fork):

- [OWASP Agent Control Standard (ACS)](https://genai.owasp.org/resource/agent-control-standard-acs/) (published 2026-09-01) — middleware hooks and runtime Guardian dispositions; ASC maps to Instrument [`toolCallRequest`](https://genai-security-project.github.io/agent-control-standard/docs/spec/instrument/hooks/) with `ALLOW` / `DENY` / `ASK`
- [OWASP Agentic AI / Agentic Applications Top 10](https://genai.owasp.org/initiatives/agentic-security-initiative/) — risk taxonomy for scenario mapping
- [OWASP MCP security cheat sheets](https://genai.owasp.org/resources/?e-filter-3b7adda-resource-item=cheat-sheets) — MCP hardening guidance
- [OWASP Agent Security Regression Harness](https://github.com/OWASP/Agent-Security-Regression-Harness) — regression-oriented agent security testing

## Positioning (honest)

ASC’s differentiator is **pre-execution ENFORCEMENT**, not detection: the gate prevents the tool call (or requires approval) and proves the decision in CI via an evidence envelope.

| Project | Primary job | When it runs | Relation to ASC |
| --- | --- | --- | --- |
| **ASC (this repo)** | Fail-closed policy gate + evidence envelope | Before tool execution / in CI admission | Enforcement oracle |
| [Promptfoo](https://www.promptfoo.dev/) (MCP red teaming) | Attack generation & detection findings in CI | Eval / red-team jobs | Complementary detection; does not replace an admission deny |
| OWASP Agent Security Regression Harness | Regression suite for agent security behaviors | CI regression | Complementary testing; ASC can act as an enforcement profile |
| LiteLLM / guardrails | Request/response filtering & provider controls | Proxy / runtime path | Complementary runtime filters; ASC focuses on tool-capability contracts + digest pinning |

## Quickstart

Requires Python 3.11+.

```bash
python -m pip install -e ".[dev]"

# Evaluate one trace — prints a full evidence envelope with --json
python -m asc check \
  --policy policy/demo-agent.policy.yaml \
  --trace corpus/scenarios/benign_read_workspace_file.json \
  --json

# Verify an envelope (rejects invalid/tampered envelopes)
python -m asc check \
  --policy policy/demo-agent.policy.yaml \
  --trace corpus/scenarios/benign_read_workspace_file.json \
  --json --envelope-out /tmp/env.json
python -m asc verify --envelope /tmp/env.json --policy policy/demo-agent.policy.yaml

# Run the full corpus and refresh evidence
python -m asc corpus \
  --policy policy/demo-agent.policy.yaml \
  --corpus corpus/scenarios \
  --results results/results.json \
  --summary results/summary.md \
  --evidence docs/EVIDENCE.md
```

### Exit codes (`asc check`)

| Verdict | Exit code | ACS disposition |
| --- | ---: | --- |
| `ALLOW` | 0 | `ALLOW` |
| `BLOCK` | 1 | `DENY` |
| `REQUIRE_APPROVAL` | 2 | `ASK` |

### Reusable GitHub Action

```yaml
- uses: justrunme/agent-security-contract@v0.2.0
  with:
    policy: policy/demo-agent.policy.yaml
    corpus: corpus/scenarios
    results: results/results.json
    summary: results/summary.md
    evidence: docs/EVIDENCE.md
```

### Runtime integration

Call the evaluator **before** tool execution (library or HTTP sidecar). See [`docs/INTEGRATION.md`](docs/INTEGRATION.md). On sidecar/client timeout, fail closed (`BLOCK`); `asc.client.evaluate_remote()` does this for you.

```bash
python -m asc.sidecar --policy policy/demo-agent.policy.yaml --port 8788
```

## Policy contract

YAML policy (`policy/demo-agent.policy.yaml`) declares:

- **Capability catalog** — tool name, description, input schema
- **Capability digest** — `sha256:` over the canonical catalog; must match the approved digest
- **Per-agent allowlists** — which tools an agent may call
- **Argument constraints** — type, pattern, deny patterns, allowlisted hosts, max length, and per-arg `required` (default `true`); undeclared args are rejected; omitted optional args are allowed
- **Path canonicalization** — path args are percent-decoded, NUL-checked, slash-collapsed, and `..`-resolved before allowlist checks
- **High-impact tools** — require `approved: true` on the call or the verdict is `REQUIRE_APPROVAL`; destructive paths that resolve to a parent/root still `BLOCK`
- **Rate limits** — max calls per trace and per tool

## Evidence envelope

Every verdict emits JSON conforming to [`schemas/evidence-envelope.schema.json`](schemas/evidence-envelope.schema.json):

| Field | Meaning |
| --- | --- |
| `schema_version` | Envelope schema (`1.0.0`) |
| `policy_version` | Policy document version |
| `policy_sha256` | SHA-256 of the policy file bytes |
| `scenario_id` | Corpus / caller scenario id |
| `verdict` / `reason` | Decision |
| `trace_id` | Trace identifier |
| `commit_sha` | `ASC_COMMIT_SHA` / `GITHUB_SHA` / `unknown` (CI sets `ASC_COMMIT_SHA` to the PR head or push SHA) |
| `timestamp` | UTC ISO-8601 |
| `envelope_sha256` | SHA-256 over the canonical JSON of all other fields |

`asc verify` rejects missing fields, invalid values, disposition/verdict inconsistency, any edit that no longer matches `envelope_sha256`, and (when `--policy` is set) a `policy_sha256` that differs from the policy file.

`envelope_sha256` is an unkeyed integrity digest, not a signature: it catches accidental or naive edits, but someone who can rewrite the file can also recompute it. Treat envelopes as trustworthy only when they come from a CI run you control (for example, the uploaded workflow artifact).

## Corpus metrics (generated)

See [`docs/EVIDENCE.md`](docs/EVIDENCE.md) for the current run. Metrics are always phrased **on this corpus of N scenarios**.

Positive coverage is first-class: legitimate `ALLOW` scenarios are at least as numerous as attack scenarios; benign false-BLOCK is reported next to critical false-ALLOW.

## Threat-model limits (honest)

ASC evaluates **static traces** (and pre-execution hook payloads) against a declared policy. It is **not**:

- a signer: evidence envelopes carry an integrity digest but no signature or attestation yet
- a full ACS wire Guardian (no session audit chain, no `MODIFY`/`DEFER` dispositions yet)
- a runtime OS sandbox or network enforcer by itself
- a prompt-injection detector inside the model
- a replacement for identity, secrets, or production change-management controls
- a claim of general agent safety beyond **this corpus of N scenarios**

Use it as a CI / admission gate alongside runtime controls, Promptfoo-style red teaming, and ACS-compliant Guardians.

## Upstream

Possible OWASP upstream contributions: [`docs/UPSTREAM.md`](docs/UPSTREAM.md).

## Development

```bash
python -m pip install -e ".[dev]"
python -m ruff check src tests
python -m pytest -q
```

CI (`.github/workflows/ci.yml`) runs lint, unit tests (including fail-closed and envelope negatives), the full corpus, writes `results/results.json` + markdown summary as artifacts, and regenerates `docs/EVIDENCE.md`. Workflow `permissions: contents: read`; Actions pinned by commit SHA.

## Security

See [SECURITY.md](SECURITY.md).
