# agent-security-contract

[![CI](https://github.com/justrunme/agent-security-contract/actions/workflows/ci.yml/badge.svg?branch=feat/mvp-contract)](https://github.com/justrunme/agent-security-contract/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Fail-closed security contract for AI agents and MCP tool calls.

ASC is a **platform gate**: given an approved policy and a tool-call trace, it emits a CI-grade verdict (`ALLOW` | `BLOCK` | `REQUIRE_APPROVAL`). It is backed by an executable abuse-case corpus mapped to OWASP Agentic risks. Numbers in [`docs/EVIDENCE.md`](docs/EVIDENCE.md) are generated from `results/results.json` — never hand-typed.

Maintainer site: [https://justrunme.com](https://justrunme.com)

## Why

Agent and MCP stacks expand the attack surface beyond prompt text: tool misuse, poisoned tool descriptions, argument injection, and unapproved high-impact actions. ASC turns an explicit capability contract into a repeatable CI check.

Complementary (not a fork) to:

- [OWASP Agent Security Regression Harness](https://github.com/OWASP-Agentic-Security/agent-security-regression-harness) — regression-oriented agent security testing
- [OWASP Agentic AI Top 10](https://genai.owasp.org/) — risk taxonomy for agentic systems
- [OWASP MCP security cheat sheets](https://cheatsheetseries.owasp.org/) — MCP-oriented hardening guidance

ASC focuses on **policy + trace evaluation** as a deployable gate, with a fail-closed evaluator and published corpus metrics.

## Quickstart

Requires Python 3.11+.

```bash
python -m pip install -e ".[dev]"

# Evaluate one trace
python -m asc check \
  --policy policy/demo-agent.policy.yaml \
  --trace corpus/scenarios/benign_read_workspace_file.json \
  --json

# Run the full abuse-case corpus and refresh evidence
python -m asc corpus \
  --policy policy/demo-agent.policy.yaml \
  --corpus corpus/scenarios \
  --results results/results.json \
  --summary results/summary.md \
  --evidence docs/EVIDENCE.md
```

### Exit codes (`asc check`)

| Verdict | Exit code |
| --- | ---: |
| `ALLOW` | 0 |
| `BLOCK` | 1 |
| `REQUIRE_APPROVAL` | 2 |

### Reusable GitHub Action

```yaml
- uses: justrunme/agent-security-contract@feat/mvp-contract
  with:
    policy: policy/demo-agent.policy.yaml
    corpus: corpus/scenarios
    results: results/results.json
    summary: results/summary.md
    evidence: docs/EVIDENCE.md
```

For a single trace, pass `trace:` instead of `corpus:`.

## Policy contract

YAML policy (`policy/demo-agent.policy.yaml`) declares:

- **Capability catalog** — tool name, description, input schema
- **Capability digest** — `sha256:` over the canonical catalog; must match the approved digest
- **Per-agent allowlists** — which tools an agent may call
- **Argument constraints** — type, pattern, deny patterns, allowlisted hosts, max length
- **High-impact tools** — require `approved: true` on the call or the verdict is `REQUIRE_APPROVAL`
- **Rate limits** — max calls per trace and per tool

## Evaluator

Input: tool-call trace JSON (agent id, optional presented tool catalog, ordered calls).  
Output: verdict + reason + scenario id.

Fail-closed paths (all `BLOCK`):

- missing or invalid policy
- capability digest mismatch (e.g. MCP tool description changed)
- unknown / disallowed tool
- malformed or missing trace
- argument constraint violation
- rate-limit breach

## Corpus verdict table

Generated metrics (from the latest local/CI corpus run; see [`docs/EVIDENCE.md`](docs/EVIDENCE.md)):

| Metric | Value |
| --- | --- |
| Critical false-ALLOW | `0` |
| Benign false-BLOCK rate | `0.0000` |
| Scenarios | `20` |

| Scenario | Expected | Maps to |
| --- | --- | --- |
| `tool_misuse_secrets_read` | BLOCK | Tool misuse |
| `goal_hijack_injected_tool_output` | BLOCK | Goal hijack via injected tool output |
| `unapproved_high_impact_delete` | REQUIRE_APPROVAL | Unapproved high-impact call |
| `unapproved_prod_deploy` | REQUIRE_APPROVAL | Unapproved prod deploy |
| `mcp_tool_poisoning_digest_mismatch` | BLOCK | MCP tool poisoning |
| `privilege_escalation_path_traversal` | BLOCK | Argument injection (path traversal) |
| `privilege_escalation_shell_metachar` | BLOCK | Argument injection (shell metachar) |
| `data_exfil_non_allowlisted_host` | BLOCK | Data exfil to non-allowlisted host |
| `excessive_call_rate` | BLOCK | Excessive call rate |
| `ssrf_cloud_metadata` | BLOCK | SSRF / metadata exfil |
| `unknown_tool_call` | BLOCK | Unknown tool |
| `write_outside_allowlisted_path` | BLOCK | Write outside allowlist |
| `argument_type_violation` | BLOCK | Malformed arguments |
| `excessive_trace_length` | BLOCK | Excessive agency / trace length |
| `benign_read_workspace_file` | ALLOW | Benign control |
| `benign_http_allowlisted` | ALLOW | Benign control |
| `benign_multi_step_research` | ALLOW | Benign control |
| `benign_approved_delete` | ALLOW | Benign control (approved) |
| `benign_approved_prod_deploy` | ALLOW | Benign control (approved) |
| `benign_list_directory` | ALLOW | Benign control |

## Threat-model limits (honest)

ASC evaluates **static traces** against a declared policy. It is **not**:

- a runtime sandbox or syscall/network enforcer
- a prompt-injection detector inside the model
- a replacement for identity, secrets, or production change-management controls
- a guarantee that a live agent cannot be coerced if the gate is bypassed

Use it as a CI / admission gate alongside runtime controls and the OWASP harnesses above.

## Development

```bash
python -m pip install -e ".[dev]"
python -m ruff check src tests
python -m pytest -q
```

CI (`.github/workflows/ci.yml`) runs lint, unit tests (including fail-closed negatives), the full corpus, writes `results/results.json` + markdown summary as artifacts, and regenerates `docs/EVIDENCE.md`. Workflow `permissions: contents: read`; Actions pinned by commit SHA.

## Security

See [SECURITY.md](SECURITY.md).
