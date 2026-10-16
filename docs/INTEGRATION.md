# Integration: pre-execution enforcement hook

ASC is meant to be called **before** a tool executes. That is the differentiator versus CI-only red-team detectors: the gate can prevent the call and emit an evidence envelope proving the decision.

## Library call (ai-runtime / ai-infra-control-plane)

```python
from asc.evaluator import evaluate_trace_data
from asc.envelope import build_envelope
from asc.policy import load_policy
from asc.trace import parse_trace

policy = load_policy("/etc/asc/agent.policy.yaml")

def before_tool_execute(agent_id: str, call: dict) -> dict:
    trace = {
        "agent_id": agent_id,
        "trace_id": call["trace_id"],
        "tool_catalog": call.get("tool_catalog"),
        "calls": [call["tool_call"]],
    }
    result = evaluate_trace_data(policy, trace, scenario_id=call.get("scenario_id", "runtime"))
    envelope = build_envelope(
        result=result,
        policy=policy,
        policy_path="/etc/asc/agent.policy.yaml",
        trace=parse_trace(trace),
    )
    if result.verdict.value != "ALLOW":
        raise PermissionError(envelope)
    return envelope
```

Fail-closed rules for the host:

- If the evaluator raises, **do not execute** the tool.
- If the policy file is missing/invalid, the evaluator returns `BLOCK`.
- If your control-plane RPC times out waiting for ASC, treat as `BLOCK`.

## HTTP sidecar example

```bash
python -m asc.sidecar --policy policy/demo-agent.policy.yaml --host 127.0.0.1 --port 8788
```

```http
POST /v1/evaluate
Content-Type: application/json

{
  "scenario_id": "runtime",
  "trace": {
    "agent_id": "demo-agent",
    "trace_id": "runtime-1",
    "calls": [
      {"call_id": "c1", "tool": "filesystem.read", "args": {"path": "/workspace/README.md"}}
    ]
  }
}
```

Responses:

| HTTP | ASC verdict |
| --- | --- |
| 200 | `ALLOW` |
| 401 | `REQUIRE_APPROVAL` (ACS disposition `ASK`) |
| 403 | `BLOCK` (ACS disposition `DENY`) |
| 503 | sidecar internal failure → treat as `BLOCK` |

Caller-side timeout pseudocode:

```python
try:
    envelope = post_json(url, payload, timeout_ms=50)
except TimeoutError:
    envelope = {"verdict": "BLOCK", "reason": "asc sidecar timeout (fail-closed)"}
```

## ACS alignment

This hook corresponds to the OWASP Agent Control Standard (ACS) Instrument hook [`toolCallRequest`](https://genai-security-project.github.io/agent-control-standard/docs/spec/instrument/hooks/) (pre-execution Guardian decision). ASC verdicts map to ACS dispositions:

| ASC | ACS disposition |
| --- | --- |
| `ALLOW` | `ALLOW` |
| `BLOCK` | `DENY` |
| `REQUIRE_APPROVAL` | `ASK` |
