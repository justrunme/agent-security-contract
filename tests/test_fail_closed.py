"""Negative tests for every fail-closed path."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from asc.digest import compute_capability_digest
from asc.evaluator import evaluate, evaluate_paths, evaluate_trace_data
from asc.models import Verdict
from asc.policy import PolicyError, load_policy, parse_policy
from asc.trace import TraceError, parse_trace


@pytest.fixture
def policy():
    return load_policy("policy/demo-agent.policy.yaml")


def _minimal_trace(tool: str = "filesystem.read", **call_extra):
    catalog = [
        {
            "name": t.name,
            "description": t.description,
            "input_schema": t.input_schema,
        }
        for t in load_policy("policy/demo-agent.policy.yaml").capabilities
    ]
    call = {"call_id": "c1", "tool": tool, "args": {"path": "/workspace/README.md"}}
    call.update(call_extra)
    return {
        "agent_id": "demo-agent",
        "trace_id": "fail-closed",
        "tool_catalog": catalog,
        "calls": [call],
    }


def test_missing_policy_blocks(tmp_path: Path) -> None:
    trace = tmp_path / "trace.json"
    trace.write_text(json.dumps(_minimal_trace()), encoding="utf-8")
    result = evaluate_paths(
        str(tmp_path / "missing.yaml"),
        str(trace),
        scenario_id="missing-policy",
    )
    assert result.verdict == Verdict.BLOCK
    assert "policy" in result.reason.lower()


def test_invalid_policy_yaml_blocks(tmp_path: Path) -> None:
    policy = tmp_path / "bad.yaml"
    policy.write_text("version: [\n", encoding="utf-8")
    trace = tmp_path / "trace.json"
    trace.write_text(json.dumps(_minimal_trace()), encoding="utf-8")
    result = evaluate_paths(str(policy), str(trace), scenario_id="bad-yaml")
    assert result.verdict == Verdict.BLOCK


def test_policy_digest_mismatch_rejected() -> None:
    raw = yaml.safe_load(Path("policy/demo-agent.policy.yaml").read_text(encoding="utf-8"))
    raw["capability_digest"] = "sha256:" + ("ab" * 32)
    with pytest.raises(PolicyError, match="capability_digest mismatch"):
        parse_policy(raw)


def test_empty_policy_blocks(tmp_path: Path) -> None:
    policy = tmp_path / "empty.yaml"
    policy.write_text("", encoding="utf-8")
    trace = tmp_path / "trace.json"
    trace.write_text(json.dumps(_minimal_trace()), encoding="utf-8")
    result = evaluate_paths(str(policy), str(trace), scenario_id="empty-policy")
    assert result.verdict == Verdict.BLOCK


def test_malformed_trace_blocks(policy) -> None:
    result = evaluate_trace_data(policy, {"agent_id": "demo-agent"}, scenario_id="malformed")
    assert result.verdict == Verdict.BLOCK
    assert "malformed" in result.reason.lower() or "invalid" in result.reason.lower()


def test_invalid_trace_json_blocks(tmp_path: Path, policy) -> None:
    policy_path = Path("policy/demo-agent.policy.yaml")
    trace = tmp_path / "bad.json"
    trace.write_text("{not-json", encoding="utf-8")
    result = evaluate_paths(str(policy_path), str(trace), scenario_id="bad-json")
    assert result.verdict == Verdict.BLOCK


def test_digest_mismatch_blocks(policy) -> None:
    data = _minimal_trace()
    data["tool_catalog"][0]["description"] = "POISONED DESCRIPTION"
    result = evaluate_trace_data(policy, data, scenario_id="digest-mismatch")
    assert result.verdict == Verdict.BLOCK
    assert "digest" in result.reason.lower()


def test_unknown_tool_blocks(policy) -> None:
    data = _minimal_trace(tool="not.a.tool")
    data["calls"][0]["args"] = {}
    result = evaluate_trace_data(policy, data, scenario_id="unknown-tool")
    assert result.verdict == Verdict.BLOCK
    assert "unknown" in result.reason.lower() or "disallowed" in result.reason.lower()


def test_unknown_agent_blocks(policy) -> None:
    data = _minimal_trace()
    data["agent_id"] = "stranger"
    result = evaluate_trace_data(policy, data, scenario_id="unknown-agent")
    assert result.verdict == Verdict.BLOCK


def test_missing_trace_file_blocks(tmp_path: Path) -> None:
    result = evaluate_paths(
        "policy/demo-agent.policy.yaml",
        str(tmp_path / "nope.json"),
        scenario_id="missing-trace",
    )
    assert result.verdict == Verdict.BLOCK


def test_parse_trace_rejects_non_bool_approved() -> None:
    with pytest.raises(TraceError):
        parse_trace(
            {
                "agent_id": "demo-agent",
                "trace_id": "x",
                "calls": [{"tool": "filesystem.read", "args": {}, "approved": "yes"}],
            }
        )


def test_evaluate_allow_happy_path(policy) -> None:
    result = evaluate_trace_data(policy, _minimal_trace(), scenario_id="happy")
    assert result.verdict == Verdict.ALLOW


def test_compute_digest_used_in_evaluate(policy) -> None:
    observed = compute_capability_digest(policy.capabilities)
    assert observed == policy.capability_digest
    result = evaluate(policy, parse_trace(_minimal_trace()), scenario_id="digest-ok")
    assert result.verdict == Verdict.ALLOW


def test_evaluator_exception_blocks(policy, monkeypatch) -> None:
    """An unexpected exception inside the evaluator must yield BLOCK, not crash or ALLOW."""
    import asc.evaluator as ev

    def boom(*_a, **_k):
        raise RuntimeError("injected failure")

    monkeypatch.setattr(ev, "_check_rate_limits", boom)
    trace = ev.parse_trace(_minimal_trace())
    result = ev.evaluate(policy, trace, scenario_id="evaluator-exception")
    assert result.verdict == Verdict.BLOCK
    assert "evaluator error" in result.reason


def test_non_mapping_trace_blocks(policy) -> None:
    assert evaluate_trace_data(policy, ["not", "a", "dict"]).verdict == Verdict.BLOCK
