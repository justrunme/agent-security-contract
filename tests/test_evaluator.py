"""Unit tests for argument constraints and high-impact approval."""

from __future__ import annotations

from asc.evaluator import evaluate_trace_data
from asc.models import Verdict
from asc.policy import load_policy


def _catalog():
    policy = load_policy("policy/demo-agent.policy.yaml")
    return [
        {"name": t.name, "description": t.description, "input_schema": t.input_schema}
        for t in policy.capabilities
    ]


def _trace(calls):
    return {
        "agent_id": "demo-agent",
        "trace_id": "unit",
        "tool_catalog": _catalog(),
        "calls": calls,
    }


def test_path_traversal_blocked() -> None:
    policy = load_policy("policy/demo-agent.policy.yaml")
    result = evaluate_trace_data(
        policy,
        _trace(
            [
                {
                    "call_id": "c1",
                    "tool": "filesystem.read",
                    "args": {"path": "/workspace/../etc/passwd"},
                }
            ]
        ),
        scenario_id="trav",
    )
    assert result.verdict == Verdict.BLOCK


def test_shell_metachar_blocked() -> None:
    policy = load_policy("policy/demo-agent.policy.yaml")
    result = evaluate_trace_data(
        policy,
        _trace([{"call_id": "c1", "tool": "shell.exec", "args": {"command": "ls; rm -rf /"}}]),
        scenario_id="meta",
    )
    assert result.verdict == Verdict.BLOCK


def test_non_allowlisted_host_blocked() -> None:
    policy = load_policy("policy/demo-agent.policy.yaml")
    result = evaluate_trace_data(
        policy,
        _trace([{"call_id": "c1", "tool": "http.fetch", "args": {"url": "https://evil.example.net/x"}}]),
        scenario_id="host",
    )
    assert result.verdict == Verdict.BLOCK


def test_allowlisted_host_allowed() -> None:
    policy = load_policy("policy/demo-agent.policy.yaml")
    result = evaluate_trace_data(
        policy,
        _trace([{"call_id": "c1", "tool": "http.fetch", "args": {"url": "https://api.example.com/v1"}}]),
        scenario_id="ok-host",
    )
    assert result.verdict == Verdict.ALLOW


def test_high_impact_requires_approval() -> None:
    policy = load_policy("policy/demo-agent.policy.yaml")
    result = evaluate_trace_data(
        policy,
        _trace(
            [
                {
                    "call_id": "c1",
                    "tool": "deploy.production",
                    "args": {"service": "web", "version": "1.0.0"},
                    "approved": False,
                }
            ]
        ),
        scenario_id="need-approval",
    )
    assert result.verdict == Verdict.REQUIRE_APPROVAL


def test_high_impact_with_approval_allowed() -> None:
    policy = load_policy("policy/demo-agent.policy.yaml")
    result = evaluate_trace_data(
        policy,
        _trace(
            [
                {
                    "call_id": "c1",
                    "tool": "deploy.production",
                    "args": {"service": "web", "version": "1.0.0"},
                    "approved": True,
                }
            ]
        ),
        scenario_id="approved",
    )
    assert result.verdict == Verdict.ALLOW


def test_rate_limit_per_tool() -> None:
    policy = load_policy("policy/demo-agent.policy.yaml")
    calls = [
        {
            "call_id": f"c{i}",
            "tool": "http.fetch",
            "args": {"url": f"https://api.example.com/{i}"},
        }
        for i in range(10)
    ]
    result = evaluate_trace_data(policy, _trace(calls), scenario_id="rate")
    assert result.verdict == Verdict.BLOCK
    assert "rate" in result.reason.lower()
