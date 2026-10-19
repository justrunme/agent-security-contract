"""Unit tests for argument constraints and high-impact approval."""

from __future__ import annotations

import pytest

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


def test_shell_credential_paths_blocked() -> None:
    policy = load_policy("policy/demo-agent.policy.yaml")
    for command in (
        "cat /root/.aws/credentials",
        "cat /etc/shadow",
        "cat /proc/self/environ",
    ):
        result = evaluate_trace_data(
            policy,
            _trace([{"call_id": "c1", "tool": "shell.exec", "args": {"command": command}}]),
            scenario_id="shell-creds",
        )
        assert result.verdict == Verdict.BLOCK, command


def test_url_encoded_and_parent_traversal_blocked() -> None:
    policy = load_policy("policy/demo-agent.policy.yaml")
    for path in (
        "/workspace/..",
        "/workspace/..%2fetc/passwd",
        "/workspace/%252e%252e%252fetc/passwd",
        "/workspace//../etc/passwd",
        "../etc/passwd",
    ):
        result = evaluate_trace_data(
            policy,
            _trace([{"call_id": "c1", "tool": "filesystem.read", "args": {"path": path}}]),
            scenario_id="trav",
        )
        assert result.verdict == Verdict.BLOCK, path


def test_approved_delete_parent_still_blocked() -> None:
    policy = load_policy("policy/demo-agent.policy.yaml")
    result = evaluate_trace_data(
        policy,
        _trace(
            [
                {
                    "call_id": "c1",
                    "tool": "filesystem.delete",
                    "args": {"path": "/workspace/out/.."},
                    "approved": True,
                }
            ]
        ),
        scenario_id="del-parent",
    )
    assert result.verdict == Verdict.BLOCK


def test_undeclared_arguments_blocked() -> None:
    policy = load_policy("policy/demo-agent.policy.yaml")
    result = evaluate_trace_data(
        policy,
        _trace(
            [
                {
                    "call_id": "c1",
                    "tool": "filesystem.read",
                    "args": {"path": "/workspace/README.md", "extra": "nope"},
                }
            ]
        ),
        scenario_id="extra-arg",
    )
    assert result.verdict == Verdict.BLOCK
    assert "undeclared" in result.reason.lower()



def _shell_verdict(command: str) -> Verdict:
    policy = load_policy("policy/demo-agent.policy.yaml")
    result = evaluate_trace_data(
        policy,
        _trace([{"call_id": "c1", "tool": "shell.exec", "args": {"command": command}}]),
        scenario_id="shell",
    )
    return result.verdict


@pytest.mark.parametrize(
    "command",
    [
        "echo pwned > /etc/cron.d/x",
        "echo x >> /workspace/out/log.txt",
        "cat < /etc/hostname",
        "cat /workspace/{README.md,../../etc/hostname}",
        "cat /workspace/..\\/..\\/etc/hostname",
        "cat '/etc/hostname'",
        'cat "/workspace/../etc/hostname"',
        "cat /workspace/[.]./etc/hostname",
        "ls (/etc)",
    ],
)
def test_shell_syntax_abuse_blocked(command: str) -> None:
    assert _shell_verdict(command) == Verdict.BLOCK, command


@pytest.mark.parametrize(
    "command",
    [
        "ls -la /workspace/out",
        "ls -1 /workspace",
        "cat /workspace/docs/setup.aws.md",
        "cat /workspace/docs/credentials-rotation.md",
        "echo rotate credentials weekly",
    ],
)
def test_shell_legitimate_commands_allowed(command: str) -> None:
    assert _shell_verdict(command) == Verdict.ALLOW, command


@pytest.mark.parametrize("command", ["ls -la", "ls -- /etc", "cat -n /etc/hostname"])
def test_shell_flags_do_not_satisfy_path_requirement(command: str) -> None:
    assert _shell_verdict(command) == Verdict.BLOCK, command


def test_directory_argument_with_trailing_slash() -> None:
    policy = load_policy("policy/demo-agent.policy.yaml")

    def verdict(tool: str, path: str, approved: bool = False) -> Verdict:
        call = {"call_id": "c1", "tool": tool, "args": {"path": path}, "approved": approved}
        return evaluate_trace_data(policy, _trace([call]), scenario_id="dir").verdict

    assert verdict("filesystem.list", "/workspace/") == Verdict.ALLOW
    assert verdict("filesystem.list", "/workspace/out/") == Verdict.ALLOW
    assert verdict("filesystem.delete", "/workspace/out/", approved=True) == Verdict.BLOCK
    assert verdict("filesystem.list", "/workspace/out/../../") == Verdict.BLOCK
