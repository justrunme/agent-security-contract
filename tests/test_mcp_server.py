"""Tests for the MCP server tools."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

import pytest

from asc.mcp_server import check_tool_call, list_policy_tools, verify_corpus, verify_scenario
from asc.models import Verdict


def _catalog():
    from asc.policy import load_policy

    policy = load_policy("policy/demo-agent.policy.yaml")
    return [
        {"name": t.name, "description": t.description, "input_schema": t.input_schema}
        for t in policy.capabilities
    ]


def _trace(calls):
    return {
        "agent_id": "demo-agent",
        "trace_id": "mcp-test",
        "tool_catalog": _catalog(),
        "calls": calls,
    }


def test_check_tool_call_allow() -> None:
    trace = _trace(
        [
            {
                "call_id": "c1",
                "tool": "filesystem.read",
                "args": {"path": "/workspace/README.md"},
            }
        ]
    )
    result = check_tool_call("policy/demo-agent.policy.yaml", trace)
    assert result["verdict"] == Verdict.ALLOW.value
    assert "satisfy" in result["reason"]
    assert result["scenario_id"] == "mcp-check"
    assert result["blocked_call_id"] is None


def test_check_tool_call_block_traversal() -> None:
    trace = _trace(
        [
            {
                "call_id": "c1",
                "tool": "filesystem.read",
                "args": {"path": "/workspace/../etc/passwd"},
            }
        ]
    )
    result = check_tool_call("policy/demo-agent.policy.yaml", trace)
    assert result["verdict"] == Verdict.BLOCK.value
    assert result["blocked_call_id"] == "c1"


def test_check_tool_call_block_disallowed_host() -> None:
    trace = _trace(
        [
            {
                "call_id": "c1",
                "tool": "http.fetch",
                "args": {"url": "https://evil.example.net/x"},
            }
        ]
    )
    result = check_tool_call("policy/demo-agent.policy.yaml", trace)
    assert result["verdict"] == Verdict.BLOCK.value
    assert "not allowlisted" in result["reason"]


def test_check_tool_call_require_approval() -> None:
    trace = _trace(
        [
            {
                "call_id": "c1",
                "tool": "deploy.production",
                "args": {"service": "web", "version": "1.0.0"},
                "approved": False,
            }
        ]
    )
    result = check_tool_call("policy/demo-agent.policy.yaml", trace)
    assert result["verdict"] == Verdict.REQUIRE_APPROVAL.value
    assert "requires approval" in result["reason"]


def test_check_tool_call_approved_allow() -> None:
    trace = _trace(
        [
            {
                "call_id": "c1",
                "tool": "deploy.production",
                "args": {"service": "web", "version": "1.0.0"},
                "approved": True,
            }
        ]
    )
    result = check_tool_call("policy/demo-agent.policy.yaml", trace)
    assert result["verdict"] == Verdict.ALLOW.value


def test_check_tool_call_fail_closed_missing_policy() -> None:
    trace = _trace([{"call_id": "c1", "tool": "filesystem.read", "args": {"path": "/workspace/x"}}])
    result = check_tool_call("/nonexistent/policy.yaml", trace)
    assert result["verdict"] == Verdict.BLOCK.value
    assert "Policy load failed" in result["reason"]
    assert result["details"]["policy_load_error"] is True


def test_check_tool_call_fail_closed_invalid_trace() -> None:
    result = check_tool_call("policy/demo-agent.policy.yaml", {"invalid": "trace"})
    assert result["verdict"] == Verdict.BLOCK.value
    assert "malformed trace" in result["reason"] or "fail-closed" in result["reason"]
    assert result["details"].get("evaluation_error") is True or "agent_id" in result["reason"]


def test_check_tool_call_fail_closed_malformed_trace() -> None:
    trace = _trace(
        [
            {
                "call_id": "c1",
                "tool": "filesystem.read",
                "args": {"extra": "unexpected"},
            }
        ]
    )
    result = check_tool_call("policy/demo-agent.policy.yaml", trace)
    assert result["verdict"] == Verdict.BLOCK.value


def test_check_tool_call_custom_scenario_id() -> None:
    trace = _trace([{"call_id": "c1", "tool": "filesystem.read", "args": {"path": "/workspace/x"}}])
    result = check_tool_call("policy/demo-agent.policy.yaml", trace, scenario_id="custom-id")
    assert result["scenario_id"] == "custom-id"


def test_verify_corpus_pass() -> None:
    result = verify_corpus("policy/demo-agent.policy.yaml", "corpus/scenarios")
    assert isinstance(result, dict)
    assert "passed" in result
    assert "metrics" in result
    assert result["metrics"]["critical_false_allow"] == 0
    assert result["metrics"]["scenario_count"] > 0
    assert result["policy"] == "policy/demo-agent.policy.yaml"
    assert result["corpus"] == "corpus/scenarios"


def test_verify_corpus_with_results() -> None:
    result = verify_corpus("policy/demo-agent.policy.yaml", "corpus/scenarios", output_results=True)
    assert "scenarios" in result
    assert len(result["scenarios"]) > 0
    scenario = result["scenarios"][0]
    assert "scenario_id" in scenario
    assert "expected" in scenario
    assert "actual" in scenario
    assert "match" in scenario


def test_verify_corpus_fail_closed_missing_corpus() -> None:
    result = verify_corpus("policy/demo-agent.policy.yaml", "/nonexistent/corpus")
    assert result["passed"] is False
    assert "not found" in result["error"]
    assert result["metrics"] == {}


def test_verify_corpus_fail_closed_missing_policy() -> None:
    result = verify_corpus("/nonexistent/policy.yaml", "corpus/scenarios")
    assert result["passed"] is False
    assert "Policy load failed" in result["error"]


def test_verify_scenario_match() -> None:
    result = verify_scenario(
        "policy/demo-agent.policy.yaml",
        "corpus/scenarios/benign_read_workspace_file.json",
    )
    assert result["match"] is True
    assert result["scenario_id"] == "benign_read_workspace_file"
    assert result["expected"] == Verdict.ALLOW.value
    assert result["actual"] == Verdict.ALLOW.value
    assert "severity" in result
    assert "owasp_risk" in result
    assert "acs_controls" in result


def test_verify_scenario_attack_blocked() -> None:
    result = verify_scenario(
        "policy/demo-agent.policy.yaml",
        "corpus/scenarios/shell_exec_backslash_escape.json",
    )
    assert result["match"] is True
    assert result["expected"] == Verdict.BLOCK.value
    assert result["actual"] == Verdict.BLOCK.value


def test_verify_scenario_fail_closed_missing_file() -> None:
    result = verify_scenario("policy/demo-agent.policy.yaml", "/nonexistent/scenario.json")
    assert result["match"] is False
    assert "not found" in result["error"]


def test_verify_scenario_fail_closed_invalid_policy() -> None:
    result = verify_scenario(
        "/nonexistent/policy.yaml",
        "corpus/scenarios/benign_read_workspace_file.json",
    )
    assert result["match"] is False
    assert "Policy load failed" in result["error"]


def test_verify_scenario_fail_closed_malformed_scenario() -> None:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write('{"invalid": "scenario"}')
        temp_path = f.name

    try:
        result = verify_scenario("policy/demo-agent.policy.yaml", temp_path)
        assert result["match"] is False
        assert "missing required field" in result["error"]
    finally:
        Path(temp_path).unlink()


def test_list_policy_tools() -> None:
    result = list_policy_tools("policy/demo-agent.policy.yaml")
    assert result["version"] == "1"
    assert result["capability_digest"].startswith("sha256:")
    assert len(result["capabilities"]) > 0
    assert len(result["agents"]) > 0

    cap = result["capabilities"][0]
    assert "name" in cap
    assert "description" in cap
    assert "input_schema" in cap

    agent = result["agents"]["demo-agent"]
    assert "allowed_tools" in agent
    assert "high_impact_tools" in agent
    assert "rate_limits" in agent
    assert "filesystem.read" in agent["allowed_tools"]
    assert "deploy.production" in agent["high_impact_tools"]


def test_list_policy_tools_fail_closed_missing_policy() -> None:
    result = list_policy_tools("/nonexistent/policy.yaml")
    assert "error" in result
    assert "Policy load failed" in result["error"]
    assert result["version"] is None
    assert result["capability_digest"] is None
    assert result["capabilities"] == []
    assert result["agents"] == {}


def test_list_policy_tools_rate_limits() -> None:
    result = list_policy_tools("policy/demo-agent.policy.yaml")
    agent = result["agents"]["demo-agent"]
    assert agent["rate_limits"]["max_calls_per_trace"] is not None
    assert isinstance(agent["rate_limits"]["max_calls_per_tool"], dict)


def test_mcp_server_stdio_integration() -> None:
    """
    Integration test: start the MCP server over stdio and call tools via the SDK client.

    This test verifies that the server starts correctly, advertises tools, and responds
    to tool calls over stdio transport.
    """
    try:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
    except ImportError:
        pytest.skip("mcp client SDK not available")

    async def run_integration():
        server_params = StdioServerParameters(
            command="python3",
            args=["-m", "asc.mcp_server"],
        )

        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                tools_list = await session.list_tools()
                tool_names = [t.name for t in tools_list.tools]

                assert "check_tool_call" in tool_names
                assert "verify_corpus" in tool_names
                assert "verify_scenario" in tool_names
                assert "list_policy_tools" in tool_names

                call_result = await session.call_tool(
                    "list_policy_tools",
                    arguments={"policy_path": "policy/demo-agent.policy.yaml"},
                )

                assert call_result.content
                content_text = call_result.content[0].text
                result = json.loads(content_text)
                assert result["version"] == "1"
                assert "agents" in result

    import asyncio

    asyncio.run(run_integration())


def test_mcp_server_check_tool_call_integration() -> None:
    """
    Integration test: verify check_tool_call over stdio returns correct verdicts.
    """
    try:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
    except ImportError:
        pytest.skip("mcp client SDK not available")

    async def run_check():
        server_params = StdioServerParameters(
            command="python3",
            args=["-m", "asc.mcp_server"],
        )

        trace_allow = _trace(
            [
                {
                    "call_id": "c1",
                    "tool": "filesystem.read",
                    "args": {"path": "/workspace/README.md"},
                }
            ]
        )

        trace_block = _trace(
            [
                {
                    "call_id": "c2",
                    "tool": "filesystem.read",
                    "args": {"path": "/workspace/../etc/passwd"},
                }
            ]
        )

        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                result_allow = await session.call_tool(
                    "check_tool_call",
                    arguments={
                        "policy_path": "policy/demo-agent.policy.yaml",
                        "trace_data": trace_allow,
                    },
                )
                result_allow_data = json.loads(result_allow.content[0].text)
                assert result_allow_data["verdict"] == Verdict.ALLOW.value

                result_block = await session.call_tool(
                    "check_tool_call",
                    arguments={
                        "policy_path": "policy/demo-agent.policy.yaml",
                        "trace_data": trace_block,
                    },
                )
                result_block_data = json.loads(result_block.content[0].text)
                assert result_block_data["verdict"] == Verdict.BLOCK.value

    import asyncio

    asyncio.run(run_check())


def test_mcp_server_entrypoint_stdio() -> None:
    """Test that the asc-mcp console script starts and responds to list_tools."""
    result = subprocess.run(
        ["python3", "-m", "asc.mcp_server", "--help"],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 0
    assert "ASC MCP server" in result.stdout or "asc-mcp" in result.stdout


def test_mcp_server_main_function() -> None:
    """Test the main() function with various arguments."""
    from asc.mcp_server import main

    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])
    assert exc_info.value.code == 0
