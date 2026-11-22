"""MCP server exposing ASC policy engine as tools."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from asc.corpus import run_corpus
from asc.evaluator import evaluate_trace_data
from asc.models import Verdict
from asc.policy import PolicyError, load_policy

mcp = FastMCP("agent-security-contract")

_policy_cache: dict[str, Any] = {}


def _load_policy_safe(policy_path: str) -> dict[str, Any]:
    """Load policy with fail-closed error handling."""
    try:
        policy = load_policy(policy_path)
        return {"success": True, "policy": policy, "error": None}
    except PolicyError as exc:
        return {"success": False, "policy": None, "error": f"Policy load failed: {exc}"}
    except Exception as exc:
        return {"success": False, "policy": None, "error": f"Unexpected error: {exc}"}


@mcp.tool()
def check_tool_call(
    policy_path: str,
    trace_data: dict[str, Any],
    scenario_id: str = "mcp-check",
) -> dict[str, Any]:
    """
    Check a proposed tool call against an ASC policy contract.

    Returns PASS/BLOCK/REQUIRE_APPROVAL verdict with reasons. Fail-closed: any error,
    missing policy, or unknown input yields BLOCK. Use this tool before executing
    any tool call to enforce a security contract.

    Args:
        policy_path: Path to the ASC policy YAML file
        trace_data: Tool call trace mapping with agent_id, trace_id, calls, optional tool_catalog
        scenario_id: Identifier for this check (for reporting)

    Returns:
        Mapping with verdict, reason, scenario_id, blocked_call_id, and details
    """
    policy_result = _load_policy_safe(policy_path)
    if not policy_result["success"]:
        return {
            "verdict": Verdict.BLOCK.value,
            "reason": policy_result["error"],
            "scenario_id": scenario_id,
            "blocked_call_id": None,
            "details": {"policy_load_error": True},
        }

    policy = policy_result["policy"]
    try:
        result = evaluate_trace_data(policy, trace_data, scenario_id=scenario_id)
        return {
            "verdict": result.verdict.value,
            "reason": result.reason,
            "scenario_id": result.scenario_id,
            "blocked_call_id": result.blocked_call_id,
            "details": result.details,
        }
    except Exception as exc:
        return {
            "verdict": Verdict.BLOCK.value,
            "reason": f"Evaluation error (fail-closed): {type(exc).__name__}: {exc}",
            "scenario_id": scenario_id,
            "blocked_call_id": None,
            "details": {"evaluation_error": True},
        }


@mcp.tool()
def verify_corpus(
    policy_path: str,
    corpus_dir: str,
    output_results: bool = False,
) -> dict[str, Any]:
    """
    Verify/run the abuse-case corpus against an ASC policy.

    Runs all scenario JSON files in the corpus directory and returns metrics including
    critical false-ALLOW count, benign false-BLOCK rate, and per-scenario results.

    Args:
        policy_path: Path to the ASC policy YAML file
        corpus_dir: Directory containing scenario JSON files
        output_results: If True, return full per-scenario results (may be large)

    Returns:
        Mapping with passed (bool), metrics, and optionally scenarios list
    """
    corpus_path = Path(corpus_dir)
    if not corpus_path.is_dir():
        return {
            "passed": False,
            "error": f"Corpus directory not found: {corpus_dir}",
            "metrics": {},
        }

    policy_result = _load_policy_safe(policy_path)
    if not policy_result["success"]:
        return {
            "passed": False,
            "error": policy_result["error"],
            "metrics": {},
        }

    try:
        report = run_corpus(
            corpus_dir=corpus_path,
            policy_path=Path(policy_path),
            results_path=None,
        )

        result: dict[str, Any] = {
            "passed": report["passed"],
            "metrics": report["metrics"],
            "policy": str(policy_path),
            "corpus": str(corpus_dir),
        }

        if output_results:
            result["scenarios"] = [
                {
                    "scenario_id": s["scenario_id"],
                    "title": s["title"],
                    "severity": s["severity"],
                    "expected": s["expected"],
                    "actual": s["actual"],
                    "match": s["match"],
                    "reason": s["reason"],
                    "owasp_risk": s["owasp_risk"],
                    "acs_controls": s["acs_controls"],
                }
                for s in report["scenarios"]
            ]

        return result
    except Exception as exc:
        return {
            "passed": False,
            "error": f"Corpus verification failed: {type(exc).__name__}: {exc}",
            "metrics": {},
        }


@mcp.tool()
def verify_scenario(
    policy_path: str,
    scenario_path: str,
) -> dict[str, Any]:
    """
    Verify a single corpus scenario file against an ASC policy.

    Loads the scenario JSON, runs the trace through the policy evaluator, and returns
    whether the actual verdict matches the expected verdict.

    Args:
        policy_path: Path to the ASC policy YAML file
        scenario_path: Path to a single scenario JSON file

    Returns:
        Mapping with match (bool), expected, actual, reason, and scenario metadata
    """
    scenario_file = Path(scenario_path)
    if not scenario_file.is_file():
        return {
            "match": False,
            "error": f"Scenario file not found: {scenario_path}",
        }

    policy_result = _load_policy_safe(policy_path)
    if not policy_result["success"]:
        return {
            "match": False,
            "error": policy_result["error"],
        }

    try:
        scenario = json.loads(scenario_file.read_text(encoding="utf-8"))
        if not isinstance(scenario, dict):
            return {"match": False, "error": "Scenario must be a JSON object"}

        for key in ("scenario_id", "expected", "trace"):
            if key not in scenario:
                return {"match": False, "error": f"Scenario missing required field: {key}"}

        policy = policy_result["policy"]
        result = evaluate_trace_data(
            policy,
            scenario["trace"],
            scenario_id=scenario["scenario_id"],
        )

        actual = result.verdict.value
        expected = scenario["expected"]
        match = actual == expected

        return {
            "match": match,
            "scenario_id": scenario["scenario_id"],
            "title": scenario.get("title", ""),
            "severity": scenario.get("severity", ""),
            "expected": expected,
            "actual": actual,
            "reason": result.reason,
            "owasp_risk": scenario.get("owasp_risk", ""),
            "acs_controls": scenario.get("acs_controls", []),
        }
    except Exception as exc:
        return {
            "match": False,
            "error": f"Scenario verification failed: {type(exc).__name__}: {exc}",
        }


@mcp.tool()
def list_policy_tools(policy_path: str) -> dict[str, Any]:
    """
    List loaded policies and their configured tools/rules.

    Returns the capability catalog, capability digest, and per-agent tool allowlists
    from an ASC policy file.

    Args:
        policy_path: Path to the ASC policy YAML file

    Returns:
        Mapping with version, capability_digest, capabilities, and agents configuration
    """
    policy_result = _load_policy_safe(policy_path)
    if not policy_result["success"]:
        return {
            "error": policy_result["error"],
            "version": None,
            "capability_digest": None,
            "capabilities": [],
            "agents": {},
        }

    policy = policy_result["policy"]
    return {
        "version": policy.version,
        "capability_digest": policy.capability_digest,
        "capabilities": [
            {
                "name": cap.name,
                "description": cap.description,
                "input_schema": cap.input_schema,
            }
            for cap in policy.capabilities
        ],
        "agents": {
            agent_id: {
                "allowed_tools": list(agent.allowed_tools.keys()),
                "high_impact_tools": list(agent.high_impact_tools),
                "rate_limits": {
                    "max_calls_per_trace": agent.rate_limits.max_calls_per_trace,
                    "max_calls_per_tool": agent.rate_limits.max_calls_per_tool,
                },
            }
            for agent_id, agent in policy.agents.items()
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="asc-mcp",
        description="ASC MCP server — exposes the policy engine as MCP tools",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "streamable-http"],
        default="stdio",
        help="Transport type (default: stdio)",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host for streamable-http transport (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8765,
        help="Port for streamable-http transport (default: 8765)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point for the asc-mcp console script."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.transport == "stdio":
        mcp.run()
    elif args.transport == "streamable-http":
        mcp.run(transport="streamable-http", host=args.host, port=args.port)
    else:
        print(f"Unknown transport: {args.transport}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
