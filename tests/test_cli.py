"""CLI exit-code and output tests."""

from __future__ import annotations

import json
from pathlib import Path

from asc.cli import EXIT_ALLOW, EXIT_BLOCK, EXIT_REQUIRE_APPROVAL, main


def test_cli_check_allow(tmp_path: Path) -> None:
    from asc.policy import load_policy

    policy = load_policy("policy/demo-agent.policy.yaml")
    catalog = [
        {"name": t.name, "description": t.description, "input_schema": t.input_schema}
        for t in policy.capabilities
    ]
    trace = {
        "agent_id": "demo-agent",
        "trace_id": "cli",
        "tool_catalog": catalog,
        "calls": [
            {"call_id": "c1", "tool": "filesystem.read", "args": {"path": "/workspace/README.md"}}
        ],
    }
    path = tmp_path / "trace.json"
    path.write_text(json.dumps(trace), encoding="utf-8")
    env_out = tmp_path / "envelope.json"
    code = main(
        [
            "check",
            "--policy",
            "policy/demo-agent.policy.yaml",
            "--trace",
            str(path),
            "--json",
            "--envelope-out",
            str(env_out),
        ]
    )
    assert code == EXIT_ALLOW
    envelope = json.loads(env_out.read_text(encoding="utf-8"))
    assert envelope["schema_version"] == "1.0.0"
    assert envelope["verdict"] == "ALLOW"
    assert envelope["trace_id"] == "cli"
    verify_code = main(
        ["verify", "--envelope", str(env_out), "--policy", "policy/demo-agent.policy.yaml"]
    )
    assert verify_code == 0


def test_cli_check_block_unknown_tool(tmp_path: Path) -> None:
    from asc.policy import load_policy

    policy = load_policy("policy/demo-agent.policy.yaml")
    catalog = [
        {"name": t.name, "description": t.description, "input_schema": t.input_schema}
        for t in policy.capabilities
    ]
    trace = {
        "agent_id": "demo-agent",
        "trace_id": "cli-block",
        "tool_catalog": catalog,
        "calls": [{"call_id": "c1", "tool": "nope.tool", "args": {}}],
    }
    path = tmp_path / "trace.json"
    path.write_text(json.dumps(trace), encoding="utf-8")
    code = main(
        ["check", "--policy", "policy/demo-agent.policy.yaml", "--trace", str(path), "--json"]
    )
    assert code == EXIT_BLOCK


def test_cli_check_require_approval(tmp_path: Path) -> None:
    from asc.policy import load_policy

    policy = load_policy("policy/demo-agent.policy.yaml")
    catalog = [
        {"name": t.name, "description": t.description, "input_schema": t.input_schema}
        for t in policy.capabilities
    ]
    trace = {
        "agent_id": "demo-agent",
        "trace_id": "cli-approval",
        "tool_catalog": catalog,
        "calls": [
            {
                "call_id": "c1",
                "tool": "filesystem.delete",
                "args": {"path": "/workspace/out/x.txt"},
                "approved": False,
            }
        ],
    }
    path = tmp_path / "trace.json"
    path.write_text(json.dumps(trace), encoding="utf-8")
    code = main(
        ["check", "--policy", "policy/demo-agent.policy.yaml", "--trace", str(path), "--json"]
    )
    assert code == EXIT_REQUIRE_APPROVAL


def test_cli_corpus(tmp_path: Path) -> None:
    results = tmp_path / "results.json"
    summary = tmp_path / "summary.md"
    evidence = tmp_path / "EVIDENCE.md"
    code = main(
        [
            "corpus",
            "--policy",
            "policy/demo-agent.policy.yaml",
            "--corpus",
            "corpus/scenarios",
            "--results",
            str(results),
            "--summary",
            str(summary),
            "--evidence",
            str(evidence),
        ]
    )
    assert code == 0
    report = json.loads(results.read_text(encoding="utf-8"))
    assert report["metrics"]["critical_false_allow"] == 0
    assert evidence.is_file()
    assert summary.is_file()


def test_main_module_import_has_no_cli_side_effects() -> None:
    """Collectors may import asc.__main__; that must not call the CLI."""
    import importlib
    import sys

    sys.modules.pop("asc.__main__", None)
    mod = importlib.import_module("asc.__main__")
    assert callable(mod.main)
