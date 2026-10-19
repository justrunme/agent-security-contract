"""Corpus integrity and end-to-end run."""

from __future__ import annotations

from pathlib import Path

from asc.corpus import run_corpus
from asc.evidence import render_evidence


def test_corpus_has_expected_size() -> None:
    scenarios = list(Path("corpus/scenarios").glob("*.json"))
    assert len(scenarios) >= 15
    assert len(scenarios) == 58


def test_allow_scenarios_at_least_attack_scenarios() -> None:
    import json

    scenarios = [
        json.loads(p.read_text(encoding="utf-8"))
        for p in Path("corpus/scenarios").glob("*.json")
    ]
    allow = sum(1 for s in scenarios if s["expected"] == "ALLOW")
    attack = sum(1 for s in scenarios if s["expected"] != "ALLOW")
    assert allow >= attack
    assert allow == 29
    assert attack == 29


def test_corpus_covers_required_themes() -> None:
    ids = {p.stem for p in Path("corpus/scenarios").glob("*.json")}
    required = {
        "tool_misuse_secrets_read",
        "goal_hijack_injected_tool_output",
        "unapproved_high_impact_delete",
        "unapproved_prod_deploy",
        "mcp_tool_poisoning_digest_mismatch",
        "privilege_escalation_path_traversal",
        "privilege_escalation_shell_metachar",
        "data_exfil_non_allowlisted_host",
        "excessive_call_rate",
        "benign_read_workspace_file",
        "benign_http_allowlisted",
        "benign_multi_step_research",
        # Policy-bypass regressions (v0.2.0)
        "shell_exec_aws_credentials",
        "shell_exec_etc_shadow",
        "shell_exec_proc_environ",
        "path_traversal_workspace_parent",
        "path_traversal_url_encoded",
        "path_traversal_double_encoded",
        "path_traversal_slash_slash",
        "path_traversal_mixed_case",
        "path_traversal_relative",
        "approved_delete_parent_escape",
        "undeclared_extra_argument",
        "shell_exec_shadow_mixed_case",
    }
    assert required.issubset(ids)


def test_scenarios_map_acs_controls() -> None:
    import json

    for path in Path("corpus/scenarios").glob("*.json"):
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data.get("acs_controls"), f"{path.name} missing acs_controls"
        assert any(
            c.startswith("Instrument.")
            or c.startswith("protocols.")
            or c.startswith("Inspect.")
            for c in data["acs_controls"]
        )


def test_corpus_run_zero_critical_false_allow(tmp_path: Path) -> None:
    report = run_corpus(
        corpus_dir=Path("corpus/scenarios"),
        policy_path=Path("policy/demo-agent.policy.yaml"),
        results_path=tmp_path / "results.json",
    )
    assert report["metrics"]["critical_false_allow"] == 0
    assert report["metrics"]["benign_false_block"] == 0
    assert report["metrics"]["allow_scenario_count"] >= report["metrics"]["attack_scenario_count"]
    assert report["passed"] is True
    assert all(row["match"] for row in report["scenarios"])
    assert "envelope" in report["scenarios"][0]
    assert report["scenarios"][0]["envelope"]["schema_version"] == "1.0.0"


def test_evidence_uses_results_numbers(tmp_path: Path) -> None:
    report = run_corpus(
        corpus_dir=Path("corpus/scenarios"),
        policy_path=Path("policy/demo-agent.policy.yaml"),
    )
    report["suite_time_ms"] = 42
    text = render_evidence(report)
    assert "`0`" in text  # critical false-allow
    assert "`42`" in text
    assert f"on this corpus of {len(report['scenarios'])} scenarios" in text
    assert "Benign false-BLOCK" in text
    assert report["scenarios"][0]["scenario_id"] in text
