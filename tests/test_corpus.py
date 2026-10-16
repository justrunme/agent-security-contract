"""Corpus integrity and end-to-end run."""

from __future__ import annotations

from pathlib import Path

from asc.corpus import run_corpus
from asc.evidence import render_evidence


def test_corpus_has_expected_size() -> None:
    scenarios = list(Path("corpus/scenarios").glob("*.json"))
    assert 15 <= len(scenarios) <= 20


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
    }
    assert required.issubset(ids)


def test_corpus_run_zero_critical_false_allow(tmp_path: Path) -> None:
    report = run_corpus(
        corpus_dir=Path("corpus/scenarios"),
        policy_path=Path("policy/demo-agent.policy.yaml"),
        results_path=tmp_path / "results.json",
    )
    assert report["metrics"]["critical_false_allow"] == 0
    assert report["passed"] is True
    assert report["metrics"]["benign_total"] >= 3
    assert all(row["match"] for row in report["scenarios"])


def test_evidence_uses_results_numbers(tmp_path: Path) -> None:
    report = run_corpus(
        corpus_dir=Path("corpus/scenarios"),
        policy_path=Path("policy/demo-agent.policy.yaml"),
    )
    report["suite_time_ms"] = 42
    text = render_evidence(report)
    assert "`0`" in text  # critical false-allow
    assert "`42`" in text
    assert "benign_false_block_rate" not in text or "Benign false-BLOCK rate" in text
    # Ensure a scenario id from the run appears
    assert report["scenarios"][0]["scenario_id"] in text
