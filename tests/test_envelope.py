"""Evidence envelope construction and asc verify negative tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from asc.cli import EXIT_ALLOW, EXIT_BLOCK, main
from asc.envelope import (
    SCHEMA_VERSION,
    EnvelopeError,
    build_envelope,
    policy_sha256_file,
    verify_envelope,
)
from asc.evaluator import evaluate_paths_envelope
from asc.models import EvaluationResult, Verdict
from asc.policy import load_policy
from asc.trace import load_trace


def test_check_emits_required_envelope_fields(tmp_path: Path) -> None:
    result, envelope = evaluate_paths_envelope(
        "policy/demo-agent.policy.yaml",
        "corpus/scenarios/benign_read_workspace_file.json",
        scenario_id="benign_read_workspace_file",
    )
    assert result.verdict == Verdict.ALLOW
    for key in (
        "schema_version",
        "policy_version",
        "policy_sha256",
        "scenario_id",
        "verdict",
        "reason",
        "trace_id",
        "commit_sha",
        "timestamp",
    ):
        assert key in envelope
    assert envelope["schema_version"] == SCHEMA_VERSION
    assert envelope["policy_sha256"] == policy_sha256_file("policy/demo-agent.policy.yaml")
    assert envelope["acs_disposition"] == "ALLOW"
    out = tmp_path / "env.json"
    out.write_text(json.dumps(envelope), encoding="utf-8")
    code = main(
        ["verify", "--envelope", str(out), "--policy", "policy/demo-agent.policy.yaml"]
    )
    assert code == EXIT_ALLOW


def test_verify_rejects_missing_field(tmp_path: Path) -> None:
    _, envelope = evaluate_paths_envelope(
        "policy/demo-agent.policy.yaml",
        "corpus/scenarios/benign_read_workspace_file.json",
    )
    del envelope["timestamp"]
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(envelope), encoding="utf-8")
    assert main(["verify", "--envelope", str(path)]) == EXIT_BLOCK


def test_verify_rejects_tampered_verdict_disposition(tmp_path: Path) -> None:
    _, envelope = evaluate_paths_envelope(
        "policy/demo-agent.policy.yaml",
        "corpus/scenarios/benign_read_workspace_file.json",
    )
    envelope["verdict"] = "BLOCK"
    # disposition still ALLOW -> tamper
    path = tmp_path / "tamper.json"
    path.write_text(json.dumps(envelope), encoding="utf-8")
    assert main(["verify", "--envelope", str(path)]) == EXIT_BLOCK


def test_verify_rejects_tampered_policy_sha(tmp_path: Path) -> None:
    _, envelope = evaluate_paths_envelope(
        "policy/demo-agent.policy.yaml",
        "corpus/scenarios/benign_read_workspace_file.json",
    )
    envelope["policy_sha256"] = "sha256:" + ("ab" * 32)
    path = tmp_path / "tamper-sha.json"
    path.write_text(json.dumps(envelope), encoding="utf-8")
    code = main(
        ["verify", "--envelope", str(path), "--policy", "policy/demo-agent.policy.yaml"]
    )
    assert code == EXIT_BLOCK


def test_verify_rejects_invalid_schema_version() -> None:
    with pytest.raises(EnvelopeError, match="schema_version"):
        verify_envelope(
            {
                "schema_version": "9.9.9",
                "policy_version": "1",
                "policy_sha256": "sha256:" + ("11" * 32),
                "scenario_id": "x",
                "verdict": "ALLOW",
                "reason": "ok",
                "trace_id": "t",
                "commit_sha": "deadbeef",
                "timestamp": "2026-10-16T00:00:00Z",
            }
        )


def test_build_envelope_uses_trace_id() -> None:
    policy = load_policy("policy/demo-agent.policy.yaml")
    trace = load_trace("corpus/scenarios/benign_list_directory.json")
    result = EvaluationResult(
        verdict=Verdict.ALLOW,
        reason="ok",
        scenario_id="benign_list_directory",
    )
    envelope = build_envelope(
        result=result,
        policy=policy,
        policy_path="policy/demo-agent.policy.yaml",
        trace=trace,
        commit_sha="abc123",
        timestamp="2026-10-16T07:00:00Z",
    )
    assert envelope["trace_id"] == "t-benign-list"
    assert envelope["commit_sha"] == "abc123"


def test_resolve_commit_sha_prefers_asc_over_github(monkeypatch) -> None:
    from asc.envelope import resolve_commit_sha

    monkeypatch.setenv("GITHUB_SHA", "merge-ref-sha")
    monkeypatch.setenv("ASC_COMMIT_SHA", "real-head-sha")
    assert resolve_commit_sha() == "real-head-sha"
    monkeypatch.delenv("ASC_COMMIT_SHA")
    assert resolve_commit_sha() == "merge-ref-sha"


def test_verify_rejects_consistent_verdict_flip(tmp_path: Path) -> None:
    """BLOCK -> ALLOW with a matching disposition is still caught by envelope_sha256."""
    _, envelope = evaluate_paths_envelope(
        "policy/demo-agent.policy.yaml",
        "corpus/scenarios/unknown_tool_call.json",
    )
    assert envelope["verdict"] == "BLOCK"
    envelope["verdict"] = "ALLOW"
    envelope["acs_disposition"] = "ALLOW"
    path = tmp_path / "flip.json"
    path.write_text(json.dumps(envelope), encoding="utf-8")
    assert main(["verify", "--envelope", str(path)]) == EXIT_BLOCK
    with pytest.raises(EnvelopeError, match="tampered envelope"):
        verify_envelope(envelope)


def test_verify_accepts_untampered_and_rejects_missing_digest(tmp_path: Path) -> None:
    _, envelope = evaluate_paths_envelope(
        "policy/demo-agent.policy.yaml",
        "corpus/scenarios/benign_read_workspace_file.json",
    )
    path = tmp_path / "ok.json"
    path.write_text(json.dumps(envelope), encoding="utf-8")
    policy = "policy/demo-agent.policy.yaml"
    assert main(["verify", "--envelope", str(path), "--policy", policy]) == 0
    del envelope["envelope_sha256"]
    with pytest.raises(EnvelopeError, match="envelope_sha256"):
        verify_envelope(envelope)
