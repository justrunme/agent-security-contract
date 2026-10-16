"""Abuse-case corpus runner."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from asc.evaluator import evaluate_trace_data
from asc.models import Verdict
from asc.policy import load_policy

CRITICAL_SEVERITIES = frozenset({"critical", "high"})


def _load_scenario(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"scenario must be an object: {path}")
    for key in ("scenario_id", "expected", "severity", "trace", "owasp_risk"):
        if key not in data:
            raise ValueError(f"scenario {path} missing required field: {key}")
    return data


def run_corpus(
    *,
    corpus_dir: Path,
    policy_path: Path,
    results_path: Path | None = None,
) -> dict[str, Any]:
    """Evaluate every scenario JSON under corpus_dir and compute metrics."""
    policy = load_policy(policy_path)
    scenario_paths = sorted(corpus_dir.glob("*.json"))
    if not scenario_paths:
        raise FileNotFoundError(f"no scenario JSON files in {corpus_dir}")

    rows: list[dict[str, Any]] = []
    critical_false_allow = 0
    benign_total = 0
    benign_false_block = 0
    all_match = True

    for path in scenario_paths:
        scenario = _load_scenario(path)
        scenario_id = scenario["scenario_id"]
        expected = scenario["expected"]
        severity = scenario["severity"]
        result = evaluate_trace_data(policy, scenario["trace"], scenario_id=scenario_id)
        actual = result.verdict.value
        match = actual == expected
        if not match:
            all_match = False

        if severity in CRITICAL_SEVERITIES and expected in {
            Verdict.BLOCK.value,
            Verdict.REQUIRE_APPROVAL.value,
        }:
            if actual == Verdict.ALLOW.value:
                critical_false_allow += 1

        if severity == "benign" and expected == Verdict.ALLOW.value:
            benign_total += 1
            if actual != Verdict.ALLOW.value:
                benign_false_block += 1

        rows.append(
            {
                "scenario_id": scenario_id,
                "title": scenario.get("title", scenario_id),
                "owasp_risk": scenario["owasp_risk"],
                "severity": severity,
                "expected": expected,
                "actual": actual,
                "match": match,
                "reason": result.reason,
                "blocked_call_id": result.blocked_call_id,
                "source": path.name,
            }
        )

    benign_rate = (benign_false_block / benign_total) if benign_total else 0.0
    report: dict[str, Any] = {
        "passed": all_match and critical_false_allow == 0,
        "policy": str(policy_path),
        "corpus": str(corpus_dir),
        "suite_time_ms": 0,
        "metrics": {
            "critical_false_allow": critical_false_allow,
            "benign_false_block": benign_false_block,
            "benign_total": benign_total,
            "benign_false_block_rate": benign_rate,
            "scenario_count": len(rows),
        },
        "scenarios": rows,
    }
    if results_path is not None:
        results_path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
        results_path.write_text(payload, encoding="utf-8")
    return report
