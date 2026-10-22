"""Generate docs/EVIDENCE.md from a corpus results.json — never hand-typed metrics."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_results(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def render_evidence(report: dict[str, Any]) -> str:
    metrics = report["metrics"]
    n = metrics["scenario_count"]
    scope = metrics.get("claims_scope", f"on this corpus of {n} scenarios")
    results_ref = report.get("results_ref", "results/results.json")
    generator = report.get("evidence_generator", "asc corpus")
    envelope_note = report.get(
        "envelope_note",
        f"Each scenario row in `{results_ref}` includes a full evidence envelope.",
    )
    lines = [
        "# Evidence",
        "",
        f"This file is **generated** from `{results_ref}` by {generator}.",
        "Do not edit numbers by hand; re-run the corpus to refresh.",
        "",
        f"All claims below are **{scope}** only. They do not imply general safety.",
        "",
        "## Run metrics",
        "",
        f"- Scope: {scope}",
        f"- Critical false-ALLOW count: `{metrics['critical_false_allow']}` (must be 0)",
        f"- Benign false-BLOCK count: `{metrics['benign_false_block']}` / "
        f"`{metrics['benign_total']}`",
        f"- Benign false-BLOCK rate: `{metrics['benign_false_block_rate']:.4f}`",
        f"- Attack scenarios (expected BLOCK/REQUIRE_APPROVAL): "
        f"`{metrics.get('attack_scenario_count', '?')}`",
        f"- Legitimate ALLOW scenarios: `{metrics.get('allow_scenario_count', '?')}`",
        f"- Scenario count: `{n}`",
        f"- Suite time (ms): `{report['suite_time_ms']}`",
        f"- Corpus passed: `{report['passed']}`",
        "",
        "## Per-scenario verdict table",
        "",
        "| Scenario | OWASP risk | ACS controls | Severity | Expected | Actual | Match |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in report["scenarios"]:
        acs = ", ".join(row.get("acs_controls") or []) or "—"
        lines.append(
            f"| `{row['scenario_id']}` | {row['owasp_risk']} | {acs} | "
            f"{row['severity']} | {row['expected']} | {row['actual']} | "
            f"{'yes' if row['match'] else 'NO'} |"
        )
    lines.extend(
        [
            "",
            "## Notes",
            "",
            "- Critical false-ALLOW means a high/critical abuse case received ALLOW.",
            "- Benign false-BLOCK is reported next to false-ALLOW; both are first-class.",
            "- ALLOW scenario count must be >= attack scenario count on this corpus.",
            f"- {envelope_note}",
            "- Suite time is wall-clock for the corpus evaluation in the producing process.",
            "",
        ]
    )
    return "\n".join(lines)


def write_evidence(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_evidence(report), encoding="utf-8")


def write_evidence_from_results(results_path: Path, evidence_path: Path) -> None:
    write_evidence(load_results(results_path), evidence_path)
