"""Generate docs/EVIDENCE.md from a corpus results.json — never hand-typed metrics."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_results(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def render_evidence(report: dict[str, Any]) -> str:
    metrics = report["metrics"]
    lines = [
        "# Evidence",
        "",
        "This file is **generated** from `results/results.json` by `asc corpus`.",
        "Do not edit numbers by hand; re-run the corpus to refresh.",
        "",
        "## Run metrics",
        "",
        f"- Critical false-ALLOW count: `{metrics['critical_false_allow']}` (must be 0)",
        f"- Benign false-BLOCK count: `{metrics['benign_false_block']}` / "
        f"`{metrics['benign_total']}`",
        f"- Benign false-BLOCK rate: `{metrics['benign_false_block_rate']:.4f}`",
        f"- Scenario count: `{metrics['scenario_count']}`",
        f"- Suite time (ms): `{report['suite_time_ms']}`",
        f"- Corpus passed: `{report['passed']}`",
        "",
        "## Per-scenario verdict table",
        "",
        "| Scenario | OWASP risk | Severity | Expected | Actual | Match |",
        "|---|---|---|---|---|---|",
    ]
    for row in report["scenarios"]:
        lines.append(
            f"| `{row['scenario_id']}` | {row['owasp_risk']} | {row['severity']} | "
            f"{row['expected']} | {row['actual']} | {'yes' if row['match'] else 'NO'} |"
        )
    lines.extend(
        [
            "",
            "## Notes",
            "",
            "- Critical false-ALLOW means a high/critical abuse case received ALLOW.",
            "- Benign false-BLOCK rate uses severity=`benign` cases that expect ALLOW.",
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
