"""CLI entrypoint: `asc check`, `asc verify`, corpus/evidence helpers."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

from asc import __version__
from asc.corpus import run_corpus
from asc.envelope import EnvelopeError, load_and_verify_envelope, verify_envelope
from asc.evaluator import evaluate_paths_envelope
from asc.evidence import write_evidence
from asc.models import Verdict

EXIT_ALLOW = 0
EXIT_REQUIRE_APPROVAL = 2
EXIT_BLOCK = 1
EXIT_USAGE = 64


def _print_result(result: dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return
    print(f"verdict: {result['verdict']}")
    print(f"scenario_id: {result['scenario_id']}")
    print(f"reason: {result['reason']}")
    print(f"trace_id: {result.get('trace_id', '')}")
    print(f"policy_sha256: {result.get('policy_sha256', '')}")
    if result.get("blocked_call_id"):
        print(f"blocked_call_id: {result['blocked_call_id']}")


def cmd_check(args: argparse.Namespace) -> int:
    result, envelope = evaluate_paths_envelope(
        args.policy,
        args.trace,
        scenario_id=args.scenario_id,
    )
    if args.envelope_out:
        Path(args.envelope_out).write_text(
            json.dumps(envelope, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    _print_result(envelope, args.json)
    if result.verdict == Verdict.ALLOW:
        return EXIT_ALLOW
    if result.verdict == Verdict.REQUIRE_APPROVAL:
        return EXIT_REQUIRE_APPROVAL
    return EXIT_BLOCK


def cmd_verify(args: argparse.Namespace) -> int:
    try:
        if args.envelope:
            envelope = load_and_verify_envelope(args.envelope, policy_path=args.policy or None)
        else:
            raw = json.load(sys.stdin)
            expected = None
            if args.policy:
                from asc.envelope import policy_sha256_file

                expected = policy_sha256_file(args.policy)
            envelope = verify_envelope(raw, expected_policy_sha256=expected)
    except EnvelopeError as exc:
        print(f"VERIFY_REJECT: {exc}", file=sys.stderr)
        return EXIT_BLOCK
    print(json.dumps({"status": "ok", "envelope": envelope}, indent=2, sort_keys=True))
    return EXIT_ALLOW


def cmd_corpus(args: argparse.Namespace) -> int:
    started = time.perf_counter()
    report = run_corpus(
        corpus_dir=Path(args.corpus),
        policy_path=Path(args.policy),
        results_path=Path(args.results),
    )
    elapsed_ms = int((time.perf_counter() - started) * 1000)
    report["suite_time_ms"] = elapsed_ms
    results_path = Path(args.results)
    results_path.parent.mkdir(parents=True, exist_ok=True)
    results_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary_path = Path(args.summary) if args.summary else results_path.with_suffix(".md")
    summary_path.write_text(_corpus_markdown(report), encoding="utf-8")

    if args.evidence:
        write_evidence(report, Path(args.evidence))

    print(f"wrote {results_path}")
    print(f"wrote {summary_path}")
    if args.evidence:
        print(f"wrote {args.evidence}")
    n = report["metrics"]["scenario_count"]
    print(
        f"on this corpus of {n} scenarios: "
        f"critical_false_allow={report['metrics']['critical_false_allow']} "
        f"benign_false_block={report['metrics']['benign_false_block']}/"
        f"{report['metrics']['benign_total']} "
        f"benign_false_block_rate={report['metrics']['benign_false_block_rate']:.4f} "
        f"suite_time_ms={elapsed_ms}"
    )
    return 0 if report["metrics"]["critical_false_allow"] == 0 and report["passed"] else EXIT_BLOCK


def _corpus_markdown(report: dict[str, Any]) -> str:
    metrics = report["metrics"]
    n = metrics["scenario_count"]
    lines = [
        "# ASC Corpus Results",
        "",
        f"Claims scope: **on this corpus of {n} scenarios** (not general safety).",
        "",
        f"- Suite time (ms): `{report['suite_time_ms']}`",
        f"- Critical false-ALLOW: `{metrics['critical_false_allow']}`",
        f"- Benign false-BLOCK: `{metrics['benign_false_block']}` / `{metrics['benign_total']}`",
        f"- Benign false-BLOCK rate: `{metrics['benign_false_block_rate']:.4f}`",
        f"- Attack scenarios: `{metrics.get('attack_scenario_count')}`",
        f"- ALLOW scenarios: `{metrics.get('allow_scenario_count')}`",
        f"- Scenarios: `{n}`",
        "",
        "| Scenario | Severity | Expected | Actual | Match | ACS | Reason |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in report["scenarios"]:
        acs = ", ".join(row.get("acs_controls") or []) or "—"
        lines.append(
            f"| `{row['scenario_id']}` | {row['severity']} | {row['expected']} | "
            f"{row['actual']} | {'yes' if row['match'] else 'NO'} | {acs} | {row['reason']} |"
        )
    lines.append("")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="asc",
        description="Agent Security Contract — fail-closed gate for AI agent tool calls",
    )
    parser.add_argument("--version", action="version", version=f"asc {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="Evaluate one tool-call trace against a policy")
    check.add_argument("--policy", required=True, help="Path to policy YAML")
    check.add_argument("--trace", required=True, help="Path to tool-call trace JSON")
    check.add_argument("--scenario-id", default="adhoc", help="Scenario id for reporting")
    check.add_argument("--json", action="store_true", help="Emit evidence envelope JSON")
    check.add_argument(
        "--envelope-out",
        default="",
        help="Optional path to write the evidence envelope JSON",
    )
    check.set_defaults(func=cmd_check)

    verify = sub.add_parser(
        "verify",
        help="Verify an evidence envelope (reject invalid/tampered envelopes)",
    )
    verify.add_argument(
        "--envelope",
        default="",
        help="Path to envelope JSON (default: stdin)",
    )
    verify.add_argument(
        "--policy",
        default="",
        help="Optional policy path; when set, policy_sha256 must match the file digest",
    )
    verify.set_defaults(func=cmd_verify)

    corpus = sub.add_parser("corpus", help="Run the abuse-case corpus and emit results")
    corpus.add_argument("--policy", required=True, help="Path to policy YAML")
    corpus.add_argument("--corpus", required=True, help="Directory of scenario JSON files")
    corpus.add_argument(
        "--results",
        default="results/results.json",
        help="Output path for results JSON",
    )
    corpus.add_argument(
        "--summary",
        default="results/summary.md",
        help="Output path for markdown summary",
    )
    corpus.add_argument(
        "--evidence",
        default="",
        help="Optional path to write docs/EVIDENCE.md from the run",
    )
    corpus.set_defaults(func=cmd_corpus)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except BrokenPipeError:
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
