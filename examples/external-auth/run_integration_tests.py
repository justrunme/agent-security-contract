#!/usr/bin/env python3
"""Integration tests through the real Envoy gateway (no mocked decisions).

Posts ASC evaluate payloads to /mcp/v1/tools/call. Envoy ext_authz calls the
adapter, which calls the real ASC sidecar. Verdicts and fail-closed behavior
are observed at the proxy edge. Writes evidence in the repo's results schema.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
EX = Path(__file__).resolve().parent
NS = "asc-external-auth"
BEARER = os.environ.get("ASC_DEMO_BEARER", "asc-demo")


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _post(
    url: str,
    payload: bytes | dict[str, Any],
    *,
    headers: dict[str, str] | None = None,
    timeout: float = 5.0,
) -> tuple[int, dict[str, Any] | None, dict[str, str]]:
    if isinstance(payload, dict):
        data = json.dumps(payload).encode("utf-8")
    else:
        data = payload
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, data=data, headers=req_headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            raw = resp.read()
            try:
                body = json.loads(raw.decode("utf-8")) if raw else None
            except json.JSONDecodeError:
                body = None
            return resp.status, body, {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            body = json.loads(raw.decode("utf-8")) if raw else None
        except json.JSONDecodeError:
            body = None
        return exc.code, body, {k.lower(): v for k, v in exc.headers.items()}
    except Exception as exc:  # noqa: BLE001
        return 0, {"verdict": "BLOCK", "reason": f"transport: {exc}"}, {}


def _kubectl(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    cmd = ["kubectl", "-n", NS, *args]
    return subprocess.run(cmd, check=check, text=True, capture_output=True)


def _wait_ready(deploy: str = "asc-gateway", timeout_s: int = 180) -> None:
    _kubectl("rollout", "status", f"deploy/{deploy}", f"--timeout={timeout_s}s")


def _rebind_port_forward() -> None:
    """Recreate kubectl port-forward after the gateway pod is replaced."""
    url = os.environ.get("ASC_EXTERNAL_AUTH_URL", "http://127.0.0.1:18080")
    port = url.rsplit(":", 1)[-1]
    if not port.isdigit():
        port = "18080"
    subprocess.run(
        ["pkill", "-f", f"kubectl -n {NS} port-forward .*asc-gateway"],
        check=False,
        capture_output=True,
    )
    time.sleep(0.5)
    log_path = Path("/tmp/asc-external-auth-pf.log")
    with log_path.open("w", encoding="utf-8") as logf:
        subprocess.Popen(  # noqa: S603
            [
                "kubectl",
                "-n",
                NS,
                "port-forward",
                "--address",
                "127.0.0.1",
                "deploy/asc-gateway",
                f"{port}:8080",
            ],
            stdout=logf,
            stderr=logf,
        )
    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            status, _body, _hdrs = _post(
                f"{url}/mcp/v1/tools/call",
                b"{}",
                headers={"Content-Type": "application/json"},
                timeout=1.0,
            )
            if status > 0:
                return
        except Exception:  # noqa: BLE001
            pass
        time.sleep(1)
    raise RuntimeError(f"port-forward to {url} did not become ready")


def _restart_gateway() -> None:
    _kubectl("rollout", "restart", "deploy/asc-gateway")
    _wait_ready()
    _rebind_port_forward()


def _gateway_url() -> str:
    url = os.environ.get("ASC_EXTERNAL_AUTH_URL", "").rstrip("/")
    if not url:
        raise SystemExit("ASC_EXTERNAL_AUTH_URL is required (run run-kind.sh first)")
    return url


def _verdict_from_response(
    status: int,
    body: dict[str, Any] | None,
    resp_headers: dict[str, str] | None = None,
) -> str:
    header_verdict = (resp_headers or {}).get("x-asc-verdict", "").upper()
    if header_verdict in {"ALLOW", "BLOCK", "REQUIRE_APPROVAL"}:
        return header_verdict
    if body and isinstance(body.get("verdict"), str) and body["verdict"] in {
        "ALLOW",
        "BLOCK",
        "REQUIRE_APPROVAL",
    }:
        return body["verdict"]
    if status == 200 and body and body.get("executed") is True:
        return "ALLOW"
    if status in {0, 401, 403, 503, 502, 504}:
        return "BLOCK"
    return "BLOCK"


def _corpus_payload(name: str, scenario_id: str) -> dict[str, Any]:
    scenario = _load_json(ROOT / "corpus" / "scenarios" / f"{name}.json")
    return {"scenario_id": scenario_id, "trace": scenario["trace"]}


def run_scenario(base: str, scenario: dict[str, Any]) -> dict[str, Any]:
    mode = scenario.get("mode", "evaluate")
    url = f"{base}/mcp/v1/tools/call"
    expected = scenario["expected"]
    scenario_id = scenario["scenario_id"]
    auth = {"Authorization": f"Bearer {BEARER}"}

    if mode == "malformed":
        status, body, hdrs = _post(url, b"{not-json", headers=auth)
        actual = _verdict_from_response(status, body, hdrs)
        executed = bool(body and body.get("executed") is True)
    elif mode == "no_credentials":
        payload = _corpus_payload(scenario["corpus_scenario"], scenario_id)
        status, body, hdrs = _post(url, payload, headers={})
        actual = _verdict_from_response(status, body, hdrs)
        executed = bool(body and body.get("executed") is True)
    elif mode == "authorizer_down":
        payload = _corpus_payload(scenario["corpus_scenario"], scenario_id)
        # Replace the ext_authz process with sleep so nothing listens on :9191.
        # Envoy failure_mode_allow=false must deny (fail closed).
        # containers[1] is asc-ext-authz in k8s/gateway.yaml.
        patch = json.dumps(
            [
                {
                    "op": "add",
                    "path": "/spec/template/spec/containers/1/command",
                    "value": ["sleep", "3600"],
                },
                {
                    "op": "replace",
                    "path": "/spec/template/spec/containers/1/readinessProbe",
                    "value": {
                        "exec": {"command": ["true"]},
                        "initialDelaySeconds": 1,
                        "periodSeconds": 2,
                    },
                },
            ]
        )
        _kubectl("patch", "deploy/asc-gateway", "--type=json", "-p", patch)
        _wait_ready()
        _rebind_port_forward()
        try:
            status, body, hdrs = _post(url, payload, headers=auth, timeout=3.0)
            actual = _verdict_from_response(status, body, hdrs)
            executed = bool(body and body.get("executed") is True)
        finally:
            # Replace (not strategic-merge apply) so readinessProbe handlers reset cleanly.
            subprocess.run(
                ["kubectl", "delete", "deploy", "asc-gateway", "-n", NS, "--wait=true"],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                ["kubectl", "apply", "-f", str(EX / "k8s" / "gateway.yaml")],
                check=True,
                capture_output=True,
                text=True,
            )
            _wait_ready()
            _rebind_port_forward()
    elif mode == "authorizer_timeout":
        payload = _corpus_payload(scenario["corpus_scenario"], scenario_id)
        _kubectl(
            "set",
            "env",
            "deploy/asc-gateway",
            "-c",
            "asc-ext-authz",
            "ASC_FORCE_SLEEP_S_TEST=3",
        )
        _wait_ready()
        _rebind_port_forward()
        try:
            status, body, hdrs = _post(url, payload, headers=auth, timeout=5.0)
            actual = _verdict_from_response(status, body, hdrs)
            executed = bool(body and body.get("executed") is True)
        finally:
            _kubectl(
                "set",
                "env",
                "deploy/asc-gateway",
                "-c",
                "asc-ext-authz",
                "ASC_FORCE_SLEEP_S_TEST=0",
            )
            _wait_ready()
            _rebind_port_forward()
    else:
        payload = _corpus_payload(scenario["corpus_scenario"], scenario_id)
        status, body, hdrs = _post(url, payload, headers=auth)
        if status == 200 and body and body.get("executed") is True:
            actual = "ALLOW"
            executed = True
        else:
            actual = _verdict_from_response(status, body, hdrs)
            executed = bool(body and body.get("executed") is True)

    expect_executed = bool(scenario.get("expect_executed", expected == "ALLOW"))
    match = actual == expected and executed == expect_executed
    reason = ""
    if isinstance(body, dict):
        reason = str(body.get("reason") or body.get("note") or "")

    # Envoy failure_mode_allow=false / status_on_error=Forbidden when the
    # authorizer is down or times out: client sees 403 without an ASC envelope.
    deny_source = None
    if mode in {"authorizer_down", "authorizer_timeout"}:
        deny_source = "envoy_ext_authz_failure_path"
        reason = (
            f"envoy ext_authz failure path ({mode.replace('authorizer_', '')}); "
            f"HTTP {status} (no ASC envelope)"
        )

    return {
        "scenario_id": scenario_id,
        "title": scenario.get("title", scenario_id),
        "owasp_risk": scenario["owasp_risk"],
        "acs_controls": scenario.get("acs_controls", []),
        "severity": scenario["severity"],
        "expected": expected,
        "actual": actual,
        "match": match,
        "reason": reason or f"http_status={status}",
        "blocked_call_id": (body or {}).get("blocked_call_id") if isinstance(body, dict) else None,
        "source": f"{scenario_id}.json",
        "http_status": status,
        "executed": executed,
        "deny_source": deny_source,
        "envelope": body if isinstance(body, dict) and "schema_version" in body else None,
    }


def build_report(rows: list[dict[str, Any]], suite_time_ms: int) -> dict[str, Any]:
    critical_false_allow = 0
    benign_total = 0
    benign_false_block = 0
    attack_total = 0
    allow_expected_total = 0
    all_match = True
    for row in rows:
        if not row["match"]:
            all_match = False
        expected = row["expected"]
        actual = row["actual"]
        severity = row["severity"]
        if severity in {"critical", "high"} and expected in {"BLOCK", "REQUIRE_APPROVAL"}:
            if actual == "ALLOW":
                critical_false_allow += 1
        if expected != "ALLOW":
            attack_total += 1
        else:
            allow_expected_total += 1
        if severity == "benign" and expected == "ALLOW":
            benign_total += 1
            if actual != "ALLOW":
                benign_false_block += 1
    benign_rate = (benign_false_block / benign_total) if benign_total else 0.0
    n = len(rows)
    commit_sha = (
        os.environ.get("ASC_COMMIT_SHA")
        or os.environ.get("GITHUB_SHA")
        or "unknown"
    )
    return {
        "passed": all_match and critical_false_allow == 0 and allow_expected_total >= attack_total,
        "policy": "policy/demo-agent.policy.yaml",
        "corpus": "examples/external-auth/scenarios",
        "commit_sha": commit_sha,
        "results_ref": "results/external-auth-results.json",
        "evidence_generator": "the external-auth integration runner",
        "envelope_note": (
            "ASC envelopes are recorded for BLOCK/REQUIRE_APPROVAL rows decided "
            "by ASC or the adapter."
        ),
        "suite_time_ms": suite_time_ms,
        "metrics": {
            "critical_false_allow": critical_false_allow,
            "benign_false_block": benign_false_block,
            "benign_total": benign_total,
            "benign_false_block_rate": benign_rate,
            "attack_scenario_count": attack_total,
            "allow_scenario_count": allow_expected_total,
            "scenario_count": n,
            "claims_scope": f"on this corpus of {n} scenarios",
        },
        "scenarios": rows,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--results",
        default=str(ROOT / "results" / "external-auth-results.json"),
    )
    parser.add_argument(
        "--evidence",
        default=str(ROOT / "docs" / "EVIDENCE-EXTERNAL-AUTH.md"),
    )
    parser.add_argument(
        "--summary",
        default=str(ROOT / "results" / "external-auth-summary.md"),
    )
    args = parser.parse_args(argv)

    # Import evidence writer from the installed / src package.
    sys.path.insert(0, str(ROOT / "src"))
    from asc.evidence import write_evidence  # noqa: WPS433

    base = _gateway_url()
    scenario_paths = sorted((EX / "scenarios").glob("*.json"))
    if not scenario_paths:
        raise SystemExit("no scenarios found")

    # Stable order: evaluate modes first, then disruptive fail-closed modes.
    order = {
        "evaluate": 0,
        "malformed": 1,
        "no_credentials": 2,
        "authorizer_timeout": 3,
        "authorizer_down": 4,
    }
    scenarios = [_load_json(p) for p in scenario_paths]
    scenarios.sort(key=lambda s: (order.get(s.get("mode", "evaluate"), 9), s["scenario_id"]))

    start = time.monotonic()
    rows = [run_scenario(base, s) for s in scenarios]
    suite_time_ms = int((time.monotonic() - start) * 1000)
    report = build_report(rows, suite_time_ms)

    results_path = Path(args.results)
    results_path.parent.mkdir(parents=True, exist_ok=True)
    results_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_evidence(report, Path(args.evidence))

    summary_lines = [
        "# External-auth integration summary",
        "",
        f"Scope: {report['metrics']['claims_scope']}",
        f"Passed: `{report['passed']}`",
        f"Critical false-ALLOW: `{report['metrics']['critical_false_allow']}`",
        f"Suite time (ms): `{report['suite_time_ms']}`",
        "",
        "| Scenario | Expected | Actual | HTTP | Executed | Match |",
        "|---|---|---|---:|---|---|",
    ]
    for row in rows:
        summary_lines.append(
            f"| `{row['scenario_id']}` | {row['expected']} | {row['actual']} | "
            f"{row['http_status']} | {row['executed']} | "
            f"{'yes' if row['match'] else 'NO'} |"
        )
    summary_lines.append("")
    Path(args.summary).write_text("\n".join(summary_lines), encoding="utf-8")

    print(json.dumps({"passed": report["passed"], "metrics": report["metrics"]}, indent=2))
    for row in rows:
        flag = "OK" if row["match"] else "FAIL"
        print(
            f"[{flag}] {row['scenario_id']}: expected={row['expected']} "
            f"actual={row['actual']} http={row['http_status']} executed={row['executed']}"
        )
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
