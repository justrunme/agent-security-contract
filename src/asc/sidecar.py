"""Minimal fail-closed HTTP sidecar for pre-execution ASC evaluation.

Intended as an integration example for ai-infra-control-plane / ai-runtime:
call POST /v1/evaluate before executing a tool. On handler errors or client
timeouts, callers MUST treat the result as BLOCK (fail-closed).
"""

from __future__ import annotations

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from asc.envelope import build_envelope
from asc.evaluator import evaluate_trace_data
from asc.models import Verdict
from asc.policy import load_policy
from asc.trace import TraceError, parse_trace


class AscSidecar(BaseHTTPRequestHandler):
    policy = None
    policy_path = ""

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write(f"{self.address_string()} - {fmt % args}\n")

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            raise ValueError("missing body")
        raw = self.rfile.read(length)
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("body must be a JSON object")
        return data

    def _write(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/healthz":
            self._write(200, {"status": "ok", "fail_closed": True})
            return
        self._write(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path != "/v1/evaluate":
            self._write(404, {"error": "not found"})
            return
        try:
            body = self._read_json()
            scenario_id = body.get("scenario_id", "runtime")
            if not isinstance(scenario_id, str) or not scenario_id:
                raise ValueError("scenario_id must be a non-empty string")
            trace_data = body.get("trace", body)
            result = evaluate_trace_data(self.policy, trace_data, scenario_id=scenario_id)
            try:
                trace = parse_trace(trace_data if "calls" in trace_data else body["trace"])
            except (TraceError, KeyError):
                trace = None
            envelope = build_envelope(
                result=result,
                policy=self.policy,
                policy_path=self.policy_path,
                trace=trace,
            )
            status = 200 if result.verdict == Verdict.ALLOW else 403
            if result.verdict == Verdict.REQUIRE_APPROVAL:
                status = 401
            self._write(status, envelope)
        except Exception as exc:  # fail-closed
            self._write(
                503,
                {
                    "schema_version": "1.0.0",
                    "verdict": Verdict.BLOCK.value,
                    "reason": f"sidecar fail-closed: {exc}",
                    "scenario_id": "runtime-error",
                    "acs_disposition": "DENY",
                },
            )


def serve(host: str, port: int, policy_path: str) -> None:
    AscSidecar.policy = load_policy(policy_path)
    AscSidecar.policy_path = policy_path
    server = ThreadingHTTPServer((host, port), AscSidecar)
    print(f"ASC sidecar listening on http://{host}:{port} (fail-closed)", flush=True)
    server.serve_forever()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ASC fail-closed evaluation sidecar")
    parser.add_argument("--policy", required=True, help="Path to policy YAML")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8788)
    args = parser.parse_args(argv)
    serve(args.host, args.port, args.policy)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
