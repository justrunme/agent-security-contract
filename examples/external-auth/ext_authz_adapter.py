#!/usr/bin/env python3
"""Envoy HTTP ext_authz adapter that calls the real ASC decision API.

This process does not evaluate policy itself. Every allow/block/ask decision
comes from ASC POST /v1/evaluate (the same sidecar used in docs/INTEGRATION.md).
On ASC unreachable, timeout, malformed upstream response, or missing client
credentials, this adapter fails closed (non-2xx) so Envoy denies the call.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

ASC_EVALUATE_URL = os.environ.get(
    "ASC_EVALUATE_URL", "http://127.0.0.1:8788/v1/evaluate"
)
ASC_TIMEOUT_S = float(os.environ.get("ASC_TIMEOUT_S", "0.5"))
# Demo credential checked at the gateway edge before calling ASC.
REQUIRED_BEARER = os.environ.get("ASC_DEMO_BEARER", "asc-demo")
# Test-only: sleep before contacting ASC so Envoy's ext_authz timeout can fire.
FORCE_SLEEP_S = float(os.environ.get("ASC_FORCE_SLEEP_S_TEST", "0"))


def _blocked(reason: str) -> dict[str, Any]:
    return {
        "verdict": "BLOCK",
        "reason": reason,
        "acs_disposition": "DENY",
        "schema_version": "1.0.0",
    }


def credentials_ok(authorization: str | None, *, required_bearer: str | None = None) -> bool:
    """Return True only when Authorization matches the required Bearer token."""
    expected = required_bearer if required_bearer is not None else REQUIRED_BEARER
    return authorization == f"Bearer {expected}"


def call_asc(payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    """POST to the real ASC sidecar. Any transport failure => BLOCK."""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        ASC_EVALUATE_URL,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        try:
            with urllib.request.urlopen(req, timeout=ASC_TIMEOUT_S) as resp:  # noqa: S310
                raw = resp.read().decode("utf-8")
                try:
                    body = json.loads(raw)
                except json.JSONDecodeError:
                    return 503, _blocked("asc HTTP 200 non-JSON (fail-closed)")
                if not isinstance(body, dict):
                    return 503, _blocked("asc returned non-object JSON (fail-closed)")
                return resp.status, body
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8")
            try:
                body = json.loads(raw) if raw else _blocked(f"asc HTTP {exc.code}")
            except json.JSONDecodeError:
                body = _blocked(f"asc HTTP {exc.code} non-JSON (fail-closed)")
            if not isinstance(body, dict):
                body = _blocked(f"asc HTTP {exc.code} non-object (fail-closed)")
            return exc.code, body
    except Exception as exc:  # noqa: BLE001 - fail closed
        return 503, _blocked(
            f"asc decision API unavailable (fail-closed): {type(exc).__name__}: {exc}"
        )


def status_for_verdict(verdict: str) -> int:
    if verdict == "ALLOW":
        return 200
    if verdict == "REQUIRE_APPROVAL":
        return 401
    return 403


def normalize_payload(body: dict[str, Any]) -> dict[str, Any]:
    """Accept ASC evaluate JSON or a thin MCP tools/call wrapper around a trace."""
    if "trace" in body:
        scenario_id = body.get("scenario_id", "runtime")
        if not isinstance(scenario_id, str) or not scenario_id:
            raise ValueError("scenario_id must be a non-empty string")
        return {"scenario_id": scenario_id, "trace": body["trace"]}
    if "calls" in body and "agent_id" in body:
        return {"scenario_id": body.get("scenario_id", "runtime"), "trace": body}
    raise ValueError("body must be an ASC evaluate payload with trace or calls")


class ExtAuthzHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write(f"{self.address_string()} - {fmt % args}\n")

    def _write(
        self,
        status: int,
        payload: dict[str, Any],
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        raw = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        if extra_headers:
            for key, value in extra_headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802
        if urlparse(self.path).path in {"/healthz", "/ext_authz/healthz"}:
            self._write(200, {"status": "ok", "fail_closed": True, "asc": ASC_EVALUATE_URL})
            return
        self._write(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        # Envoy HTTP ext_authz prepends path_prefix; accept any /ext_authz* POST.
        path = urlparse(self.path).path
        if not path.startswith("/ext_authz"):
            self._write(404, {"error": "not found"})
            return

        if not credentials_ok(self.headers.get("Authorization")):
            self._write(
                401,
                _blocked("missing or invalid credentials (fail-closed)"),
                extra_headers={"x-asc-verdict": "BLOCK"},
            )
            return

        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length > 0 else b""
        if FORCE_SLEEP_S > 0:
            time.sleep(FORCE_SLEEP_S)

        try:
            body = json.loads(raw.decode("utf-8") if raw else "null")
            if not isinstance(body, dict):
                raise ValueError("body must be a JSON object")
            payload = normalize_payload(body)
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError) as exc:
            self._write(
                403,
                _blocked(f"malformed tool-call body (fail-closed): {exc}"),
                extra_headers={"x-asc-verdict": "BLOCK"},
            )
            return

        asc_status, envelope = call_asc(payload)
        verdict = envelope.get("verdict", "BLOCK")
        if verdict not in {"ALLOW", "BLOCK", "REQUIRE_APPROVAL"}:
            verdict = "BLOCK"
            envelope = _blocked("asc returned no valid verdict (fail-closed)")
        # Prefer ASC's own HTTP mapping when present; otherwise map locally.
        if asc_status in {200, 401, 403}:
            out_status = asc_status
        else:
            out_status = status_for_verdict(str(verdict))
        if out_status == 200 and verdict != "ALLOW":
            out_status = status_for_verdict(str(verdict))
        self._write(
            out_status,
            envelope,
            extra_headers={"x-asc-verdict": str(verdict)},
        )


def main() -> int:
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "9191"))
    print(
        f"ASC ext_authz adapter on http://{host}:{port} -> {ASC_EVALUATE_URL} "
        f"(timeout={ASC_TIMEOUT_S}s, fail-closed)",
        flush=True,
    )
    ThreadingHTTPServer((host, port), ExtAuthzHandler).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
