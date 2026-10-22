"""Unit tests for the Envoy ext_authz adapter (real fail-closed helpers, no mocks of ASC logic)."""

from __future__ import annotations

import importlib.util
import json
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

ADAPTER_PATH = (
    Path(__file__).resolve().parents[1]
    / "examples"
    / "external-auth"
    / "ext_authz_adapter.py"
)


def _load_adapter():
    spec = importlib.util.spec_from_file_location("asc_ext_authz_adapter", ADAPTER_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


adapter = _load_adapter()


def test_normalize_payload_evaluate_shape() -> None:
    body = {"scenario_id": "s1", "trace": {"agent_id": "demo-agent", "trace_id": "t", "calls": []}}
    assert adapter.normalize_payload(body) == body


def test_normalize_payload_trace_as_root() -> None:
    body = {"agent_id": "demo-agent", "trace_id": "t", "calls": [], "scenario_id": "s2"}
    out = adapter.normalize_payload(body)
    assert out["scenario_id"] == "s2"
    assert out["trace"]["agent_id"] == "demo-agent"


def test_normalize_payload_rejects_empty_scenario_id() -> None:
    with pytest.raises(ValueError, match="scenario_id"):
        adapter.normalize_payload({"scenario_id": "", "trace": {"calls": []}})


def test_normalize_payload_rejects_unknown_shape() -> None:
    with pytest.raises(ValueError, match="ASC evaluate payload"):
        adapter.normalize_payload({"not": "a-trace"})


@given(st.sampled_from(["ALLOW", "BLOCK", "REQUIRE_APPROVAL", "NOPE", ""]))
def test_status_for_verdict_mapping(verdict: str) -> None:
    status = adapter.status_for_verdict(verdict)
    if verdict == "ALLOW":
        assert status == 200
    elif verdict == "REQUIRE_APPROVAL":
        assert status == 401
    else:
        assert status == 403


def test_credentials_ok_accepts_bearer() -> None:
    assert adapter.credentials_ok("Bearer asc-demo", required_bearer="asc-demo") is True


@pytest.mark.parametrize(
    "header",
    [None, "", "Bearer wrong", "asc-demo", "bearer asc-demo", "Basic asc-demo"],
)
def test_credentials_ok_rejects_missing_or_invalid(header: str | None) -> None:
    assert adapter.credentials_ok(header, required_bearer="asc-demo") is False


def _serve_once(handler_cls: type[BaseHTTPRequestHandler]) -> tuple[str, ThreadingHTTPServer]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    return f"http://{host}:{port}", server


def test_call_asc_connection_error_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(adapter, "ASC_EVALUATE_URL", "http://127.0.0.1:1/v1/evaluate")
    monkeypatch.setattr(adapter, "ASC_TIMEOUT_S", 0.2)
    status, body = adapter.call_asc({"scenario_id": "x", "trace": {}})
    assert status == 503
    assert body["verdict"] == "BLOCK"
    assert "fail-closed" in body["reason"]


def test_call_asc_timeout_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    class Hang(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            time.sleep(2.0)

        def log_message(self, fmt: str, *args: Any) -> None:
            return

    url, server = _serve_once(Hang)
    try:
        monkeypatch.setattr(adapter, "ASC_EVALUATE_URL", f"{url}/v1/evaluate")
        monkeypatch.setattr(adapter, "ASC_TIMEOUT_S", 0.2)
        status, body = adapter.call_asc({"scenario_id": "x", "trace": {}})
        assert status == 503
        assert body["verdict"] == "BLOCK"
        assert "fail-closed" in body["reason"]
    finally:
        server.shutdown()


def test_call_asc_http_5xx_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    class Boom(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            raw = b'{"verdict":"BLOCK","reason":"upstream 503","acs_disposition":"DENY"}'
            self.send_response(503)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, fmt: str, *args: Any) -> None:
            return

    url, server = _serve_once(Boom)
    try:
        monkeypatch.setattr(adapter, "ASC_EVALUATE_URL", f"{url}/v1/evaluate")
        monkeypatch.setattr(adapter, "ASC_TIMEOUT_S", 1.0)
        status, body = adapter.call_asc({"scenario_id": "x", "trace": {}})
        assert status == 503
        assert body["verdict"] == "BLOCK"
    finally:
        server.shutdown()


def test_call_asc_malformed_json_response_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    class BadJson(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            raw = b"not-json"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, fmt: str, *args: Any) -> None:
            return

    url, server = _serve_once(BadJson)
    try:
        monkeypatch.setattr(adapter, "ASC_EVALUATE_URL", f"{url}/v1/evaluate")
        monkeypatch.setattr(adapter, "ASC_TIMEOUT_S", 1.0)
        status, body = adapter.call_asc({"scenario_id": "x", "trace": {}})
        assert status == 503
        assert body["verdict"] == "BLOCK"
        assert "non-JSON" in body["reason"] or "fail-closed" in body["reason"]
    finally:
        server.shutdown()


def test_call_asc_http_error_non_json_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    class Bad403(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            raw = b"<html>nope</html>"
            self.send_response(403)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, fmt: str, *args: Any) -> None:
            return

    url, server = _serve_once(Bad403)
    try:
        monkeypatch.setattr(adapter, "ASC_EVALUATE_URL", f"{url}/v1/evaluate")
        monkeypatch.setattr(adapter, "ASC_TIMEOUT_S", 1.0)
        status, body = adapter.call_asc({"scenario_id": "x", "trace": {}})
        assert status == 403
        assert body["verdict"] == "BLOCK"
        assert "fail-closed" in body["reason"]
    finally:
        server.shutdown()


def test_handler_missing_credentials_denied_without_asc(monkeypatch: pytest.MonkeyPatch) -> None:
    """Missing Authorization must 401; ASC must not be contacted."""
    called = {"asc": False}

    def boom_call_asc(payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        called["asc"] = True
        raise AssertionError("ASC must not be called without credentials")

    monkeypatch.setattr(adapter, "call_asc", boom_call_asc)
    monkeypatch.setattr(adapter, "REQUIRED_BEARER", "asc-demo")

    server = ThreadingHTTPServer(("127.0.0.1", 0), adapter.ExtAuthzHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        data = json.dumps(
            {"scenario_id": "x", "trace": {"agent_id": "a", "trace_id": "t", "calls": []}}
        ).encode()
        req = urllib.request.Request(
            f"http://{host}:{port}/ext_authz/mcp/v1/tools/call",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req, timeout=2)  # noqa: S310
        assert exc_info.value.code == 401
        body = json.loads(exc_info.value.read().decode())
        assert body["verdict"] == "BLOCK"
        assert "credentials" in body["reason"]
        assert called["asc"] is False
    finally:
        server.shutdown()
