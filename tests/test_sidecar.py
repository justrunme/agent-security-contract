"""Integration test for the fail-closed HTTP sidecar."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from asc.policy import load_policy
from asc.sidecar import AscSidecar


@pytest.fixture
def sidecar_server():
    AscSidecar.policy = load_policy("policy/demo-agent.policy.yaml")
    AscSidecar.policy_path = "policy/demo-agent.policy.yaml"
    server = ThreadingHTTPServer(("127.0.0.1", 0), AscSidecar)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    yield f"http://{host}:{port}"
    server.shutdown()


def _post(url: str, payload: dict, timeout: float = 2.0) -> tuple[int, dict]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            return resp.status, body
    except urllib.error.HTTPError as exc:
        body = json.loads(exc.read().decode("utf-8"))
        return exc.code, body


def test_sidecar_allows_benign_pre_execution(sidecar_server: str) -> None:
    scenario = json.loads(
        open("corpus/scenarios/benign_read_workspace_file.json", encoding="utf-8").read()
    )
    status, body = _post(
        f"{sidecar_server}/v1/evaluate",
        {"scenario_id": scenario["scenario_id"], "trace": scenario["trace"]},
    )
    assert status == 200
    assert body["verdict"] == "ALLOW"
    assert body["schema_version"] == "1.0.0"
    assert "policy_sha256" in body


def test_sidecar_blocks_attack_pre_execution(sidecar_server: str) -> None:
    scenario = json.loads(
        open("corpus/scenarios/data_exfil_non_allowlisted_host.json", encoding="utf-8").read()
    )
    status, body = _post(
        f"{sidecar_server}/v1/evaluate",
        {"scenario_id": scenario["scenario_id"], "trace": scenario["trace"]},
    )
    assert status == 403
    assert body["verdict"] == "BLOCK"
    assert body["acs_disposition"] == "DENY"


def test_sidecar_fail_closed_on_malformed_body(sidecar_server: str) -> None:
    status, body = _post(f"{sidecar_server}/v1/evaluate", {"not": "a-trace"})
    assert status in {403, 503}
    assert body["verdict"] == "BLOCK"


def test_client_transport_failure_fail_closed(sidecar_server: str) -> None:
    """Caller contract for ai-runtime: transport/timeout errors => BLOCK."""

    def evaluate_or_block(url: str, payload: dict, timeout: float) -> str:
        try:
            _status, body = _post(url, payload, timeout=timeout)
            return body.get("verdict", "BLOCK")
        except TimeoutError:
            return "BLOCK"
        except urllib.error.URLError:
            return "BLOCK"

    scenario = json.loads(
        open("corpus/scenarios/benign_api_fetch.json", encoding="utf-8").read()
    )
    assert (
        evaluate_or_block(
            f"{sidecar_server}/v1/evaluate",
            {"scenario_id": "ok", "trace": scenario["trace"]},
            timeout=2.0,
        )
        == "ALLOW"
    )
    # Unreachable port: must not proceed.
    unreachable = evaluate_or_block(
        "http://127.0.0.1:1/v1/evaluate",
        {"trace": {}},
        timeout=0.2,
    )
    assert unreachable == "BLOCK"


def test_shipped_client_times_out_to_block() -> None:
    """A sidecar that hangs past the client timeout must yield BLOCK."""
    import socket
    import time

    from asc.client import evaluate_remote

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def hang() -> None:
        conn, _ = srv.accept()
        time.sleep(2.0)
        conn.close()

    threading.Thread(target=hang, daemon=True).start()
    start = time.monotonic()
    body = evaluate_remote(f"http://127.0.0.1:{port}/v1/evaluate", {"trace": {}}, timeout=0.3)
    assert body["verdict"] == "BLOCK"
    assert "fail-closed" in body["reason"]
    assert time.monotonic() - start < 1.5
    srv.close()


def test_shipped_client_unreachable_and_allow(sidecar_server: str) -> None:
    from asc.client import evaluate_remote

    assert evaluate_remote("http://127.0.0.1:1/v1/evaluate", {}, timeout=0.2)["verdict"] == "BLOCK"
    scenario = json.loads(open("corpus/scenarios/benign_api_fetch.json", encoding="utf-8").read())
    body = evaluate_remote(
        f"{sidecar_server}/v1/evaluate", {"scenario_id": "ok", "trace": scenario["trace"]}
    )
    assert body["verdict"] == "ALLOW"
