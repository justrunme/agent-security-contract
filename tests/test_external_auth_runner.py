"""Unit tests for external-auth integration runner helpers."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

RUNNER_PATH = (
    Path(__file__).resolve().parents[1]
    / "examples"
    / "external-auth"
    / "run_integration_tests.py"
)


def _load_runner():
    spec = importlib.util.spec_from_file_location("asc_ext_auth_runner", RUNNER_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


runner = _load_runner()


def test_classify_envoy_failure_path_on_bare_403() -> None:
    assert (
        runner.classify_envoy_ext_authz_failure(
            status=403,
            body=None,
            headers={},
        )
        == "envoy_ext_authz_failure_path"
    )
    assert (
        runner.classify_envoy_ext_authz_failure(
            status=403,
            body={"error": "forbidden"},
            headers={"content-type": "text/plain"},
        )
        == "envoy_ext_authz_failure_path"
    )


def test_classify_envoy_failure_path_null_on_200() -> None:
    """A 200 on authorizer_down/timeout scenarios must not be labeled Envoy deny."""
    assert (
        runner.classify_envoy_ext_authz_failure(
            status=200,
            body={"executed": True, "note": "reached mcp-demo"},
            headers={},
        )
        is None
    )


def test_classify_envoy_failure_path_null_when_adapter_envelope_present() -> None:
    body = {
        "schema_version": "1.0.0",
        "verdict": "BLOCK",
        "reason": "malformed tool-call body (fail-closed)",
    }
    assert (
        runner.classify_envoy_ext_authz_failure(
            status=403,
            body=body,
            headers={"x-asc-verdict": "BLOCK"},
        )
        is None
    )
    assert (
        runner.classify_envoy_ext_authz_failure(
            status=403,
            body=body,
            headers={},
        )
        is None
    )


def test_classify_envoy_failure_path_null_on_401_credentials() -> None:
    assert (
        runner.classify_envoy_ext_authz_failure(
            status=401,
            body={"schema_version": "1.0.0", "verdict": "BLOCK", "reason": "credentials"},
            headers={"x-asc-verdict": "BLOCK"},
        )
        is None
    )


def test_build_report_commit_sha_unknown_without_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ASC_COMMIT_SHA", raising=False)
    monkeypatch.delenv("GITHUB_SHA", raising=False)
    report = runner.build_report([], suite_time_ms=1)
    assert report["commit_sha"] == "unknown"


def test_build_report_commit_sha_from_asc_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ASC_COMMIT_SHA", "abc123def")
    monkeypatch.setenv("GITHUB_SHA", "should-not-win")
    report = runner.build_report([], suite_time_ms=1)
    assert report["commit_sha"] == "abc123def"
