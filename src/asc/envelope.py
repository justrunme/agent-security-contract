"""Evidence envelope construction and fail-closed verification."""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from asc.models import EvaluationResult, Policy, Trace, Verdict

SCHEMA_VERSION = "1.0.0"


def _schema_path() -> Path:
    candidates = [
        Path(__file__).resolve().parent / "schemas" / "evidence-envelope.schema.json",
        Path(__file__).resolve().parents[2] / "schemas" / "evidence-envelope.schema.json",
        Path.cwd() / "schemas" / "evidence-envelope.schema.json",
    ]
    for path in candidates:
        if path.is_file():
            return path
    return candidates[0]

_SHA256_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
_ISO_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)

REQUIRED_FIELDS = (
    "schema_version",
    "policy_version",
    "policy_sha256",
    "scenario_id",
    "verdict",
    "reason",
    "trace_id",
    "commit_sha",
    "timestamp",
)


DIGEST_FIELD = "envelope_sha256"


def envelope_digest(envelope: dict[str, Any]) -> str:
    """SHA-256 over the canonical JSON of every field except the digest itself.

    This is an integrity check against accidental or naive edits. It is not a
    signature: anyone who can rewrite the file can recompute it.
    """
    body = {k: v for k, v in envelope.items() if k != DIGEST_FIELD}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class EnvelopeError(Exception):
    """Raised when an evidence envelope is invalid or tampered."""


def policy_sha256_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def policy_sha256_file(path: str | Path) -> str:
    return policy_sha256_bytes(Path(path).read_bytes())


def resolve_commit_sha(explicit: str | None = None) -> str:
    if explicit:
        return explicit
    for key in ("GITHUB_SHA", "ASC_COMMIT_SHA", "GIT_COMMIT"):
        value = os.environ.get(key)
        if value:
            return value
    return "unknown"


def utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def acs_disposition(verdict: Verdict) -> str:
    if verdict == Verdict.ALLOW:
        return "ALLOW"
    if verdict == Verdict.REQUIRE_APPROVAL:
        return "ASK"
    return "DENY"


def build_envelope(
    *,
    result: EvaluationResult,
    policy: Policy | None,
    policy_path: str | Path | None,
    trace: Trace | None,
    commit_sha: str | None = None,
    timestamp: str | None = None,
    policy_version: str | None = None,
    policy_digest: str | None = None,
) -> dict[str, Any]:
    """Build a schema_version=1.0.0 evidence envelope for a verdict."""
    if policy is not None:
        version = policy.version
    else:
        version = policy_version or "unknown"

    if policy_path is not None and Path(policy_path).is_file():
        digest = policy_sha256_file(policy_path)
    elif policy_digest is not None:
        digest = policy_digest
    else:
        digest = "sha256:" + ("0" * 64)

    trace_id = trace.trace_id if trace is not None else "unknown"
    envelope: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "policy_version": version,
        "policy_sha256": digest,
        "scenario_id": result.scenario_id,
        "verdict": result.verdict.value,
        "reason": result.reason,
        "trace_id": trace_id,
        "commit_sha": resolve_commit_sha(commit_sha),
        "timestamp": timestamp or utc_now_iso(),
        "blocked_call_id": result.blocked_call_id,
        "details": dict(result.details),
        "acs_disposition": acs_disposition(result.verdict),
    }
    envelope[DIGEST_FIELD] = envelope_digest(envelope)
    return envelope


def load_schema() -> dict[str, Any]:
    schema_path = _schema_path()
    if not schema_path.is_file():
        raise EnvelopeError(f"evidence schema not found: {schema_path}")
    try:
        return json.loads(schema_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise EnvelopeError(f"invalid evidence schema JSON: {exc}") from exc


def verify_envelope(
    envelope: Any,
    *,
    expected_policy_sha256: str | None = None,
) -> dict[str, Any]:
    """Validate an envelope. Fail-closed on schema or integrity defects."""
    if not isinstance(envelope, dict):
        raise EnvelopeError("envelope must be a JSON object")

    for field in REQUIRED_FIELDS:
        if field not in envelope:
            raise EnvelopeError(f"missing required field: {field}")

    if envelope.get("schema_version") != SCHEMA_VERSION:
        raise EnvelopeError(
            f"unsupported schema_version: {envelope.get('schema_version')} "
            f"(expected {SCHEMA_VERSION})"
        )

    policy_version = envelope.get("policy_version")
    if not isinstance(policy_version, str) or not policy_version:
        raise EnvelopeError("policy_version must be a non-empty string")

    policy_sha = envelope.get("policy_sha256")
    if not isinstance(policy_sha, str) or _SHA256_RE.match(policy_sha) is None:
        raise EnvelopeError("policy_sha256 must match sha256:<64 hex>")

    for field in ("scenario_id", "reason", "trace_id", "commit_sha"):
        value = envelope.get(field)
        if not isinstance(value, str) or not value:
            raise EnvelopeError(f"{field} must be a non-empty string")

    verdict = envelope.get("verdict")
    if verdict not in {v.value for v in Verdict}:
        raise EnvelopeError(f"invalid verdict: {verdict}")

    timestamp = envelope.get("timestamp")
    if not isinstance(timestamp, str) or _ISO_RE.match(timestamp) is None:
        raise EnvelopeError("timestamp must be an ISO-8601 date-time string")

    if "acs_disposition" in envelope:
        if envelope["acs_disposition"] not in {"ALLOW", "DENY", "ASK"}:
            raise EnvelopeError("acs_disposition must be ALLOW, DENY, or ASK")
        expected = acs_disposition(Verdict(verdict))
        if envelope["acs_disposition"] != expected:
            raise EnvelopeError(
                f"tampered acs_disposition: {envelope['acs_disposition']} "
                f"incompatible with verdict {verdict}"
            )

    if expected_policy_sha256 is not None and policy_sha != expected_policy_sha256:
        raise EnvelopeError(
            f"tampered policy_sha256: envelope has {policy_sha}, "
            f"expected {expected_policy_sha256}"
        )

    digest = envelope.get(DIGEST_FIELD)
    if not isinstance(digest, str) or _SHA256_RE.match(digest) is None:
        raise EnvelopeError(f"{DIGEST_FIELD} must match sha256:<64 hex>")
    if digest != envelope_digest(envelope):
        raise EnvelopeError(f"tampered envelope: {DIGEST_FIELD} does not match content")

    # Reject unknown top-level keys beyond the published schema.
    schema = load_schema()
    allowed = set(schema.get("properties", {}).keys())
    unknown = sorted(set(envelope.keys()) - allowed)
    if unknown:
        raise EnvelopeError(f"unknown envelope fields: {', '.join(unknown)}")

    return envelope


def load_and_verify_envelope(
    path: str | Path,
    *,
    policy_path: str | Path | None = None,
) -> dict[str, Any]:
    envelope_path = Path(path)
    if not envelope_path.is_file():
        raise EnvelopeError(f"envelope file not found: {envelope_path}")
    try:
        raw = json.loads(envelope_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise EnvelopeError(f"invalid envelope JSON: {exc}") from exc
    expected = policy_sha256_file(policy_path) if policy_path else None
    return verify_envelope(raw, expected_policy_sha256=expected)
