"""Fail-closed client for the ASC HTTP sidecar.

Any transport error, timeout, non-JSON body or missing/unknown verdict is
reported as BLOCK. Callers must only execute the tool call on ALLOW.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from asc.models import Verdict

_VALID = {v.value for v in Verdict}


def _blocked(reason: str) -> dict[str, Any]:
    return {"verdict": Verdict.BLOCK.value, "reason": reason, "acs_disposition": "DENY"}


def evaluate_remote(url: str, payload: dict[str, Any], *, timeout: float = 0.5) -> dict[str, Any]:
    """POST a trace to the sidecar and return its envelope, or a BLOCK on any failure."""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                raw = resp.read()
        except urllib.error.HTTPError as exc:  # 401/403/503 still carry an envelope
            raw = exc.read()
        body = json.loads(raw.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001 - timeouts, refused, bad JSON => BLOCK
        return _blocked(f"asc sidecar unavailable (fail-closed): {type(exc).__name__}: {exc}")
    if not isinstance(body, dict) or body.get("verdict") not in _VALID:
        return _blocked("asc sidecar returned no valid verdict (fail-closed)")
    return body
