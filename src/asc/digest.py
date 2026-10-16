"""Capability digest helpers (SHA-256 over a canonical tool catalog)."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from asc.models import CapabilityTool


def canonical_capabilities(tools: list[CapabilityTool] | tuple[CapabilityTool, ...]) -> str:
    """Return a stable JSON encoding of the capability catalog."""
    payload: list[dict[str, Any]] = [
        {
            "name": t.name,
            "description": t.description,
            "input_schema": t.input_schema,
        }
        for t in sorted(tools, key=lambda x: x.name)
    ]
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_capability_digest(tools: list[CapabilityTool] | tuple[CapabilityTool, ...]) -> str:
    """Compute sha256:<hex> digest for the given tool capability catalog."""
    digest = hashlib.sha256(canonical_capabilities(tools).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"
