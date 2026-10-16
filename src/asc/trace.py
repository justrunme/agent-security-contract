"""Parse tool-call traces from JSON. Fail-closed on malformed input."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from asc.models import CapabilityTool, ToolCall, Trace


class TraceError(Exception):
    """Raised when a trace is missing or malformed."""


def _require_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TraceError(f"{label} must be a mapping")
    return value


def _parse_catalog(raw: Any) -> tuple[CapabilityTool, ...] | None:
    if raw is None:
        return None
    if not isinstance(raw, list):
        raise TraceError("tool_catalog must be a list when present")
    tools: list[CapabilityTool] = []
    for i, item in enumerate(raw):
        data = _require_mapping(item, f"tool_catalog[{i}]")
        name = data.get("name")
        description = data.get("description")
        if not isinstance(name, str) or not name:
            raise TraceError(f"tool_catalog[{i}].name must be a non-empty string")
        if not isinstance(description, str):
            raise TraceError(f"tool_catalog[{i}].description must be a string")
        schema = data.get("input_schema", {})
        if not isinstance(schema, dict):
            raise TraceError(f"tool_catalog[{i}].input_schema must be a mapping")
        tools.append(CapabilityTool(name=name, description=description, input_schema=schema))
    return tuple(tools)


def _parse_call(raw: Any, index: int) -> ToolCall:
    data = _require_mapping(raw, f"calls[{index}]")
    call_id = data.get("call_id", f"call-{index}")
    tool = data.get("tool")
    args = data.get("args", {})
    approved = data.get("approved", False)
    if not isinstance(call_id, str) or not call_id:
        raise TraceError(f"calls[{index}].call_id must be a non-empty string")
    if not isinstance(tool, str) or not tool:
        raise TraceError(f"calls[{index}].tool must be a non-empty string")
    if not isinstance(args, dict):
        raise TraceError(f"calls[{index}].args must be a mapping")
    if not isinstance(approved, bool):
        raise TraceError(f"calls[{index}].approved must be a boolean")
    return ToolCall(call_id=call_id, tool=tool, args=args, approved=approved)


def parse_trace(raw: Any) -> Trace:
    """Parse and validate a trace mapping.

    Accepts either a bare trace object or a corpus scenario envelope that
    contains a nested ``trace`` field.
    """
    data = _require_mapping(raw, "trace")
    if "trace" in data and "calls" not in data:
        data = _require_mapping(data.get("trace"), "trace")
    agent_id = data.get("agent_id")
    trace_id = data.get("trace_id")
    if not isinstance(agent_id, str) or not agent_id:
        raise TraceError("agent_id must be a non-empty string")
    if not isinstance(trace_id, str) or not trace_id:
        raise TraceError("trace_id must be a non-empty string")
    calls_raw = data.get("calls")
    if not isinstance(calls_raw, list):
        raise TraceError("calls must be a list")
    calls = tuple(_parse_call(item, i) for i, item in enumerate(calls_raw))
    catalog = _parse_catalog(data.get("tool_catalog"))
    return Trace(agent_id=agent_id, trace_id=trace_id, calls=calls, tool_catalog=catalog)


def load_trace(path: str | Path) -> Trace:
    """Load a JSON tool-call trace. Fail-closed on missing or invalid content."""
    trace_path = Path(path)
    if not trace_path.is_file():
        raise TraceError(f"trace file not found: {trace_path}")
    try:
        text = trace_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise TraceError(f"unable to read trace: {exc}") from exc
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        raise TraceError(f"invalid trace JSON: {exc}") from exc
    return parse_trace(raw)
