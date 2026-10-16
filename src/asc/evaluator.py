"""Fail-closed evaluator for agent tool-call traces against an ASC policy."""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from asc.digest import compute_capability_digest
from asc.envelope import build_envelope
from asc.models import (
    AgentPolicy,
    ArgConstraint,
    EvaluationResult,
    Policy,
    ToolAllow,
    ToolCall,
    Trace,
    Verdict,
)
from asc.policy import PolicyError, load_policy
from asc.trace import TraceError, load_trace, parse_trace


def _block(
    reason: str,
    scenario_id: str,
    *,
    call_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> EvaluationResult:
    return EvaluationResult(
        verdict=Verdict.BLOCK,
        reason=reason,
        scenario_id=scenario_id,
        blocked_call_id=call_id,
        details=details or {},
    )


def _type_ok(value: Any, expected: str) -> bool:
    if expected == "any":
        return True
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    return False


def _host_allowed(url: str, allow_hosts: tuple[str, ...]) -> bool:
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    host = (parsed.hostname or "").lower()
    if not host:
        return False
    for allowed in allow_hosts:
        allowed_l = allowed.lower()
        if host == allowed_l or host.endswith("." + allowed_l):
            return True
    return False


def _check_arg(
    name: str,
    value: Any,
    constraint: ArgConstraint,
    call: ToolCall,
    scenario_id: str,
) -> EvaluationResult | None:
    if not _type_ok(value, constraint.type):
        return _block(
            f"argument type violation for {call.tool}.{name}: expected {constraint.type}",
            scenario_id,
            call_id=call.call_id,
            details={"argument": name, "expected_type": constraint.type},
        )
    if isinstance(value, str):
        if constraint.max_length is not None and len(value) > constraint.max_length:
            return _block(
                f"argument too long for {call.tool}.{name}",
                scenario_id,
                call_id=call.call_id,
                details={"argument": name, "max_length": constraint.max_length},
            )
        if constraint.pattern is not None and re.search(constraint.pattern, value) is None:
            return _block(
                f"argument pattern mismatch for {call.tool}.{name}",
                scenario_id,
                call_id=call.call_id,
                details={"argument": name, "pattern": constraint.pattern},
            )
        for deny in constraint.deny_patterns:
            if re.search(deny, value):
                return _block(
                    f"denied pattern in {call.tool}.{name}: {deny}",
                    scenario_id,
                    call_id=call.call_id,
                    details={"argument": name, "deny_pattern": deny},
                )
        if constraint.allow_hosts:
            if not _host_allowed(value, constraint.allow_hosts):
                return _block(
                    f"host not allowlisted for {call.tool}.{name}",
                    scenario_id,
                    call_id=call.call_id,
                    details={
                        "argument": name,
                        "value": value,
                        "allow_hosts": list(constraint.allow_hosts),
                    },
                )
    return None


def _check_call_args(
    call: ToolCall,
    allow: ToolAllow,
    scenario_id: str,
) -> EvaluationResult | None:
    for arg_name, constraint in allow.args.items():
        if arg_name not in call.args:
            return _block(
                f"missing required argument {call.tool}.{arg_name}",
                scenario_id,
                call_id=call.call_id,
                details={"argument": arg_name},
            )
        result = _check_arg(arg_name, call.args[arg_name], constraint, call, scenario_id)
        if result is not None:
            return result
    return None


def _check_rate_limits(
    agent: AgentPolicy,
    trace: Trace,
    scenario_id: str,
) -> EvaluationResult | None:
    limits = agent.rate_limits
    if limits.max_calls_per_trace is not None and len(trace.calls) > limits.max_calls_per_trace:
        return _block(
            f"excessive call rate: {len(trace.calls)} > max_calls_per_trace "
            f"{limits.max_calls_per_trace}",
            scenario_id,
            details={
                "call_count": len(trace.calls),
                "max_calls_per_trace": limits.max_calls_per_trace,
            },
        )
    counts = Counter(c.tool for c in trace.calls)
    for tool_name, max_count in limits.max_calls_per_tool.items():
        if counts.get(tool_name, 0) > max_count:
            return _block(
                f"excessive call rate for tool {tool_name}: "
                f"{counts[tool_name]} > {max_count}",
                scenario_id,
                details={"tool": tool_name, "count": counts[tool_name], "max": max_count},
            )
    return None


def evaluate(policy: Policy, trace: Trace, *, scenario_id: str = "adhoc") -> EvaluationResult:
    """Evaluate a parsed trace against a parsed policy. Always fail-closed.

    Any unexpected exception inside the evaluator yields BLOCK, never ALLOW.
    """
    try:
        return _evaluate(policy, trace, scenario_id=scenario_id)
    except Exception as exc:  # noqa: BLE001 - fail-closed by design
        return _block(
            f"evaluator error (fail-closed): {type(exc).__name__}: {exc}",
            scenario_id,
        )


def _evaluate(policy: Policy, trace: Trace, *, scenario_id: str) -> EvaluationResult:
    agent = policy.agents.get(trace.agent_id)
    if agent is None:
        return _block(
            f"unknown agent_id: {trace.agent_id}",
            scenario_id,
            details={"agent_id": trace.agent_id},
        )

    catalog = trace.tool_catalog if trace.tool_catalog is not None else policy.capabilities
    observed_digest = compute_capability_digest(catalog)
    if observed_digest != policy.capability_digest:
        return _block(
            "capability digest mismatch (possible MCP tool poisoning or unapproved catalog)",
            scenario_id,
            details={
                "expected": policy.capability_digest,
                "observed": observed_digest,
            },
        )

    rate_result = _check_rate_limits(agent, trace, scenario_id)
    if rate_result is not None:
        return rate_result

    pending_approval: EvaluationResult | None = None

    for call in trace.calls:
        allow = agent.allowed_tools.get(call.tool)
        if allow is None:
            return _block(
                f"unknown or disallowed tool: {call.tool}",
                scenario_id,
                call_id=call.call_id,
                details={"tool": call.tool},
            )

        arg_result = _check_call_args(call, allow, scenario_id)
        if arg_result is not None:
            return arg_result

        if call.tool in agent.high_impact_tools and not call.approved:
            if pending_approval is None:
                pending_approval = EvaluationResult(
                    verdict=Verdict.REQUIRE_APPROVAL,
                    reason=f"high-impact tool requires approval: {call.tool}",
                    scenario_id=scenario_id,
                    blocked_call_id=call.call_id,
                    details={"tool": call.tool},
                )

    if pending_approval is not None:
        return pending_approval

    return EvaluationResult(
        verdict=Verdict.ALLOW,
        reason="all tool calls satisfy the security contract",
        scenario_id=scenario_id,
    )


def evaluate_paths(
    policy_path: str,
    trace_path: str,
    *,
    scenario_id: str = "adhoc",
) -> EvaluationResult:
    """Load policy and trace from disk, then evaluate. Fail-closed on load errors."""
    try:
        policy = load_policy(policy_path)
    except PolicyError as exc:
        return _block(f"invalid or missing policy: {exc}", scenario_id)
    try:
        trace = load_trace(trace_path)
    except TraceError as exc:
        return _block(f"invalid or malformed trace: {exc}", scenario_id)
    return evaluate(policy, trace, scenario_id=scenario_id)


def evaluate_paths_envelope(
    policy_path: str,
    trace_path: str,
    *,
    scenario_id: str = "adhoc",
) -> tuple[EvaluationResult, dict[str, Any]]:
    """Evaluate and return (result, evidence envelope). Always emits an envelope."""
    policy: Policy | None = None
    trace: Trace | None = None
    try:
        policy = load_policy(policy_path)
    except PolicyError as exc:
        result = _block(f"invalid or missing policy: {exc}", scenario_id)
        envelope = build_envelope(
            result=result,
            policy=None,
            policy_path=policy_path if Path(policy_path).is_file() else None,
            trace=None,
            policy_version="unknown",
        )
        return result, envelope
    try:
        trace = load_trace(trace_path)
    except TraceError as exc:
        result = _block(f"invalid or malformed trace: {exc}", scenario_id)
        envelope = build_envelope(
            result=result,
            policy=policy,
            policy_path=policy_path,
            trace=None,
        )
        return result, envelope
    result = evaluate(policy, trace, scenario_id=scenario_id)
    envelope = build_envelope(
        result=result,
        policy=policy,
        policy_path=policy_path,
        trace=trace,
    )
    return result, envelope


def evaluate_trace_data(
    policy: Policy,
    trace_data: dict[str, Any],
    *,
    scenario_id: str = "adhoc",
) -> EvaluationResult:
    """Evaluate an in-memory trace mapping. Fail-closed on parse errors."""
    try:
        trace = parse_trace(trace_data)
    except Exception as exc:  # noqa: BLE001 - fail-closed on any parse defect
        return _block(f"invalid or malformed trace: {exc}", scenario_id)
    return evaluate(policy, trace, scenario_id=scenario_id)
