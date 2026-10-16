"""Shared data models for policy, traces, and verdicts."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Verdict(StrEnum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


@dataclass(frozen=True)
class ArgConstraint:
    type: str = "any"
    pattern: str | None = None
    deny_patterns: tuple[str, ...] = ()
    allow_hosts: tuple[str, ...] = ()
    max_length: int | None = None


@dataclass(frozen=True)
class ToolAllow:
    name: str
    args: dict[str, ArgConstraint] = field(default_factory=dict)


@dataclass(frozen=True)
class CapabilityTool:
    name: str
    description: str
    input_schema: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RateLimits:
    max_calls_per_trace: int | None = None
    max_calls_per_tool: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class AgentPolicy:
    agent_id: str
    allowed_tools: dict[str, ToolAllow]
    high_impact_tools: frozenset[str]
    rate_limits: RateLimits


@dataclass(frozen=True)
class Policy:
    version: str
    capability_digest: str
    capabilities: tuple[CapabilityTool, ...]
    agents: dict[str, AgentPolicy]


@dataclass(frozen=True)
class ToolCall:
    call_id: str
    tool: str
    args: dict[str, Any]
    approved: bool = False


@dataclass(frozen=True)
class Trace:
    agent_id: str
    trace_id: str
    calls: tuple[ToolCall, ...]
    tool_catalog: tuple[CapabilityTool, ...] | None = None


@dataclass(frozen=True)
class EvaluationResult:
    verdict: Verdict
    reason: str
    scenario_id: str
    blocked_call_id: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "reason": self.reason,
            "scenario_id": self.scenario_id,
            "blocked_call_id": self.blocked_call_id,
            "details": self.details,
        }
