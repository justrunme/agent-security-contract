"""Load and validate ASC policy documents (YAML). Fail-closed on any defect."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from asc.digest import compute_capability_digest
from asc.models import AgentPolicy, ArgConstraint, CapabilityTool, Policy, RateLimits, ToolAllow


class PolicyError(Exception):
    """Raised when a policy document is missing, malformed, or inconsistent."""


def _require_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PolicyError(f"{label} must be a mapping")
    return value


_ARG_CONSTRAINT_KEYS = frozenset(
    {"type", "pattern", "deny_patterns", "allow_hosts", "max_length", "required"}
)


def _parse_arg_constraint(raw: Any, label: str) -> ArgConstraint:
    data = _require_mapping(raw, label)
    # Fail closed on unknown keys: a typo such as ``deny_pattern`` or an
    # unsupported ``default`` must not silently drop a constraint.
    unknown = sorted(set(data) - _ARG_CONSTRAINT_KEYS)
    if unknown:
        raise PolicyError(f"{label} has unknown keys: {', '.join(unknown)}")
    type_name = data.get("type", "any")
    if not isinstance(type_name, str):
        raise PolicyError(f"{label}.type must be a string")
    pattern = data.get("pattern")
    if pattern is not None and not isinstance(pattern, str):
        raise PolicyError(f"{label}.pattern must be a string")
    deny = data.get("deny_patterns", [])
    if not isinstance(deny, list) or not all(isinstance(x, str) for x in deny):
        raise PolicyError(f"{label}.deny_patterns must be a list of strings")
    hosts = data.get("allow_hosts", [])
    if not isinstance(hosts, list) or not all(isinstance(x, str) for x in hosts):
        raise PolicyError(f"{label}.allow_hosts must be a list of strings")
    max_length = data.get("max_length")
    if max_length is not None and not isinstance(max_length, int):
        raise PolicyError(f"{label}.max_length must be an integer")
    # Default True: omitted means required (backward compatible with v0.2.0).
    if "required" in data:
        required = data["required"]
        if not isinstance(required, bool):
            raise PolicyError(f"{label}.required must be a boolean")
    else:
        required = True
    return ArgConstraint(
        type=type_name,
        pattern=pattern,
        deny_patterns=tuple(deny),
        allow_hosts=tuple(hosts),
        max_length=max_length,
        required=required,
    )


def _parse_tool_allow(raw: Any) -> ToolAllow:
    data = _require_mapping(raw, "allowed_tools[]")
    name = data.get("name")
    if not isinstance(name, str) or not name:
        raise PolicyError("allowed_tools[].name must be a non-empty string")
    args_raw = data.get("args", {})
    args_map = _require_mapping(args_raw, f"allowed_tools[{name}].args")
    args = {
        k: _parse_arg_constraint(v, f"allowed_tools[{name}].args.{k}")
        for k, v in args_map.items()
    }
    return ToolAllow(name=name, args=args)


def _parse_capabilities(raw: Any) -> tuple[CapabilityTool, ...]:
    if not isinstance(raw, list) or not raw:
        raise PolicyError("capabilities must be a non-empty list")
    tools: list[CapabilityTool] = []
    for i, item in enumerate(raw):
        data = _require_mapping(item, f"capabilities[{i}]")
        name = data.get("name")
        description = data.get("description")
        if not isinstance(name, str) or not name:
            raise PolicyError(f"capabilities[{i}].name must be a non-empty string")
        if not isinstance(description, str):
            raise PolicyError(f"capabilities[{i}].description must be a string")
        schema = data.get("input_schema", {})
        if not isinstance(schema, dict):
            raise PolicyError(f"capabilities[{i}].input_schema must be a mapping")
        tools.append(CapabilityTool(name=name, description=description, input_schema=schema))
    return tuple(tools)


def _parse_rate_limits(raw: Any) -> RateLimits:
    if raw is None:
        return RateLimits()
    data = _require_mapping(raw, "rate_limits")
    max_calls = data.get("max_calls_per_trace")
    if max_calls is not None and (not isinstance(max_calls, int) or max_calls < 1):
        raise PolicyError("rate_limits.max_calls_per_trace must be a positive integer")
    per_tool_raw = data.get("max_calls_per_tool", {})
    per_tool_map = _require_mapping(per_tool_raw, "rate_limits.max_calls_per_tool")
    per_tool: dict[str, int] = {}
    for k, v in per_tool_map.items():
        if not isinstance(v, int) or v < 1:
            raise PolicyError(f"rate_limits.max_calls_per_tool.{k} must be a positive integer")
        per_tool[k] = v
    return RateLimits(max_calls_per_trace=max_calls, max_calls_per_tool=per_tool)


def _parse_agent(agent_id: str, raw: Any) -> AgentPolicy:
    data = _require_mapping(raw, f"agents.{agent_id}")
    allowed_raw = data.get("allowed_tools")
    if not isinstance(allowed_raw, list) or not allowed_raw:
        raise PolicyError(f"agents.{agent_id}.allowed_tools must be a non-empty list")
    allowed: dict[str, ToolAllow] = {}
    for item in allowed_raw:
        tool = _parse_tool_allow(item)
        if tool.name in allowed:
            raise PolicyError(f"duplicate allowed tool: {tool.name}")
        allowed[tool.name] = tool
    high_impact = data.get("high_impact_tools", [])
    if not isinstance(high_impact, list) or not all(isinstance(x, str) for x in high_impact):
        raise PolicyError(f"agents.{agent_id}.high_impact_tools must be a list of strings")
    rate_limits = _parse_rate_limits(data.get("rate_limits"))
    return AgentPolicy(
        agent_id=agent_id,
        allowed_tools=allowed,
        high_impact_tools=frozenset(high_impact),
        rate_limits=rate_limits,
    )


def parse_policy(raw: Any) -> Policy:
    """Parse and validate a policy mapping. Raises PolicyError on any defect."""
    data = _require_mapping(raw, "policy")
    version = data.get("version")
    if not isinstance(version, str) or not version:
        raise PolicyError("version must be a non-empty string")
    digest = data.get("capability_digest")
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        raise PolicyError("capability_digest must be a sha256:<hex> string")
    capabilities = _parse_capabilities(data.get("capabilities"))
    computed = compute_capability_digest(capabilities)
    if computed != digest:
        raise PolicyError(
            f"capability_digest mismatch: policy declares {digest}, computed {computed}"
        )
    agents_raw = _require_mapping(data.get("agents"), "agents")
    if not agents_raw:
        raise PolicyError("agents must not be empty")
    agents = {aid: _parse_agent(aid, aval) for aid, aval in agents_raw.items()}
    capability_names = {c.name for c in capabilities}
    for agent in agents.values():
        for tool_name in agent.allowed_tools:
            if tool_name not in capability_names:
                raise PolicyError(
                    f"agent {agent.agent_id} allows unknown capability tool: {tool_name}"
                )
        for tool_name in agent.high_impact_tools:
            if tool_name not in capability_names:
                raise PolicyError(
                    f"agent {agent.agent_id} marks unknown high-impact tool: {tool_name}"
                )
    return Policy(
        version=version,
        capability_digest=digest,
        capabilities=capabilities,
        agents=agents,
    )


def load_policy(path: str | Path) -> Policy:
    """Load a policy YAML file. Fail-closed on missing or invalid content."""
    policy_path = Path(path)
    if not policy_path.is_file():
        raise PolicyError(f"policy file not found: {policy_path}")
    try:
        text = policy_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyError(f"unable to read policy: {exc}") from exc
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PolicyError(f"invalid policy YAML: {exc}") from exc
    if raw is None:
        raise PolicyError("policy file is empty")
    return parse_policy(raw)
