"""Configurable policy for constraining an agent's capabilities."""

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping


@dataclass(frozen=True)
class ToolSchema:
    """Minimal, dependency-free argument contract for one tool."""

    required: frozenset[str] = frozenset()
    properties: Mapping[str, type] = field(default_factory=dict)
    allow_extra: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "properties", MappingProxyType(dict(self.properties)))
        unknown_required = self.required - self.properties.keys()
        if unknown_required:
            raise ValueError(f"required arguments need declared types: {unknown_required}")


def _default_schemas() -> Mapping[str, ToolSchema]:
    return {
        "calculator": ToolSchema(frozenset({"expression"}), {"expression": str}),
        "search": ToolSchema(frozenset({"query"}), {"query": str}),
        "read_file": ToolSchema(frozenset({"path"}), {"path": str}),
        "send_email": ToolSchema(
            frozenset({"to", "body"}), {"to": str, "body": str, "subject": str}
        ),
        "write_file": ToolSchema(
            frozenset({"path", "content"}), {"path": str, "content": str}
        ),
    }


@dataclass(frozen=True)
class SafetyPolicy:
    """A small, explicit policy suitable for demos and experimentation."""

    allowed_tools: frozenset[str] = field(
        default_factory=lambda: frozenset({"calculator", "search", "read_file"})
    )
    approval_tools: frozenset[str] = field(
        default_factory=lambda: frozenset({"send_email", "write_file"})
    )
    blocked_path_fragments: tuple[str, ...] = (
        ".env",
        ".ssh",
        "credentials",
        "secrets",
        "/etc/shadow",
    )
    max_actions_per_session: int = 10
    max_argument_characters: int = 4_000
    max_context_characters: int = 20_000
    tool_schemas: Mapping[str, ToolSchema] = field(default_factory=_default_schemas)

    def __post_init__(self) -> None:
        if self.max_actions_per_session < 1:
            raise ValueError("max_actions_per_session must be positive")
        if self.max_argument_characters < 1:
            raise ValueError("max_argument_characters must be positive")
        if self.max_context_characters < 1:
            raise ValueError("max_context_characters must be positive")
        overlap = self.allowed_tools & self.approval_tools
        if overlap:
            raise ValueError(f"tools cannot be both allowed and approval-only: {overlap}")
        object.__setattr__(self, "tool_schemas", MappingProxyType(dict(self.tool_schemas)))
        missing = (self.allowed_tools | self.approval_tools) - self.tool_schemas.keys()
        if missing:
            raise ValueError(f"allowlisted tools need schemas: {missing}")
