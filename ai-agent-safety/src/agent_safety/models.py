"""Domain models used by the safety gateway."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class ToolRequest:
    """A proposed action produced by an agent."""

    tool: str
    arguments: dict[str, Any] = field(default_factory=dict)
    context: str = ""


@dataclass(frozen=True)
class Decision:
    """The gateway's decision about a proposed action."""

    allowed: bool
    risk: RiskLevel
    reasons: tuple[str, ...]
    requires_approval: bool = False

    @property
    def status(self) -> str:
        if self.requires_approval:
            return "needs_approval"
        return "allowed" if self.allowed else "blocked"
