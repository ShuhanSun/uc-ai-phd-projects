"""Configurable policy for constraining an agent's capabilities."""

from dataclasses import dataclass, field


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

    def __post_init__(self) -> None:
        if self.max_actions_per_session < 1:
            raise ValueError("max_actions_per_session must be positive")
        if self.max_argument_characters < 1:
            raise ValueError("max_argument_characters must be positive")
        overlap = self.allowed_tools & self.approval_tools
        if overlap:
            raise ValueError(f"tools cannot be both allowed and approval-only: {overlap}")
