"""Structured, privacy-conscious audit logging."""

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from .models import Decision, ToolRequest


@dataclass(frozen=True)
class AuditEvent:
    timestamp: str
    session_id: str
    tool: str
    argument_digest: str
    status: str
    risk: str
    reasons: tuple[str, ...]


class AuditLogger:
    """Append decisions as JSON Lines without retaining sensitive arguments."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self.events: list[AuditEvent] = []

    def record(self, session_id: str, request: ToolRequest, decision: Decision) -> None:
        serialized = json.dumps(request.arguments, sort_keys=True, default=str)
        event = AuditEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            session_id=session_id,
            tool=request.tool,
            argument_digest=hashlib.sha256(serialized.encode()).hexdigest()[:16],
            status=decision.status,
            risk=decision.risk.value,
            reasons=decision.reasons,
        )
        self.events.append(event)
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(asdict(event)) + "\n")
