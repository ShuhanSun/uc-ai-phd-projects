"""Structured, privacy-conscious audit logging."""

import hashlib
import hmac
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
    rule_ids: tuple[str, ...]
    previous_digest: str
    event_digest: str


class AuditLogger:
    """Append decisions as JSON Lines without retaining sensitive arguments."""

    def __init__(
        self, path: Path | None = None, integrity_key: bytes | None = None
    ) -> None:
        self.path = path
        self.integrity_key = integrity_key
        self.events: list[AuditEvent] = []
        self._previous_digest = "0" * 64
        if path and path.exists() and path.stat().st_size:
            valid, _ = self.verify_file(path, integrity_key)
            if not valid:
                raise ValueError("existing audit log failed integrity verification")
            last_line = path.read_text(encoding="utf-8").splitlines()[-1]
            self._previous_digest = json.loads(last_line)["event_digest"]

    def record(self, session_id: str, request: ToolRequest, decision: Decision) -> None:
        serialized = json.dumps(request.arguments, sort_keys=True, default=str)
        fields = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "session_id": session_id,
            "tool": request.tool,
            "argument_digest": hashlib.sha256(serialized.encode()).hexdigest()[:16],
            "status": decision.status,
            "risk": decision.risk.value,
            "reasons": decision.reasons,
            "rule_ids": decision.rule_ids,
            "previous_digest": self._previous_digest,
        }
        digest = self._sign(_canonical(fields))
        event = AuditEvent(**fields, event_digest=digest)
        self._previous_digest = digest
        self.events.append(event)
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(asdict(event)) + "\n")

    def _sign(self, payload: bytes) -> str:
        if self.integrity_key:
            return hmac.digest(self.integrity_key, payload, "sha256").hex()
        return hashlib.sha256(payload).hexdigest()

    @classmethod
    def verify_file(
        cls, path: Path, integrity_key: bytes | None = None
    ) -> tuple[bool, int]:
        """Verify a JSONL hash chain and return validity plus checked event count."""

        verifier = cls(integrity_key=integrity_key)
        previous = "0" * 64
        count = 0
        with path.open(encoding="utf-8") as stream:
            for line in stream:
                try:
                    raw = json.loads(line)
                    claimed = raw.pop("event_digest")
                except (json.JSONDecodeError, KeyError):
                    return False, count
                if raw.get("previous_digest") != previous:
                    return False, count
                expected = verifier._sign(_canonical(raw))
                if not hmac.compare_digest(claimed, expected):
                    return False, count
                previous = claimed
                count += 1
        return True, count


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
