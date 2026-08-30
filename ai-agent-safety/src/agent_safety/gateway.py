"""Central policy-enforcement point for agent tool calls."""

import json
import re
from collections import Counter

from .audit import AuditLogger
from .models import Decision, RiskLevel, ToolRequest
from .policy import SafetyPolicy


INJECTION_PATTERNS = (
    re.compile(r"ignore (?:all |the )?(?:previous|prior) instructions", re.I),
    re.compile(r"reveal (?:the )?(?:system prompt|hidden instructions)", re.I),
    re.compile(r"(?:disable|bypass|override) (?:the )?(?:safety|policy|guardrails)", re.I),
    re.compile(r"you are now (?:in )?(?:developer|admin|root) mode", re.I),
)


class SafetyGateway:
    """Evaluate every action before it reaches a real tool executor."""

    def __init__(
        self,
        policy: SafetyPolicy | None = None,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        self.policy = policy or SafetyPolicy()
        self.audit = audit_logger or AuditLogger()
        self._action_counts: Counter[str] = Counter()

    def evaluate(self, request: ToolRequest, session_id: str = "default") -> Decision:
        reasons: list[str] = []
        risk = RiskLevel.LOW
        serialized = json.dumps(request.arguments, sort_keys=True, default=str)
        combined_text = f"{request.context}\n{serialized}"

        if self._action_counts[session_id] >= self.policy.max_actions_per_session:
            decision = Decision(False, RiskLevel.HIGH, ("session action budget exhausted",))
            self.audit.record(session_id, request, decision)
            return decision

        self._action_counts[session_id] += 1

        if request.tool not in self.policy.allowed_tools | self.policy.approval_tools:
            reasons.append("tool is not in the capability allowlist")
            risk = RiskLevel.CRITICAL

        if any(pattern.search(combined_text) for pattern in INJECTION_PATTERNS):
            reasons.append("prompt-injection pattern detected")
            risk = RiskLevel.CRITICAL

        normalized = combined_text.casefold()
        if any(fragment.casefold() in normalized for fragment in self.policy.blocked_path_fragments):
            reasons.append("request references a protected resource")
            risk = RiskLevel.CRITICAL

        if len(serialized) > self.policy.max_argument_characters:
            reasons.append("arguments exceed the configured size limit")
            risk = max(risk, RiskLevel.HIGH, key=_risk_rank)

        requires_approval = request.tool in self.policy.approval_tools and not reasons
        if requires_approval:
            reasons.append("tool requires human approval")
            risk = RiskLevel.MEDIUM

        decision = Decision(
            allowed=not reasons,
            risk=risk,
            reasons=tuple(reasons) or ("request satisfies policy",),
            requires_approval=requires_approval,
        )
        self.audit.record(session_id, request, decision)
        return decision

    def reset_session(self, session_id: str) -> None:
        self._action_counts.pop(session_id, None)


def _risk_rank(risk: RiskLevel) -> int:
    return list(RiskLevel).index(risk)
