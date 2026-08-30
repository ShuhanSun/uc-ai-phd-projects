"""Central policy-enforcement point for agent tool calls."""

import json
import re
from collections import Counter
from typing import TYPE_CHECKING

from .audit import AuditLogger
from .models import Decision, RiskLevel, ToolRequest
from .policy import SafetyPolicy
from .validation import validate_arguments

if TYPE_CHECKING:
    from .approval import ApprovalAuthority


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

    def evaluate(
        self,
        request: ToolRequest,
        session_id: str = "default",
        *,
        approval_token: str | None = None,
        approval_authority: "ApprovalAuthority | None" = None,
    ) -> Decision:
        reasons: list[str] = []
        risk = RiskLevel.LOW
        serialized = json.dumps(request.arguments, sort_keys=True, default=str)
        # Tool arguments are always model-controlled. Context is screened unless
        # the caller explicitly attests it came from a trusted policy source.
        combined_text = serialized
        if not request.context_trusted:
            combined_text = f"{request.context}\n{serialized}"

        if self._action_counts[session_id] >= self.policy.max_actions_per_session:
            decision = Decision(
                False,
                RiskLevel.HIGH,
                ("session action budget exhausted",),
                rule_ids=("BUDGET_EXHAUSTED",),
            )
            self.audit.record(session_id, request, decision)
            return decision

        self._action_counts[session_id] += 1

        if request.tool not in self.policy.allowed_tools | self.policy.approval_tools:
            reasons.append("tool is not in the capability allowlist")
            risk = RiskLevel.CRITICAL

        rule_ids: list[str] = []
        if reasons:
            rule_ids.append("CAPABILITY_DENIED")

        schema = self.policy.tool_schemas.get(request.tool)
        if schema:
            schema_errors = validate_arguments(request.arguments, schema)
            if schema_errors:
                reasons.extend(schema_errors)
                rule_ids.append("SCHEMA_INVALID")
                risk = max(risk, RiskLevel.HIGH, key=_risk_rank)

        if any(pattern.search(combined_text) for pattern in INJECTION_PATTERNS):
            reasons.append("prompt-injection pattern detected")
            rule_ids.append("PROMPT_INJECTION")
            risk = RiskLevel.CRITICAL

        normalized = combined_text.casefold()
        if any(fragment.casefold() in normalized for fragment in self.policy.blocked_path_fragments):
            reasons.append("request references a protected resource")
            rule_ids.append("PROTECTED_RESOURCE")
            risk = RiskLevel.CRITICAL

        if len(serialized) > self.policy.max_argument_characters:
            reasons.append("arguments exceed the configured size limit")
            rule_ids.append("ARGUMENT_LIMIT")
            risk = max(risk, RiskLevel.HIGH, key=_risk_rank)

        if len(request.context) > self.policy.max_context_characters:
            reasons.append("context exceeds the configured size limit")
            rule_ids.append("CONTEXT_LIMIT")
            risk = max(risk, RiskLevel.HIGH, key=_risk_rank)

        has_policy_violation = bool(reasons)
        requires_approval = (
            request.tool in self.policy.approval_tools and not has_policy_violation
        )
        if requires_approval:
            risk = RiskLevel.MEDIUM
            if approval_token and approval_authority:
                verified, approval_reason = approval_authority.consume(
                    approval_token, request, session_id
                )
                reasons.append(approval_reason)
                if verified:
                    rule_ids.append("HUMAN_APPROVAL_VERIFIED")
                    requires_approval = False
                else:
                    rule_ids.append("HUMAN_APPROVAL_INVALID")
            else:
                reasons.append("tool requires human approval")
                rule_ids.append("HUMAN_APPROVAL")

        decision = Decision(
            allowed=not has_policy_violation and not requires_approval,
            risk=risk,
            reasons=tuple(reasons) or ("request satisfies policy",),
            requires_approval=requires_approval,
            rule_ids=tuple(rule_ids),
        )
        self.audit.record(session_id, request, decision)
        return decision

    def reset_session(self, session_id: str) -> None:
        self._action_counts.pop(session_id, None)


def _risk_rank(risk: RiskLevel) -> int:
    return list(RiskLevel).index(risk)
