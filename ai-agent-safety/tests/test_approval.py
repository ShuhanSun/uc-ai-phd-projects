from agent_safety import ApprovalAuthority, SafetyGateway, ToolRequest


SECRET = b"a-test-secret-that-is-at-least-32-bytes-long"


def test_request_bound_approval_allows_action_once() -> None:
    authority = ApprovalAuthority(SECRET, clock=lambda: 1_000)
    request = ToolRequest("write_file", {"path": "report.txt", "content": "safe"})
    token = authority.issue(request, "session-a", nonce="review-123")
    gateway = SafetyGateway()

    approved = gateway.evaluate(
        request,
        "session-a",
        approval_token=token,
        approval_authority=authority,
    )
    replay = gateway.evaluate(
        request,
        "session-a",
        approval_token=token,
        approval_authority=authority,
    )

    assert approved.allowed
    assert approved.status == "allowed"
    assert replay.status == "needs_approval"
    assert "already used" in replay.reasons[0]


def test_approval_cannot_authorize_modified_arguments() -> None:
    authority = ApprovalAuthority(SECRET, clock=lambda: 1_000)
    reviewed = ToolRequest("write_file", {"path": "report.txt", "content": "safe"})
    changed = ToolRequest("write_file", {"path": "report.txt", "content": "changed"})
    token = authority.issue(reviewed, "session-a", nonce="review-456")

    decision = SafetyGateway().evaluate(
        changed,
        "session-a",
        approval_token=token,
        approval_authority=authority,
    )

    assert decision.status == "needs_approval"
    assert "does not match" in decision.reasons[0]


def test_expired_approval_is_rejected() -> None:
    now = [1_000]
    authority = ApprovalAuthority(SECRET, clock=lambda: now[0])
    request = ToolRequest("write_file", {"path": "report.txt", "content": "safe"})
    token = authority.issue(request, "session-a", nonce="review-789", ttl_seconds=10)
    now[0] = 1_011

    decision = SafetyGateway().evaluate(
        request,
        "session-a",
        approval_token=token,
        approval_authority=authority,
    )

    assert decision.status == "needs_approval"
    assert "expired" in decision.reasons[0]


def test_tampered_and_cross_session_approvals_are_rejected() -> None:
    authority = ApprovalAuthority(SECRET, clock=lambda: 1_000)
    request = ToolRequest("write_file", {"path": "report.txt", "content": "safe"})
    token = authority.issue(request, "session-a", nonce="review-abc")
    gateway = SafetyGateway()
    payload, signature = token.split(".")
    tampered_token = f"{payload}.{'A' if signature[0] != 'A' else 'B'}{signature[1:]}"

    tampered = gateway.evaluate(
        request,
        "session-a",
        approval_token=tampered_token,
        approval_authority=authority,
    )
    wrong_session = gateway.evaluate(
        request,
        "session-b",
        approval_token=token,
        approval_authority=authority,
    )

    assert tampered.status == "needs_approval"
    assert "signature is invalid" in tampered.reasons[0]
    assert wrong_session.status == "needs_approval"
    assert "does not match" in wrong_session.reasons[0]
