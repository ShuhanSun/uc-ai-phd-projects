import pytest

from agent_safety import SafetyGateway, SafetyPolicy, ToolRequest, ToolSchema


@pytest.mark.parametrize(
    ("arguments", "reason"),
    [
        ({}, "missing required argument: query"),
        ({"query": 42}, "argument query must be str"),
        ({"query": "safety", "limit": 10}, "unexpected argument: limit"),
    ],
)
def test_schema_rejects_malformed_arguments(arguments: dict, reason: str) -> None:
    decision = SafetyGateway().evaluate(ToolRequest("search", arguments))

    assert decision.status == "blocked"
    assert reason in decision.reasons
    assert "SCHEMA_INVALID" in decision.rule_ids


def test_custom_tool_requires_a_schema() -> None:
    with pytest.raises(ValueError, match="need schemas"):
        SafetyPolicy(allowed_tools=frozenset({"custom"}))


def test_custom_schema_can_be_supplied() -> None:
    policy = SafetyPolicy(
        allowed_tools=frozenset({"custom"}),
        approval_tools=frozenset(),
        tool_schemas={"custom": ToolSchema(frozenset({"value"}), {"value": int})},
    )

    assert SafetyGateway(policy).evaluate(ToolRequest("custom", {"value": 2})).allowed
