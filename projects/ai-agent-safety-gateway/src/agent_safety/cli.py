"""Command-line demonstration of the safety gateway."""

import argparse
import json

from .gateway import SafetyGateway
from .models import ToolRequest


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate a proposed AI-agent tool call")
    parser.add_argument("tool", help="tool the agent wants to invoke")
    parser.add_argument("--arguments", default="{}", help="tool arguments as a JSON object")
    parser.add_argument("--context", default="", help="untrusted context used by the agent")
    parser.add_argument("--session", default="cli", help="session identifier")
    args = parser.parse_args()

    arguments = json.loads(args.arguments)
    if not isinstance(arguments, dict):
        parser.error("--arguments must decode to a JSON object")

    decision = SafetyGateway().evaluate(
        ToolRequest(tool=args.tool, arguments=arguments, context=args.context),
        session_id=args.session,
    )
    print(json.dumps({
        "status": decision.status,
        "risk": decision.risk.value,
        "reasons": decision.reasons,
        "rule_ids": decision.rule_ids,
    }, indent=2))


if __name__ == "__main__":
    main()
