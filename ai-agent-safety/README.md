# AI Agent Safety Gateway

A small, dependency-free reference project for studying **defense in depth for
tool-using AI agents**. The gateway sits between an agent and its tools and makes
an explicit decision before an action can run. It does not claim to make an LLM
perfectly safe; it demonstrates controls that reduce risk and create evidence for
evaluation.

## Safety model

The project implements five complementary controls:

1. **Least privilege:** only explicitly allowlisted tools are available.
2. **Prompt-injection screening:** common attempts to replace system policy are
   rejected, including attacks embedded in tool arguments or retrieved context.
3. **Protected-resource rules:** requests for credentials, secrets, or sensitive
   operating-system paths are blocked.
4. **Human approval:** consequential tools such as email and file writes return
   `needs_approval` rather than executing automatically.
5. **Budgets and auditability:** each session has an action limit, and decisions
   are logged with a hash of arguments rather than their potentially sensitive
   contents.

```text
user / environment -> AI agent -> SafetyGateway -> decision -> tool executor
                                      |
                                      +-----------> audit log
```

## Run the demo

Python 3.10 or newer is required. No runtime dependencies are needed.

```bash
cd ai-agent-safety
python -m agent_safety.cli calculator --arguments '{"expression":"12 * 4"}'
python -m agent_safety.cli send_email --arguments '{"to":"team@example.test"}'
python -m agent_safety.cli read_file --arguments '{"path":"~/.ssh/id_rsa"}'
```

When running directly from a checkout, either install the project with
`python -m pip install -e .` or prefix the commands with `PYTHONPATH=src`.

Example allowed result:

```json
{
  "status": "allowed",
  "risk": "low",
  "reasons": ["request satisfies policy"]
}
```

## Integrate with an agent

Every proposed tool call must pass through the gateway. Only dispatch when
`decision.allowed` is true; an approval decision should go to a separate,
authenticated human workflow.

```python
from agent_safety import SafetyGateway, ToolRequest

gateway = SafetyGateway()
request = ToolRequest("search", {"query": "agent safety evaluations"})
decision = gateway.evaluate(request, session_id="research-42")

if decision.allowed:
    result = tool_registry[request.tool](**request.arguments)
elif decision.requires_approval:
    approval_queue.submit(request)
else:
    raise PermissionError(decision.reasons)
```

## Test and extend

```bash
python -m pip install pytest
pytest
```

Useful research extensions include semantic injection classifiers, taint
tracking for retrieved content, signed approval tokens, per-tool JSON schemas,
and benchmark datasets measuring false-positive and false-negative rates.

## Limitations and responsible use

- Pattern matching is illustrative and cannot detect every prompt injection.
- This package evaluates calls but intentionally does not execute tools or build
  an approval service.
- Hashing makes logs less revealing, not anonymous; production systems still
  need access controls, retention limits, encryption, and incident procedures.
- Deployments should add tool-specific validation and sandboxing. Never rely on
  an LLM's self-assessment as the only security boundary.
