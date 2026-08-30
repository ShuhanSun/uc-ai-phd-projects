# Threat Model and Evaluation Plan

## Scope

The protected system is a tool-using agent where model output is untrusted data.
The gateway is the reference monitor between that output and real tool adapters.
The tool executor, approval UI, identity provider, operating-system sandbox, and
model provider are outside this package and must provide their own controls.

## Assets and trust boundaries

| Asset | Primary concern | Boundary control |
| --- | --- | --- |
| Credentials and private files | Confidentiality | Protected-resource rules plus executor sandbox |
| Files, messages, and external APIs | Integrity | Tool allowlist, strict schemas, human approval |
| Tool quota and compute | Availability/cost | Per-session action and argument budgets |
| Human authorization | Authenticity | Signed, expiring, request-bound, single-use token |
| Decision evidence | Integrity/privacy | Argument digest and optionally keyed audit chain |

Inputs from users, retrieved pages, files, tool results, and the model are
untrusted. Policy configuration, approval keys, and tool implementations are
trusted. A production deployment should isolate those trusted components from
the agent process.

## Abuse cases

| ID | Attack | Implemented mitigation | Residual risk |
| --- | --- | --- | --- |
| T1 | Model selects a powerful undeclared tool | Default-deny capability allowlist | A broadly scoped allowed tool can still be abused |
| T2 | Retrieved text asks the model to ignore policy | Injection indicators over context and arguments | Obfuscation and semantic attacks evade patterns |
| T3 | Model supplies missing, extra, or wrong-type arguments | Per-tool strict schemas without coercion | Semantic validity remains tool-specific |
| T4 | Agent reads credentials or sensitive OS files | Configurable protected fragments | Aliases, links, encoding, and TOCTOU require executor controls |
| T5 | Agent performs a consequential side effect | Human-approval-only tools | Reviewer fatigue and compromised reviewer identity |
| T6 | Approval is replayed or applied to changed arguments | HMAC signature, expiry, request/session binding, one-time use | In-memory replay state is not distributed or durable |
| T7 | Agent loops to exhaust cost or quota | Session action budget and argument-size limit | Distributed sessions can evade local counters |
| T8 | Audit history is modified | Chained digests; optional HMAC authenticity | Key theft, deletion, truncation, and storage compromise |

## Security invariants

1. A tool outside the policy is never returned as allowed.
2. An approval-only tool is allowed only with a valid token for the exact tool,
   exact arguments, and exact session.
3. Model-generated values are never silently coerced to fit a tool schema.
4. Raw arguments are never written to the audit log.
5. Reusing an accepted approval token fails within the authority instance.
6. Exceeding a session budget produces a blocked decision before rule evaluation.

The unit tests encode these invariants. They are necessary but not sufficient
evidence: deployment tests must also verify that **all** tool execution paths go
through the gateway.

## Evaluation plan

Build a labeled corpus containing benign tasks and attacks, including spelling
variation, Unicode confusables, encoded instructions, multilingual attacks,
indirect injections in retrieved content, path traversal, symlinks, oversized
payloads, approval replay, token tampering, and cross-session token use. Report:

- attack block rate and false-negative rate by abuse-case category;
- benign pass rate and false-positive rate by tool;
- approval completion and rejection rates;
- p50/p95 decision latency and throughput;
- budget enforcement accuracy under concurrent sessions; and
- audit verification success after mutation, insertion, reordering, or deletion.

Do not tune and report on the same corpus. Version the policy, test set, and
gateway together so results are reproducible.

## Production hardening backlog

- Normalize Unicode and resolve paths inside an OS sandbox before authorization.
- Replace pattern-only injection detection with layered classifiers and taint
  tracking while retaining deterministic rules as a backstop.
- Store counters and consumed approval nonces atomically in a shared database.
- Authenticate approvers, record the policy version, and require two reviewers
  for critical actions.
- Send HMAC-chained logs to append-only remote storage with signed checkpoints to
  detect truncation.
- Add per-tool rate, destination, data-loss-prevention, and output-validation
  rules, plus emergency revocation and incident-response procedures.
