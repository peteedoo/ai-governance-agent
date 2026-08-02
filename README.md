# FLL AI Governance Agent

**Faulty Link Labs** — a policy-enforcement layer that sits between an LLM and the end user. Every model output passes through configurable guardrails, and every decision is written to a tamper-evident, hash-chained audit trail.

Built for legal firms and malpractice-insurance workflows, where *"the model said it"* is not a defense.

## Where this fits: the two layers of agent governance

Agent security is splitting into two complementary layers, and serious deployments need both:

| Layer | Governs | Example tooling |
|---|---|---|
| **Endpoint / action layer** | What the agent *does* — tool calls, file writes, shell commands, network access | [Numbat](https://github.com/perplexityai/numbat) (Perplexity, Apache 2.0) |
| **Content / output layer** | What the agent *says* — advice phrasing, PII in text, mandated disclaimers, confidence | **This project** |

Numbat stops an agent from `curl`-ing client files off the machine. This layer stops an agent from telling a client *"you should sue."* One without the other leaves a hole an insurer will find. FLL is designed to slot into stacks that already run an endpoint layer — findings are evidence, not verdicts; monitor first, promote to enforcement deliberately.

## Why this exists

LLMs in legal/insurance contexts create three concrete liability risks:

| Risk | What it looks like | How this layer handles it |
|---|---|---|
| **PII leakage** | Client SSNs, phone numbers in model output | Automatic redaction or block |
| **Unauthorized practice of law (UPL)** | Model tells a user "you should sue" | Escalation to human review |
| **Ungrounded advice** | Low-confidence output presented as fact | Confidence-threshold escalation |
| **Accountability** | No record of what the model produced | Hash-chained SQLite audit log |

## Architecture

```
User prompt ──▶ LLM ──▶ raw output
                            │
                    GovernanceEngine
                    ┌─────┴─────┐
              Policy A     Policy B   (YAML, composable)
                    │
              Findings ──▶ strictest decision wins
                    │
        ALLOW / REDACT / BLOCK / ESCALATE
                    │
             AuditLogger (SHA-256 hash chain, SQLite)
```

- **Policies are YAML** — compliance officers can read and edit them without touching Python.
- **Checks are pure functions** — `(text, context, spec) -> findings`, trivially testable.
- **Severity model**: `BLOCK > ESCALATE > REDACT > ALLOW`. The strictest finding wins.
- **Audit chain**: each event embeds the previous event's hash. Editing or deleting any record invalidates the chain — verifiable with one command.

## Quickstart

```bash
pip install -e ".[dev]"

# Evaluate an output against all policies in policies/
python -m fll_governance --policies policies/ \
  "Reach the client at 303-555-0142. This is not legal advice." --confidence 0.9

# Run the full demo (fake LLM wrapped by the governance layer)
python examples/demo.py

# Verify audit-trail integrity
python -m fll_governance --policies policies/ --verify-audit

# Tests
pytest
```

## Decisions

| Decision | Meaning | Who sees the output |
|---|---|---|
| `ALLOW` | Clean | End user, as generated |
| `REDACT` | PII removed automatically | End user, sanitized |
| `ESCALATE` | Risky (UPL phrasing, low confidence, unknown check) | Human reviewer only, with `event_id` |
| `BLOCK` | Hard stop (missing disclaimer, banned topic) | No one — never leaves the system |

## Built-in checks

- `pii` — SSN, credit card, email, phone (per-kind action: redact / block / escalate)
- `required_disclaimer` — blocks output missing a mandated phrase (e.g., "not legal advice")
- `unauthorized_practice_of_law` — regex triggers on advice-style phrasing → escalate
- `banned_topics` — hard block on configurable topics
- `min_confidence` — escalates when model self-confidence is below a threshold

## Writing a policy

```yaml
name: my-firm-policy
checks:
  - check: pii
    action: redact
    kinds: [ssn]
    replacement: "[REDACTED]"
  - check: min_confidence
    threshold: 0.8
```

## Writing a custom check

```python
# fll_governance/checks.py
def my_check(text, context, spec):
    if "magic word" in text:
        yield Finding("my_check", Decision.ESCALATE, "found magic word")

REGISTRY["my_check"] = my_check
```

## Integration

The engine is model-agnostic. Wrap any client call:

```python
engine = GovernanceEngine.from_dir("policies", audit=AuditLogger("audit.db"))
verdict = engine.evaluate(llm_output, context={"confidence": score})
```

Designed to be adopted as the guardrail layer for the Hermes agent framework once Hermes stabilizes; the interface is one function call.

## HTTP service mode

```bash
pip install -e ".[serve]"
uvicorn fll_governance.service:app --port 8100
```

| Endpoint | Method | Purpose |
|---|---|---|
| `/evaluate` | POST | `{"output": "...", "context": {"confidence": 0.9}}` → verdict JSON |
| `/audit/verify` | GET | `{"chain_valid": true}` — audit integrity check |
| `/audit/tail?n=10` | GET | most recent audit events |
| `/healthz` | GET | liveness probe |

Configure with env vars: `FLL_POLICY_DIR` (default `policies/`), `FLL_AUDIT_DB` (default `audit.db`).

## Roadmap

- [x] FastAPI service mode (HTTP endpoint for evaluate/verify)
- [ ] Vector-similarity check against approved-answer banks
- [ ] Policy version pinning in audit events
- [ ] Export audit trail to insurer-friendly formats (CSV/PDF)

## License

MIT — © Faulty Link Labs (Ryan Oldfield)
