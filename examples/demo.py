"""Demo: wrap any LLM call with the governance layer.

Swap `fake_llm` for your real model call (OpenAI, Anthropic, local, Hermes...).
The engine sits between the model and the user.
"""

from fll_governance import Decision, GovernanceEngine
from fll_governance.audit import AuditLogger


def fake_llm(prompt: str) -> tuple[str, float]:
    """Stand-in for a real LLM. Returns (output, confidence)."""
    return (
        "Based on the lease terms, you should sue your landlord for the deposit. "
        "Reach the tenant at 303-555-0142 for corroboration. "
        "This summary is not legal advice.",
        0.62,
    )


def governed_call(prompt: str) -> str:
    raw_output, confidence = fake_llm(prompt)
    engine = GovernanceEngine.from_dir("policies", audit=AuditLogger("audit.db"))
    verdict = engine.evaluate(raw_output, context={"confidence": confidence})

    if verdict.decision == Decision.BLOCK:
        return "[blocked by governance policy — routed to attorney review]"
    if verdict.decision == Decision.ESCALATE:
        return f"[escalated for human review: {verdict.event_id}]"
    return verdict.output


if __name__ == "__main__":
    print(governed_call("Summarize my options about my landlord."))
