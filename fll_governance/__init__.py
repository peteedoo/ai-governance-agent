"""Faulty Link Labs — AI Governance Agent.

A policy-enforcement layer for LLM outputs: guardrails, compliance checks,
and tamper-evident audit trails.
"""

from .engine import GovernanceEngine, Verdict, Decision

__all__ = ["GovernanceEngine", "Verdict", "Decision"]
__version__ = "0.1.0"
