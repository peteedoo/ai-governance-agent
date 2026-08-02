"""Core governance engine: loads policies, runs checks, returns a verdict."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import yaml

from . import checks as check_lib
from .audit import AuditLogger
from .engine_types import Decision, Finding


@dataclass
class Verdict:
    decision: Decision
    findings: list[Finding]
    output: str                # final (possibly redacted) text, or "" if blocked
    latency_ms: float = 0.0
    event_id: str | None = None

    @property
    def ok(self) -> bool:
        return self.decision in (Decision.ALLOW, Decision.REDACT)


@dataclass
class Policy:
    name: str
    checks: list[dict] = field(default_factory=list)

    @classmethod
    def load(cls, path: str | Path) -> "Policy":
        data = yaml.safe_load(Path(path).read_text())
        return cls(name=data.get("name", Path(path).stem), checks=data.get("checks", []))


class GovernanceEngine:
    """Evaluates LLM outputs against one or more YAML policies.

    Severity model: the strictest finding wins. BLOCK > ESCALATE > REDACT > ALLOW.
    """

    _SEVERITY = {Decision.ALLOW: 0, Decision.REDACT: 1, Decision.ESCALATE: 2, Decision.BLOCK: 3}

    def __init__(self, policies: list[Policy], audit: AuditLogger | None = None):
        self.policies = policies
        self.audit = audit
        self._registry: dict[str, Callable] = check_lib.REGISTRY

    @classmethod
    def from_dir(cls, policy_dir: str | Path, audit: AuditLogger | None = None) -> "GovernanceEngine":
        paths = sorted(Path(policy_dir).glob("*.yaml")) + sorted(Path(policy_dir).glob("*.yml"))
        if not paths:
            raise FileNotFoundError(f"No policy files found in {policy_dir}")
        return cls([Policy.load(p) for p in paths], audit=audit)

    def evaluate(self, output: str, *, context: dict | None = None) -> Verdict:
        """Run all policy checks against an LLM output string."""
        started = time.perf_counter()
        context = context or {}
        findings: list[Finding] = []
        final_text = output

        for policy in self.policies:
            for spec in policy.checks:
                name = spec["check"]
                fn = self._registry.get(name)
                if fn is None:
                    findings.append(Finding(name, Decision.ESCALATE, "unknown check — routing to human"))
                    continue
                for finding in fn(final_text, context, spec):
                    findings.append(finding)
                    if finding.decision == Decision.REDACT and "replacement" in spec:
                        final_text = final_text.replace(finding.detail, spec["replacement"])
                    if finding.decision == Decision.BLOCK:
                        final_text = ""

        decision = max((f.decision for f in findings), key=lambda d: self._SEVERITY[d], default=Decision.ALLOW)
        verdict = Verdict(decision, findings, final_text,
                          latency_ms=(time.perf_counter() - started) * 1000)
        if self.audit:
            verdict.event_id = self.audit.record(output=output, verdict=verdict, context=context)
        return verdict
