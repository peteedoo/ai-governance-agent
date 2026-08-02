"""FastAPI service mode: expose the governance engine over HTTP.

Run:
    pip install -e ".[serve]"
    uvicorn fll_governance.service:app --host 0.0.0.0 --port 8100

Endpoints:
    POST /evaluate      — evaluate an LLM output against loaded policies
    GET  /audit/verify  — verify hash-chain integrity
    GET  /audit/tail    — most recent audit events
    GET  /healthz       — liveness probe
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .audit import AuditLogger
from .engine import GovernanceEngine

POLICY_DIR = os.environ.get("FLL_POLICY_DIR", "policies")
AUDIT_DB = os.environ.get("FLL_AUDIT_DB", "audit.db")

app = FastAPI(title="FLL AI Governance Agent", version="0.1.0")
_engine: GovernanceEngine | None = None


def get_engine() -> GovernanceEngine:
    global _engine
    if _engine is None:
        _engine = GovernanceEngine.from_dir(POLICY_DIR, audit=AuditLogger(AUDIT_DB))
    return _engine


class EvaluateRequest(BaseModel):
    output: str = Field(..., description="Raw LLM output text to evaluate")
    context: dict[str, Any] = Field(default_factory=dict,
                                    description="e.g. {'confidence': 0.85}")


class FindingOut(BaseModel):
    check: str
    decision: str
    detail: str


class EvaluateResponse(BaseModel):
    decision: str
    ok: bool
    latency_ms: float
    event_id: str | None
    findings: list[FindingOut]
    output: str


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@app.post("/evaluate", response_model=EvaluateResponse)
def evaluate(req: EvaluateRequest) -> EvaluateResponse:
    engine = get_engine()
    verdict = engine.evaluate(req.output, context=req.context)
    return EvaluateResponse(
        decision=verdict.decision.value,
        ok=verdict.ok,
        latency_ms=round(verdict.latency_ms, 2),
        event_id=verdict.event_id,
        findings=[FindingOut(check=f.check, decision=f.decision.value, detail=f.detail)
                  for f in verdict.findings],
        output=verdict.output,
    )


@app.get("/audit/verify")
def audit_verify() -> dict:
    engine = get_engine()
    if engine.audit is None:
        raise HTTPException(status_code=503, detail="audit logger not configured")
    return {"chain_valid": engine.audit.verify_chain()}


@app.get("/audit/tail")
def audit_tail(n: int = 10) -> list[dict]:
    engine = get_engine()
    if engine.audit is None:
        raise HTTPException(status_code=503, detail="audit logger not configured")
    return engine.audit.tail(n)
