"""CLI: evaluate a single LLM output against the loaded policies.

Usage:
    python -m fll_governance --policies policies/ "output text to evaluate"
    python -m fll_governance --policies policies/ --file output.txt --confidence 0.5
    python -m fll_governance --policies policies/ --verify-audit
"""

from __future__ import annotations

import argparse
import json
import sys

from .audit import AuditLogger
from .engine import GovernanceEngine


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="fll-governance",
                                     description="FLL AI governance policy enforcement layer")
    parser.add_argument("--policies", required=True, help="directory of YAML policy files")
    parser.add_argument("--file", help="read LLM output from file instead of argv")
    parser.add_argument("--confidence", type=float, help="model self-reported confidence (0-1)")
    parser.add_argument("--audit-db", default="audit.db")
    parser.add_argument("--verify-audit", action="store_true",
                        help="verify the audit chain integrity and exit")
    parser.add_argument("text", nargs="?", help="LLM output to evaluate")
    args = parser.parse_args(argv)

    audit = AuditLogger(args.audit_db)

    if args.verify_audit:
        ok = audit.verify_chain()
        print("audit chain:", "VALID" if ok else "TAMPERED")
        return 0 if ok else 1

    text = args.text
    if args.file:
        text = open(args.file).read()
    if not text:
        parser.error("provide output text via argv or --file")

    engine = GovernanceEngine.from_dir(args.policies, audit=audit)
    context = {}
    if args.confidence is not None:
        context["confidence"] = args.confidence
    verdict = engine.evaluate(text, context=context)

    print(json.dumps({
        "decision": verdict.decision.value,
        "ok": verdict.ok,
        "latency_ms": round(verdict.latency_ms, 2),
        "event_id": verdict.event_id,
        "findings": [{"check": f.check, "decision": f.decision.value, "detail": f.detail}
                     for f in verdict.findings],
        "output": verdict.output,
    }, indent=2))
    return 0 if verdict.ok else 2


if __name__ == "__main__":
    sys.exit(main())
