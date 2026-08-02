"""Built-in guardrail checks. Each check is a pure function:

    fn(text: str, context: dict, spec: dict) -> Iterable[Finding]

Register new checks by adding them to REGISTRY at the bottom.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from .engine_types import Decision, Finding

# --- PII patterns (kept deliberately conservative) ---
_PATTERNS = {
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "phone": re.compile(r"\b(?:\+1[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
}


def pii(text: str, context: dict, spec: dict) -> Iterable[Finding]:
    """Detect and optionally redact personally identifiable information."""
    kinds = spec.get("kinds", list(_PATTERNS))
    mode = spec.get("action", "redact")  # redact | block | escalate
    for kind in kinds:
        pattern = _PATTERNS.get(kind)
        if not pattern:
            continue
        for match in pattern.finditer(text):
            yield Finding(f"pii.{kind}",
                          Decision[mode.upper()],
                          match.group(0))


def required_disclaimer(text: str, context: dict, spec: dict) -> Iterable[Finding]:
    """Block outputs missing a mandatory disclaimer (e.g., 'not legal advice')."""
    phrase = spec.get("phrase", "not legal advice")
    if phrase.lower() not in text.lower():
        yield Finding("required_disclaimer", Decision.BLOCK,
                      f"missing required disclaimer: '{phrase}'")


def unauthorized_practice_of_law(text: str, context: dict, spec: dict) -> Iterable[Finding]:
    """Escalate phrasing that could constitute legal advice (UPL risk)."""
    triggers = spec.get("triggers", [
        r"\byou should sue\b", r"\byou must file\b", r"\bi (?:recommend|advise) you (?:to )?sue\b",
        r"\byou are (?:legally )?(?:entitled|obligated)\b", r"\bthis constitutes legal advice\b",
    ])
    for trigger in triggers:
        m = re.search(trigger, text, re.IGNORECASE)
        if m:
            yield Finding("upl_risk", Decision.ESCALATE, m.group(0))


def banned_topics(text: str, context: dict, spec: dict) -> Iterable[Finding]:
    """Block outputs touching forbidden topics outright."""
    for topic in spec.get("topics", []):
        if topic.lower() in text.lower():
            yield Finding("banned_topic", Decision.BLOCK, f"forbidden topic: {topic}")


def min_confidence(text: str, context: dict, spec: dict) -> Iterable[Finding]:
    """Escalate if the model's self-reported confidence is below threshold."""
    threshold = spec.get("threshold", 0.7)
    confidence = context.get("confidence")
    if confidence is not None and confidence < threshold:
        yield Finding("min_confidence", Decision.ESCALATE,
                      f"confidence {confidence:.2f} < threshold {threshold:.2f}")


REGISTRY = {
    "pii": pii,
    "required_disclaimer": required_disclaimer,
    "unauthorized_practice_of_law": unauthorized_practice_of_law,
    "banned_topics": banned_topics,
    "min_confidence": min_confidence,
}
