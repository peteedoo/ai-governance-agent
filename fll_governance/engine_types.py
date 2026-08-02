"""Shared types, kept separate to avoid circular imports between engine and checks."""

from dataclasses import dataclass
from enum import Enum


class Decision(str, Enum):
    ALLOW = "ALLOW"
    REDACT = "REDACT"
    BLOCK = "BLOCK"
    ESCALATE = "ESCALATE"


@dataclass
class Finding:
    check: str
    decision: Decision
    detail: str
