import pytest

from fll_governance.audit import AuditLogger
from fll_governance.engine import Decision, GovernanceEngine, Policy


@pytest.fixture()
def engine(tmp_path):
    policy = Policy(name="test", checks=[
        {"check": "pii", "action": "redact", "kinds": ["ssn"], "replacement": "[REDACTED]"},
        {"check": "required_disclaimer", "phrase": "not legal advice"},
        {"check": "banned_topics", "topics": ["admit fault"]},
        {"check": "min_confidence", "threshold": 0.7},
    ])
    return GovernanceEngine([policy], audit=AuditLogger(tmp_path / "audit.db"))


def test_allow_clean_output(engine):
    v = engine.evaluate("Here is a summary. This is not legal advice.", context={"confidence": 0.9})
    assert v.decision == Decision.ALLOW
    assert v.ok


def test_pii_redacted(engine):
    v = engine.evaluate("Client SSN is 123-45-6789. Not legal advice.", context={"confidence": 0.9})
    assert v.decision == Decision.REDACT
    assert "[REDACTED]" in v.output
    assert "123-45-6789" not in v.output


def test_missing_disclaimer_blocks(engine):
    v = engine.evaluate("File the motion by Friday.")
    assert v.decision == Decision.BLOCK
    assert v.output == ""


def test_banned_topic_blocks(engine):
    v = engine.evaluate("You should admit fault now. Not legal advice.", context={"confidence": 0.9})
    assert v.decision == Decision.BLOCK


def test_low_confidence_escalates(engine):
    v = engine.evaluate("Summary. Not legal advice.", context={"confidence": 0.4})
    assert v.decision == Decision.ESCALATE


def test_audit_chain_valid(engine, tmp_path):
    engine.evaluate("Clean. Not legal advice.", context={"confidence": 0.9})
    engine.evaluate("SSN 123-45-6789. Not legal advice.", context={"confidence": 0.9})
    assert engine.audit.verify_chain()


def test_audit_chain_detects_tampering(engine):
    import sqlite3
    engine.evaluate("Clean. Not legal advice.", context={"confidence": 0.9})
    with sqlite3.connect(engine.audit.db_path) as conn:
        conn.execute("UPDATE events SET decision = 'BLOCK'")
    assert not engine.audit.verify_chain()


def test_from_dir_loads_repo_policies():
    from pathlib import Path
    policy_dir = Path(__file__).resolve().parent.parent / "policies"
    eng = GovernanceEngine.from_dir(policy_dir)
    assert len(eng.policies) == 2
