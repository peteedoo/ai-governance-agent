import pytest

fastapi = pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from fll_governance.service import app


@pytest.fixture()
def client(tmp_path, monkeypatch):
    import fll_governance.service as svc
    from pathlib import Path
    policy_dir = Path(__file__).resolve().parent.parent / "policies"
    monkeypatch.setattr(svc, "POLICY_DIR", str(policy_dir))
    monkeypatch.setattr(svc, "AUDIT_DB", str(tmp_path / "audit.db"))
    monkeypatch.setattr(svc, "_engine", None)
    return TestClient(app)


def test_healthz(client):
    assert client.get("/healthz").json() == {"status": "ok"}


def test_evaluate_allow(client):
    r = client.post("/evaluate", json={
        "output": "Summary of the lease. This is not legal advice.",
        "context": {"confidence": 0.95},
    })
    assert r.status_code == 200
    body = r.json()
    assert body["decision"] == "ALLOW"
    assert body["ok"] is True
    assert body["event_id"]


def test_evaluate_block_missing_disclaimer(client):
    r = client.post("/evaluate", json={"output": "You should admit fault immediately."})
    assert r.json()["decision"] == "BLOCK"


def test_audit_verify_after_evaluations(client):
    client.post("/evaluate", json={"output": "Fine. This is not legal advice.",
                                   "context": {"confidence": 0.9}})
    assert client.get("/audit/verify").json() == {"chain_valid": True}


def test_audit_tail(client):
    client.post("/evaluate", json={"output": "Fine. This is not legal advice.",
                                   "context": {"confidence": 0.9}})
    events = client.get("/audit/tail").json()
    assert len(events) >= 1
    assert "decision" in events[0]
