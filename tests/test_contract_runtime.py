from fastapi.testclient import TestClient
from backend.app.main import app, db, init_db
import json

init_db()
client = TestClient(app)

def test_contract_execute_seed():
    r = client.get("/api/parsers")
    assert r.status_code == 200
    parser = r.json()[0]
    # compile a fresh contract from known samples
    c = client.post("/api/parsers/compile-contract", json={"raw_samples":["src=10.1.1.1 dst=10.1.1.2 sport=1234 dport=443 action=accept proto=tcp"],"source":"runtime-test","name":"runtime-test"})
    assert c.status_code == 200
    payload = c.json()
    contract_id = payload.get("contract_id") or payload.get("id")
    assert contract_id
    e = client.post("/api/contracts/execute", json={"raw":"src=10.1.1.1 dst=10.1.1.2 sport=1234 dport=443 action=accept proto=tcp","contract_id":contract_id})
    assert e.status_code == 200
    out=e.json()
    assert out["coverage"] > 0.9
    assert out["normalized"]["source.ip"] == "10.1.1.1"
    assert out["normalized"]["destination.port"] == 443
    assert out["raw_sha256"]

def test_contract_unknown_preserved():
    c = client.post("/api/parsers/compile-contract", json={"raw_samples":["src=10.1.1.1 vendor_magic=xyz action=accept"],"source":"runtime-test-unknown","name":"runtime-test-unknown"})
    assert c.status_code == 200
    contract_id=c.json().get("contract_id")
    e=client.post("/api/contracts/execute", json={"raw":"src=10.1.1.1 vendor_magic=xyz action=accept","contract_id":contract_id})
    assert e.status_code == 200
    out=e.json()
    assert out["extensions"]["vendor_magic"] == "xyz"
