import json
from fastapi.testclient import TestClient
from backend.app.main import app, db

client=TestClient(app)

def _seed_event():
    r=client.post('/api/pipeline/process',json={"source":"risk-test","raw":"action=deny src_ip=10.1.1.2 dst_ip=10.1.1.3 dport=443 proto=tcp","idempotency_key":"risk-test-001"})
    assert r.status_code in (200,201)
    return r.json()["event_id"]

def test_event_risk_and_summary():
    eid=_seed_event()
    r=client.post(f'/api/risk/event/{eid}')
    assert r.status_code==200
    data=r.json()
    assert data['risk_id'].startswith('RISK-')
    assert 0<=data['score']<=100
    assert data['factors']
    s=client.get('/api/risk/summary')
    assert s.status_code==200
    assert 'bands' in s.json()
