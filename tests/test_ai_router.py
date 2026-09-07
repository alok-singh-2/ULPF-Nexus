import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fastapi.testclient import TestClient
from backend.app.main import app

client=TestClient(app)

def test_ai_router_deterministic():
    r=client.post('/api/ai/route',json={'raw':'src=10.0.0.1 dst=10.0.0.2 dport=443 action=accept proto=tcp'})
    assert r.status_code==200
    assert r.json()['route'] in {'deterministic','lightweight-local'}
    assert r.json()['deterministic_confidence'] > 0.9

def test_ai_metrics_and_decision_audit():
    r=client.get('/api/ai/metrics')
    assert r.status_code==200
    assert 'thresholds' in r.json()
    d=client.get('/api/ai/decisions?limit=10')
    assert d.status_code==200
    assert d.json()
