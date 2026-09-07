from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_security_flow_endpoint():
    r = client.get('/api/security/flow')
    assert r.status_code == 200
    body = r.json()
    assert body['air_gapped'] is True
    assert body['simulation_only'] is True


def test_security_orchestrator_endpoint():
    r = client.post('/api/security/orchestrate', json={
        'detection_limit': 100,
        'correlation_limit': 100,
        'attack_path_refresh': False,
        'auto_response': True,
        'analyst': 'test-suite',
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body['air_gapped'] is True
    assert body['simulation_only'] is True
    assert 'flow' in body
    assert body['flow'][0] == 'detect'
