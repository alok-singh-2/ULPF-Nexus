from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def login():
    r = client.post('/api/auth/login', json={'username': 'admin', 'password': 'change-me'})
    assert r.status_code == 200, r.text
    return {'Authorization': 'Bearer ' + r.json()['access_token']}


def test_health_and_readiness():
    assert client.get('/api/health').status_code == 200
    assert client.get('/api/ready').status_code == 200
    assert client.get('/api/security/health/components').status_code == 200


def test_auth_and_rbac_config():
    headers = login()
    r = client.get('/api/security/config', headers=headers)
    assert r.status_code == 200
    r = client.post('/api/security/config', headers=headers, json={'key': 'demo_mode', 'value': 'on', 'secret': False})
    assert r.status_code == 200


def test_tamper_evident_audit_chain():
    headers = login()
    client.post('/api/security/config', headers=headers, json={'key': 'audit_test', 'value': 'v1'})
    r = client.post('/api/security/audit/verify', headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()['valid'] is True
