from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_investigation_search_and_bundle():
    r = client.post('/api/pipeline/process', json={
        'source': 'investigation-test',
        'raw': 'src=10.91.1.2 dst=10.91.1.3 sport=1234 dport=443 action=accept proto=tcp',
        'idempotency_key': 'investigation-001'
    })
    assert r.status_code == 200
    event_id = r.json()['event_id']

    s = client.get('/api/investigation/search', params={'q': event_id})
    assert s.status_code == 200
    assert any(x['event_id'] == event_id for x in s.json())

    b = client.get(f'/api/investigation/{event_id}')
    assert b.status_code == 200
    data = b.json()
    assert data['event']['event_id'] == event_id
    assert data['integrity']['raw_sha256_matches'] is True
    assert data['forensic_trace'] is not None
    assert 'model_ref' in data

    v = client.post(f'/api/investigation/{event_id}/verify')
    assert v.status_code == 200
    assert v.json()['raw_integrity'] is True
