from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)

def _seed(raw, key):
    r = client.post('/api/pipeline/process', json={'source':'entity-test','raw':raw,'idempotency_key':key})
    assert r.status_code == 200
    return r.json()['event_id']

def test_entity_rebuild_and_neighbors():
    _seed('action=deny src=192.0.2.10 dst=192.0.2.20 dport=443 proto=tcp', 'ent-1')
    _seed('action=accept src=192.0.2.10 dst=192.0.2.20 dport=443 proto=tcp', 'ent-2')
    r = client.post('/api/entities/rebuild')
    assert r.status_code == 200
    data = r.json()
    assert data['entity_count'] >= 3
    ents = client.get('/api/entities', params={'entity_type':'ip'}).json()
    src = next(e for e in ents if e['display_name'] == '192.0.2.10')
    detail = client.get(f"/api/entities/{src['entity_id']}")
    assert detail.status_code == 200
    assert any(x['relation']=='communicates_with' for x in detail.json()['outgoing'])

def test_attack_path_detection():
    base='198.51.100.10'; dst='198.51.100.20'
    _seed(f'action=deny src={base} dst={dst} dport=22 proto=tcp', 'path-1')
    _seed(f'action=accept src={base} dst={dst} dport=22 proto=tcp', 'path-2')
    _seed(f'action=privilege_change src={base} dst={dst} dport=22 proto=tcp', 'path-3')
    _seed(f'action=sensitive_access src={base} dst={dst} dport=443 proto=tcp', 'path-4')
    client.post('/api/entities/rebuild')
    r=client.post('/api/attack-paths/build')
    assert r.status_code == 200
    paths=client.get('/api/attack-paths').json()
    assert any(len(p['event_ids'])>=3 for p in paths)
