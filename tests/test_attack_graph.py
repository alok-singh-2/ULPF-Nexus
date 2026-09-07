from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)

def _seed(raw, key):
    r = client.post('/api/pipeline/process', json={'source':'attack-graph-test','raw':raw,'idempotency_key':key})
    assert r.status_code == 200
    return r.json()['event_id']

def test_attack_path_graph_endpoint():
    base='203.0.113.10'; dst='203.0.113.20'
    _seed(f'action=deny src={base} dst={dst} dport=22 proto=tcp', 'ag-1')
    _seed(f'action=accept src={base} dst={dst} dport=22 proto=tcp', 'ag-2')
    _seed(f'action=privilege_change src={base} dst={dst} dport=22 proto=tcp', 'ag-3')
    _seed(f'action=sensitive_access src={base} dst={dst} dport=443 proto=tcp', 'ag-4')
    client.post('/api/entities/rebuild')
    built=client.post('/api/attack-paths/build')
    assert built.status_code == 200
    paths=client.get('/api/attack-paths?limit=100').json()
    path=next(p for p in paths if len(p['event_ids']) >= 3)
    r=client.get(f"/api/attack-paths/{path['path_id']}/graph")
    assert r.status_code == 200
    data=r.json()
    assert data['path']['path_id'] == path['path_id']
    assert data['node_count'] >= 4
    assert any(n['type']=='event' for n in data['nodes'])
    assert any(e['relation']=='attack-sequence' for e in data['edges'])
