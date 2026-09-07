from fastapi.testclient import TestClient
from backend.app.main import app
import time

client = TestClient(app)

def test_multi_event_correlation_sequence():
    source = 'corr-test-' + str(time.time_ns())
    raws = [
        'src=10.50.0.7 dst=10.50.0.20 action=deny proto=tcp dport=22',
        'src=10.50.0.7 dst=10.50.0.20 action=accept proto=tcp dport=22',
        'src=10.50.0.7 dst=10.50.0.20 action=accept proto=tcp dport=443',
        'src=10.50.0.7 dst=10.50.0.20 action=accept proto=tcp dport=8080',
    ]
    for raw in raws:
        r = client.post('/api/pipeline/process', json={'source': source, 'raw': raw})
        assert r.status_code == 200
    body = {
        'name': 'Login → privilege → sensitive access',
        'description': 'Demonstration sequence correlation',
        'severity': 'high',
        'window_seconds': 900,
        'group_by': 'source',
        'steps': [
            {'name': 'FAILED LOGIN', 'conditions': [{'field': 'event.action', 'operator': 'eq', 'value': 'deny'}]},
            {'name': 'SUCCESSFUL LOGIN', 'conditions': [{'field': 'event.action', 'operator': 'eq', 'value': 'accept'}]},
            {'name': 'PRIVILEGE / SENSITIVE ACTION', 'conditions': [{'field': 'destination.port', 'operator': 'eq', 'value': '8080'}]},
        ],
    }
    c = client.post('/api/correlations/rules', json=body)
    assert c.status_code == 200
    assert len(c.json()['steps']) == 3
    run = client.post('/api/correlations/run')
    assert run.status_code == 200
    assert run.json()['created'] >= 1
    inc = client.get('/api/correlations/incidents', params={'limit': 20})
    assert inc.status_code == 200
    match = [x for x in inc.json()['incidents'] if x['rule_id'] == c.json()['rule_id']]
    assert match
    assert len(match[0]['step_matches']) == 3
    assert len(match[0]['event_ids']) == 3
