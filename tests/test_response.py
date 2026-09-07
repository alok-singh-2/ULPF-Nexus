from fastapi.testclient import TestClient
from backend.app.main import app, db

client = TestClient(app)

def _event_id():
    conn = db(); row = conn.execute("SELECT event_id FROM events ORDER BY created_at DESC LIMIT 1").fetchone(); conn.close()
    assert row
    return row["event_id"]

def test_response_recommendation_requires_approval_and_executes_as_simulation():
    eid = _event_id()
    r = client.post('/api/response/recommend', json={'entity_type':'event','entity_id':eid,'analyst':'test'})
    assert r.status_code == 200
    d = r.json(); rid = d['recommendation_id']
    blocked = client.post(f'/api/response/recommendations/{rid}/execute?analyst=test')
    assert blocked.status_code == 409
    assert d['evidence']['simulation_only'] is True
    approved = client.post(f'/api/response/recommendations/{rid}/decision', json={'analyst':'test','decision':'approve','notes':'approved for demo'})
    assert approved.status_code == 200 and approved.json()['status'] == 'approved'
    executed = client.post(f'/api/response/recommendations/{rid}/execute?analyst=test')
    assert executed.status_code == 200
    assert executed.json()['status'] == 'simulated'
    assert executed.json()['result']['simulated'] is True

def test_response_recommendations_list_and_executions_are_available():
    assert client.get('/api/response/recommendations').status_code == 200
    body = client.get('/api/response/executions').json()
    assert body['simulation_only'] is True
