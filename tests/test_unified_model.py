import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))
from app.main import app, init_db, db, build_translation_artifact, _finalize_event_pipeline, ProcessRequest
from fastapi.testclient import TestClient

init_db()
client=TestClient(app)

def test_unified_registry_and_artifact():
    ev = _finalize_event_pipeline(ProcessRequest(source='unified-test', raw='action=accept src=10.5.1.1 dst=10.5.1.2 sport=1234 dport=443 proto=tcp'))
    ref = client.get('/api/model/events/'+ev['event_id'])
    assert ref.status_code == 200
    assert ref.json()['schema_id'] == 'ulpf-event-v1'
    assert ref.json()['artifact_id']
    arts = client.get('/api/model/artifacts').json()
    assert any(a['artifact_id'] == ref.json()['artifact_id'] for a in arts)
    reg=client.get('/api/model/registry').json()
    assert reg['schemas']
    assert reg['parsers']
