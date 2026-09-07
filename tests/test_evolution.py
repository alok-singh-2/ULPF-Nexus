from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_evolution_command_center_run():
    payload = {
        "source": "test-evolution-source",
        "candidate_name": "test-evolution-parser",
        "samples": [
            "src_addr=10.50.1.7 dst_addr=10.50.2.9 source_port=51001 destination_port=443 decision=accept transport=tcp",
            "src_addr=10.50.1.8 dst_addr=10.50.2.9 source_port=51002 destination_port=443 decision=deny transport=tcp",
        ],
    }
    r = client.post('/api/evolution/run', json=payload)
    assert r.status_code == 200
    body = r.json()
    assert body['run_id'].startswith('EVR-')
    assert body['final_state'] in {'trusted', 'candidate-ready', 'review', 'quarantine'}


def test_evolution_control_center():
    r = client.get('/api/evolution/control-center')
    assert r.status_code == 200
    body = r.json()
    assert 'states' in body and 'routes' in body and 'mutations' in body and 'recent' in body
