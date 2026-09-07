from pathlib import Path
from fastapi.testclient import TestClient
from backend.app.main import app, DATA_DIR

client = TestClient(app)


def login():
    r = client.post('/api/auth/login', json={'username': 'admin', 'password': 'change-me'})
    assert r.status_code == 200, r.text
    return {'Authorization': 'Bearer ' + r.json()['access_token']}


def test_airgap_status_and_self_test():
    r = client.get('/api/airgap/status')
    assert r.status_code == 200, r.text
    assert r.json()['air_gapped'] is True
    h = login()
    r = client.post('/api/airgap/self-test', headers=h)
    assert r.status_code == 200, r.text
    assert r.json()['passed'] is True


def test_offline_config_export_import():
    h = login()
    r = client.get('/api/airgap/config/export', headers=h)
    assert r.status_code == 200, r.text
    assert r.json()['format'] == 'ulpf-nexus-config'
    r = client.post('/api/airgap/config/import', headers=h, json={'configuration': {'demo_offline_mode': 'true'}})
    assert r.status_code == 200, r.text
    assert 'demo_offline_mode' in r.json()['keys']


def test_verified_backup_and_restore_guard(tmp_path: Path):
    h = login()
    r = client.post('/api/airgap/backup', headers=h)
    assert r.status_code == 200, r.text
    backup = r.json()['backup_path']
    assert (Path(backup) if Path(backup).is_absolute() else Path.cwd() / backup)
    # Restore must require explicit confirmation.
    r = client.post('/api/airgap/restore', headers=h, json={'backup_path': backup, 'confirm': False})
    assert r.status_code == 400
