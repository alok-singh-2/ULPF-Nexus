import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_storage_catalog_and_adapters():
    c = client.get('/api/storage/catalog')
    assert c.status_code == 200
    assert 'sources' in c.json()
    a = client.get('/api/storage/adapters')
    assert a.status_code == 200
    names = {x['name'] for x in a.json()['adapters']}
    assert {'sqlite','postgresql','opensearch','clickhouse'} <= names


def test_storage_search_and_analytics():
    r = client.post('/api/storage/events/search', json={'q':'action=accept','limit':20})
    assert r.status_code == 200
    a = client.get('/api/storage/analytics?window_hours=24')
    assert a.status_code == 200
    assert 'by_source' in a.json() and 'by_format' in a.json()


def test_retention_dry_run():
    r = client.post('/api/storage/retention/apply?dry_run=true')
    assert r.status_code == 200
    d = r.json()
    assert d['dry_run'] is True
    assert 'cutoff' in d


def test_archived_not_found_safe():
    r = client.get('/api/storage/archive/not-a-real-event')
    assert r.status_code == 404
