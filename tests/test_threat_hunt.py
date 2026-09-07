from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_threat_hunt_search_and_summary():
    raws = [
        'src=172.16.10.1 dst=172.16.10.50 sport=5001 dport=443 action=accept proto=tcp',
        'src=172.16.10.1 dst=172.16.10.50 sport=5002 dport=443 action=accept proto=tcp',
        'src=172.16.10.1 dst=172.16.10.50 sport=5003 dport=443 action=accept proto=tcp',
    ]
    for raw in raws:
        r = client.post('/api/pipeline/process', json={'source': 'hunt-test', 'raw': raw})
        assert r.status_code == 200

    search = client.post('/api/threat-hunt/search', json={
        'source': 'hunt-test',
        'src_ip': '172.16.10.1',
        'dst_ip': '172.16.10.50',
        'action': 'accept',
        'limit': 20,
    })
    assert search.status_code == 200
    data = search.json()
    assert data['count'] >= 3
    assert data['summary']['total'] >= 3

    summary = client.get('/api/threat-hunt/summary')
    assert summary.status_code == 200
    assert summary.json()['total'] >= 3


def test_threat_hunt_correlation_and_timeline():
    corr = client.get('/api/threat-hunt/correlation', params={
        'src_ip': '172.16.10.1',
        'dst_ip': '172.16.10.50',
        'window_seconds': 300,
        'limit': 100,
    })
    assert corr.status_code == 200
    data = corr.json()
    assert data['event_count'] >= 3
    assert any(x['relationship'] == '172.16.10.1 → 172.16.10.50' for x in data['top_edges'])
    assert any(x['source_ip'] == '172.16.10.1' for x in data['bursts'])

    timeline = client.get('/api/threat-hunt/timeline', params={'source': 'hunt-test', 'limit': 50})
    assert timeline.status_code == 200
    assert timeline.json()['count'] >= 3
    assert all('event_id' in x and 'timestamp' in x for x in timeline.json()['timeline'][:3])
