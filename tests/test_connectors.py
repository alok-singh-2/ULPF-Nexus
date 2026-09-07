from fastapi.testclient import TestClient
from app.main import app


def test_http_connector_register_health_and_receive():
    with TestClient(app) as client:
        r = client.post('/api/connectors', json={
            'name': 'test-http-connector',
            'connector_type': 'http',
            'source': 'test-firewall',
            'config': {'endpoint': 'http://127.0.0.1:9000/events'},
            'enabled': True,
        })
        assert r.status_code == 200
        connector = r.json()
        cid = connector['connector_id']
        assert connector['status'] == 'healthy'

        h = client.get('/api/connectors/health')
        assert h.status_code == 200
        assert any(x['connector_id'] == cid for x in h.json()['connectors'])

        received = client.post(f'/api/connectors/{cid}/receive', json={
            'raw': 'src=10.50.0.1 dst=10.50.0.2 dport=443 action=accept proto=tcp',
            'process': True,
            'metadata': {'test': True},
        })
        assert received.status_code == 200
        assert received.json()['accepted'] is True
        assert received.json()['event_id']

        events = client.get(f'/api/connectors/{cid}/events')
        assert events.status_code == 200
        assert events.json()[0]['status'] == 'accepted'


def test_connector_disable_blocks_receive():
    with TestClient(app) as client:
        r = client.post('/api/connectors', json={
            'name': 'disabled-test', 'connector_type': 'http', 'source': 'disabled-source',
            'config': {}, 'enabled': True,
        })
        cid = r.json()['connector_id']
        d = client.post(f'/api/connectors/{cid}/enable', json={'enabled': False})
        assert d.status_code == 200 and d.json()['status'] == 'disabled'
        blocked = client.post(f'/api/connectors/{cid}/receive', json={'raw': 'action=accept', 'process': False})
        assert blocked.status_code == 409


def test_udp_connector_live_runtime_start_stop():
    with TestClient(app) as client:
        import socket, time
        probe_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); probe_sock.bind(('127.0.0.1', 0)); port = probe_sock.getsockname()[1]; probe_sock.close()
        r = client.post('/api/connectors', json={
            'name': 'live-udp-test', 'connector_type': 'syslog_udp', 'source': 'live-udp',
            'config': {'host': '127.0.0.1', 'port': port}, 'enabled': True,
        })
        assert r.status_code == 200
        cid = r.json()['connector_id']
        started = client.post(f'/api/connectors/{cid}/start')
        assert started.status_code == 200 and started.json()['started'] is True
        for _ in range(40):
            status = client.get('/api/connectors/runtime').json()['running']
            if any(x['connector_id'] == cid and x['type'] == 'syslog_udp' for x in status): break
            time.sleep(0.05)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(b'<134>1 demo firewall src=10.9.0.1 dst=10.9.0.2 action=accept proto=tcp', ('127.0.0.1', port))
        sock.close()
        time.sleep(0.3)
        events = client.get(f'/api/connectors/{cid}/events').json()
        assert events and events[0]['status'] == 'accepted'
        stopped = client.post(f'/api/connectors/{cid}/stop')
        assert stopped.status_code == 200 and stopped.json()['stopped'] is True


def test_file_tail_live_runtime():
    with TestClient(app) as client:
        from pathlib import Path
        import tempfile, time
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'events.log'
            path.write_text('')
            r = client.post('/api/connectors', json={
                'name': 'live-file-test', 'connector_type': 'file_tail', 'source': 'live-file',
                'config': {'path': str(path), 'poll_interval': 0.05}, 'enabled': True,
            })
            assert r.status_code == 200
            cid = r.json()['connector_id']
            assert client.post(f'/api/connectors/{cid}/start').status_code == 200
            time.sleep(0.1)
            with path.open('a') as f: f.write('src=10.1.1.1 dst=10.1.1.2 action=accept\n')
            for _ in range(20):
                events = client.get(f'/api/connectors/{cid}/events').json()
                if events: break
                time.sleep(0.05)
            assert events and events[0]['status'] == 'accepted'
            client.post(f'/api/connectors/{cid}/stop')
