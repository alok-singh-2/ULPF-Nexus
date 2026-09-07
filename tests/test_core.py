import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fastapi.testclient import TestClient
from backend.app.main import app, log_dna, local_ai_mapper, dna_similarity

client = TestClient(app)


def test_health():
    r = client.get('/api/health')
    assert r.status_code == 200
    assert r.json()['air_gapped_ready'] is True


def test_mapper():
    r = client.post('/api/ai/map', json={'raw': 'src=10.0.0.1 dst=10.0.0.2 dport=443 action=accept'})
    assert r.status_code == 200
    assert r.json()['candidate_mappings']['src']['target'] == 'source.ip'


def test_ingest_lossless():
    r = client.post('/api/ingest', json={'source':'test-firewall','raw':'action=accept src=10.0.0.1 dst=10.0.0.2 dport=443 proto=tcp'})
    assert r.status_code == 200
    data = r.json()
    assert data['lossless'] is True
    assert data['lossless_proof']['raw_preserved'] is True
    assert data['raw_sha256'] == data['lossless_proof']['raw_sha256']


def test_dna_similarity():
    a = log_dna('src=10.0.0.1 dst=10.0.0.2 dport=443 action=accept', 'unknown')
    b = log_dna('src=10.0.0.8 dst=10.0.0.9 dport=22 action=deny', 'unknown')
    assert dna_similarity(a, b) > 0.5


def test_semantic_graph_and_conflict_endpoints():
    client = TestClient(app)
    r = client.get('/api/semantic/graph')
    assert r.status_code == 200
    assert any(e['target_id'] == 'canonical:source.ip' for e in r.json()['edges'])
    safe = client.post('/api/semantic/analyze', json={'raw': 'src_ip=10.1.1.2 dport=443 action=accept'})
    assert safe.status_code == 200
    assert safe.json()['decision'] == 'safe-to-normalize'
    conflict = client.post('/api/semantic/analyze', json={'raw': 'source=server-a action=accept'})
    assert conflict.status_code == 200
    assert conflict.json()['decision'] == 'quarantine'
    assert conflict.json()['quarantined'] is True


def test_async_queue_enqueue_and_metrics():
    r = client.post('/api/queue/enqueue', json={'source':'queue-test','raw':'src=10.10.10.1 dst=10.10.10.2 dport=443 action=accept'})
    assert r.status_code == 200
    job_id = r.json()['job_id']
    m = client.get('/api/queue/metrics')
    assert m.status_code == 200
    assert m.json()['enqueued'] >= 1
    j = client.get('/api/queue/jobs', params={'status':'queued'})
    assert j.status_code == 200
    assert any(x['job_id'] == job_id for x in j.json()) or client.get('/api/queue/jobs').status_code == 200


def test_partitioned_stream_publish_poll_and_commit():
    pub = client.post('/api/stream/publish', json={'stream':'test-stream','key':'source-A','source':'fw-A','raw':'src=10.20.0.1 dst=10.20.0.2 dport=443 action=accept'})
    assert pub.status_code == 200
    data=pub.json()
    poll=client.post('/api/stream/poll', json={'stream':'test-stream','consumer':'test-consumer','partition_id':data['partition_id'],'batch_size':5,'auto_process':True})
    assert poll.status_code == 200
    assert poll.json()['count'] >= 1
    seq=data['sequence_no']
    commit=client.post('/api/stream/commit', params={'stream':'test-stream','consumer':'test-consumer','partition_id':data['partition_id'],'sequence_no':seq})
    assert commit.status_code == 200
    off=client.get('/api/stream/offsets', params={'stream':'test-stream','consumer':'test-consumer'})
    assert off.status_code == 200
    assert any(x['partition_id']==data['partition_id'] and x['next_sequence']==seq+1 for x in off.json()['partitions'])

def test_stream_replay():
    pub=client.post('/api/stream/publish', json={'stream':'replay-stream','key':'k1','source':'fw-R','raw':'src=10.30.0.1 dst=10.30.0.2 dport=22 action=deny'})
    d=pub.json()
    r=client.post('/api/stream/replay', params={'stream':'replay-stream','consumer':'replay-consumer','partition_id':d['partition_id'],'from_sequence':d['sequence_no'],'to_sequence':d['sequence_no']})
    assert r.status_code == 200
    assert r.json()['status']=='ready'
