from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_embedding_status_is_local():
    r = client.get('/api/ai/embeddings/status')
    assert r.status_code == 200
    body = r.json()
    assert body['air_gapped'] is True
    assert body['dimension'] > 0

def test_semantic_retrieval_returns_local_hits():
    r = client.post('/api/ai/retrieve', json={'query': 'sourceAddress client ip', 'top_k': 5})
    assert r.status_code == 200
    body = r.json()
    assert body['retrieval_id'].startswith('RET-')
    assert body['results']
    assert body['results'][0]['canonical_field'] in {'source.ip','destination.ip','source.port','destination.port','event.action','network.protocol','user.name','host.name'}

def test_context_map_includes_parser_context_and_mapping():
    r = client.post('/api/ai/context', json={'raw': 'src_addr=10.1.1.2 action=accept', 'source':'test-context'})
    assert r.status_code == 200
    body = r.json()
    assert body['semantic_results']
    assert body['candidate_parsers']
    assert 'schema' in body and body['schema']['id'] == 'ulpf-event-v1'
