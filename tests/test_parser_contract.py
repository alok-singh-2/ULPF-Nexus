from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_compile_translation_contract():
    samples = [
        'src_addr=10.40.1.7 dst_addr=10.40.2.9 source_port=51543 destination_port=443 decision=accept transport=tcp vendor_code=gw-7',
        'src_addr=10.40.1.8 dst_addr=10.40.2.10 source_port=51544 destination_port=22 decision=deny transport=tcp vendor_code=gw-8',
    ]
    r = client.post('/api/parsers/compile-contract', json={'raw_samples': samples, 'source': 'contract-firewall', 'name': 'contract-firewall-parser'})
    assert r.status_code == 200
    body = r.json()
    c = body['contract']
    assert body['contract_id'].startswith('CTR-')
    assert c['contract_type'] == 'ulpf.translation-contract'
    assert c['detection']['format'] == 'kv'
    assert c['field_mapping']['src_addr']['target'] == 'source.ip'
    assert c['field_mapping']['source_port']['type'] == 'port'
    assert c['preserve_unknown'] is True
    assert 'vendor_code' in c['unknown_fields']
    assert c['safety']['requires_sandbox'] is True


def test_contract_is_retrievable():
    r = client.post('/api/parsers/compile-contract', json={'raw_samples': ['src=10.0.0.1 action=accept'], 'source': 'retrieval-test'})
    assert r.status_code == 200
    pid = r.json()['parser_id']
    g = client.get(f'/api/parsers/contracts/{pid}')
    assert g.status_code == 200
    assert g.json()['payload']['field_mapping']['src']['target'] == 'source.ip'
