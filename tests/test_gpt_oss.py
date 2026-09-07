import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

import app.main as main


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        _ = self.rfile.read(length)
        payload = {
            "choices": [{"message": {"content": json.dumps({
                "candidate_mappings": {
                    "src_addr": {"target": "source.ip", "confidence": 0.98, "evidence": "IPv4 value + source alias", "value": "10.1.1.7"},
                    "action": {"target": "event.action", "confidence": 0.96, "evidence": "action token", "value": "accept"}
                },
                "unknown_fields": ["vendor_code"],
                "conflicts": [],
                "mapping_confidence": 0.97
            })}}]
        }
        data = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


def test_gpt_oss_adapter_validation(monkeypatch):
    server = HTTPServer(("127.0.0.1", 0), Handler)
    Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.setattr(main, "AI_BASE_URL", f"http://127.0.0.1:{server.server_port}/v1")
    monkeypatch.setattr(main, "AI_MODEL", "gpt-oss-120b")
    result = main._gpt_oss_map("src_addr=10.1.1.7 action=accept vendor_code=42")
    server.shutdown()
    assert result["provider_status"] == "available"
    assert result["candidate_mappings"]["src_addr"]["target"] == "source.ip"
    assert result["unknown_fields"] == ["vendor_code"]
    assert result["mapping_confidence"] >= 0.9
