from backend.app.main import app, _ensure_demo_tables
from fastapi.testclient import TestClient

def test_demo_command_center_runs():
    _ensure_demo_tables()
    c=TestClient(app)
    r=c.post("/api/demo/run", json={"scenario":"full_sih_demo","reset_demo":True,"analyst":"Test"})
    assert r.status_code == 200, r.text
    body=r.json()
    assert body["status"] == "completed"
    assert body["summary"]["events_ingested"] == 4
    assert body["summary"]["air_gapped"] is True
    s=c.get("/api/demo/command-center")
    assert s.status_code == 200
