import importlib

from fastapi.testclient import TestClient


def _sample_flow():
    return {
        "flow_id": "f1",
        "src_ip": "10.0.0.10",
        "dst_ip": "10.0.0.20",
        "src_port": 12345,
        "dst_port": 443,
        "protocol": "TCP",
        "start_time": 1.0,
        "end_time": 2.0,
        "features": {
            "Flow Duration": 1.0,
            "Total Fwd Packets": 5,
            "Total Backward Packets": 4,
            "Total Length of Fwd Packets": 500,
            "Total Length of Bwd Packets": 420,
            "Fwd Packet Length Max": 120,
            "Fwd Packet Length Min": 80,
            "Fwd Packet Length Mean": 100,
            "Fwd Packet Length Std": 10,
            "Bwd Packet Length Max": 130,
            "Bwd Packet Length Min": 70,
            "Bwd Packet Length Mean": 95,
            "Bwd Packet Length Std": 12,
            "Flow Bytes/s": 920,
            "Flow Packets/s": 9,
            "FIN Flag Count": 0,
            "SYN Flag Count": 1,
            "RST Flag Count": 0,
            "ACK Flag Count": 1,
        },
    }


def test_api_predict_and_stats(monkeypatch, tmp_path):
    monkeypatch.setenv("NIDS_DB_PATH", str(tmp_path / "nids_test.db"))

    api_module = importlib.import_module("nids_engine.backend.api")
    api_module = importlib.reload(api_module)
    client = TestClient(api_module.app)

    predict_res = client.post("/predict", json={"features": _sample_flow()["features"]})
    assert predict_res.status_code == 200
    assert "is_anomaly" in predict_res.json()
    assert "attack_type" in predict_res.json()

    ingest_res = client.post("/api/ingest_flow", json=_sample_flow())
    assert ingest_res.status_code == 200
    assert ingest_res.json()["accepted"] is True

    stats_res = client.get("/stats")
    assert stats_res.status_code == 200
    stats = stats_res.json()
    assert stats["total_flows"] >= 1
