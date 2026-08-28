"""Guards that raw addresses never leave the API, on any egress path."""

import json

import pytest
from fastapi.testclient import TestClient

from nids_engine import privacy


SRC_IP = "192.0.2.10"
DST_IP = "198.51.100.20"


def _sample_flow():
    return {
        "flow_id": f"{SRC_IP}:443-{DST_IP}:51000-TCP",
        "src_ip": SRC_IP,
        "dst_ip": DST_IP,
        "src_port": 443,
        "dst_port": 51000,
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


@pytest.fixture
def api_client(monkeypatch, tmp_path):
    import importlib

    monkeypatch.setenv("NIDS_DB_PATH", str(tmp_path / "nids_privacy.db"))
    monkeypatch.setenv("NIDS_ANON_SALT", "test-salt")
    api_module = importlib.reload(importlib.import_module("nids_engine.backend.api"))
    return TestClient(api_module.app)


def test_anonymize_ip_is_stable_and_one_way(monkeypatch):
    monkeypatch.setenv("NIDS_ANON_SALT", "test-salt")
    pseudonym = privacy.anonymize_ip(SRC_IP)

    assert pseudonym.startswith(privacy.ANON_PREFIX)
    assert SRC_IP not in pseudonym
    assert pseudonym == privacy.anonymize_ip(SRC_IP)
    assert pseudonym != privacy.anonymize_ip(DST_IP)


def test_anonymize_ip_is_idempotent(monkeypatch):
    monkeypatch.setenv("NIDS_ANON_SALT", "test-salt")
    pseudonym = privacy.anonymize_ip(SRC_IP)

    assert privacy.anonymize_ip(pseudonym) == pseudonym


def test_scrub_covers_embedded_addresses(monkeypatch):
    monkeypatch.setenv("NIDS_ANON_SALT", "test-salt")
    scrubbed = privacy.scrub({"flow_id": f"{SRC_IP}:443-{DST_IP}:51000-TCP"})

    assert SRC_IP not in scrubbed["flow_id"]
    assert DST_IP not in scrubbed["flow_id"]
    assert scrubbed["flow_id"].endswith(":443-" + privacy.anonymize_ip(DST_IP) + ":51000-TCP")


def test_scrub_is_a_no_op_when_privacy_mode_is_off(monkeypatch):
    monkeypatch.setenv("NIDS_PRIVACY_MODE", "off")

    assert privacy.scrub({"src_ip": SRC_IP}) == {"src_ip": SRC_IP}


def test_websocket_never_carries_a_raw_address(api_client):
    with api_client.websocket_connect("/ws/events") as websocket:
        snapshot = websocket.receive_json()
        assert SRC_IP not in json.dumps(snapshot)

        assert api_client.post("/api/ingest_flow", json=_sample_flow()).status_code == 200

        update = websocket.receive_json()
        payload = json.dumps(update)
        assert SRC_IP not in payload
        assert DST_IP not in payload
        assert update["flow"]["src_ip"] == privacy.anonymize_ip(SRC_IP)
        assert update["flow"]["dst_ip"] == privacy.anonymize_ip(DST_IP)


@pytest.mark.parametrize("endpoint", ["/api/flows", "/api/alerts", "/api/stats", "/stats"])
def test_rest_endpoints_never_carry_a_raw_address(api_client, endpoint):
    assert api_client.post("/api/ingest_flow", json=_sample_flow()).status_code == 200

    body = api_client.get(endpoint).text
    assert SRC_IP not in body
    assert DST_IP not in body
