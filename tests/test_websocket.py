import asyncio
import json
import pytest
from fastapi.testclient import TestClient
from nids_engine.backend.api import app, ws_manager

def test_websocket_snapshot():
    """Test that connecting to the websocket returns an initial snapshot."""
    client = TestClient(app)
    with client.websocket_connect("/ws/events") as websocket:
        data = websocket.receive_json()
        assert data["event"] == "snapshot"
        assert "stats" in data
        assert "alerts" in data
        assert "flows" in data

@pytest.mark.asyncio
async def test_websocket_broadcast_on_ingest():
    """Test that ingesting a flow triggers a broadcast to connected websocket clients."""
    # We use the actual app and ws_manager here
    client = TestClient(app)
    
    with client.websocket_connect("/ws/events") as websocket:
        # Initial snapshot
        websocket.receive_json()
        
        # Simulate flow ingestion
        sample_flow = {
            "flow_id": "ws_test_flow",
            "src_ip": "1.2.3.4",
            "dst_ip": "5.6.7.8",
            "src_port": 123,
            "dst_port": 456,
            "protocol": "UDP",
            "start_time": 100.0,
            "end_time": 101.0,
            "features": {
                "Flow Duration": 1.0,
                "Total Fwd Packets": 1,
                "Total Backward Packets": 1,
                "Total Length of Fwd Packets": 10,
                "Total Length of Bwd Packets": 10,
                "Fwd Packet Length Max": 10,
                "Fwd Packet Length Min": 10,
                "Fwd Packet Length Mean": 10,
                "Fwd Packet Length Std": 0,
                "Bwd Packet Length Max": 10,
                "Bwd Packet Length Min": 10,
                "Bwd Packet Length Mean": 10,
                "Bwd Packet Length Std": 0,
                "Flow Bytes/s": 20,
                "Flow Packets/s": 2,
                "FIN Flag Count": 0,
                "SYN Flag Count": 0,
                "RST Flag Count": 0,
                "ACK Flag Count": 0,
            }
        }
        
        # Trigger ingestion
        response = client.post("/api/ingest_flow", json=sample_flow)
        assert response.status_code == 200
        
        # Check if websocket received the update
        update = websocket.receive_json()
        assert update["event"] == "flow_processed"
        assert update["flow"]["flow_id"] == "ws_test_flow"
        assert "stats" in update
