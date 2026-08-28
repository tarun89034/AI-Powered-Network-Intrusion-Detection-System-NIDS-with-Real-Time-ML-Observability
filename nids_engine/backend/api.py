"""Backend API service for dashboard, inference, and live WebSocket events."""

import os
from typing import Any, Dict, List

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from nids_engine.privacy import scrub
from nids_engine.storage.db import FlowDatabase
from nids_engine.ml.model_manager import ModelManager


class PredictRequest(BaseModel):
    features: Dict[str, Any]


class PredictResponse(BaseModel):
    is_anomaly: bool
    attack_type: str


class IngestFlowRequest(BaseModel):
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: float
    end_time: float
    features: Dict[str, Any]


class ConnectionManager:
    def __init__(self) -> None:
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: Dict[str, Any]) -> None:
        stale_connections: List[WebSocket] = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                stale_connections.append(connection)

        for connection in stale_connections:
            self.disconnect(connection)

app = FastAPI(title="NIDS Engine API", version="1.0.0")

# Allow requests from the React dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, restrict to dashboard URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Connect to the global SQLite database
db = FlowDatabase(db_path=os.getenv("NIDS_DB_PATH"))
model_manager = ModelManager()
ws_manager = ConnectionManager()

@app.get("/")
def read_root():
    return {"status": "Active", "service": "NIDS Backend API"}

@app.get("/api/stats")
def get_stats():
    """Returns general NIDS statistics."""
    return scrub(db.get_stats())


@app.get("/stats")
def get_stats_compat():
    """Compatibility endpoint for /stats requirement."""
    return scrub(db.get_stats())

@app.get("/api/alerts")
def get_alerts(limit: int = 50):
    """Returns recent anomaly alerts."""
    return scrub(db.get_alerts(limit))

@app.get("/api/flows")
def get_flows(limit: int = 100):
    """Returns recent network flows."""
    return scrub(db.get_recent_flows(limit))


@app.post("/api/predict", response_model=PredictResponse)
def predict(payload: PredictRequest):
    """Runs model inference on supplied feature vector."""
    is_anomaly, attack_type = model_manager.predict(payload.features)
    return PredictResponse(is_anomaly=is_anomaly, attack_type=attack_type)


@app.post("/predict", response_model=PredictResponse)
def predict_compat(payload: PredictRequest):
    """Compatibility endpoint for /predict requirement."""
    is_anomaly, attack_type = model_manager.predict(payload.features)
    return PredictResponse(is_anomaly=is_anomaly, attack_type=attack_type)


@app.post("/api/ingest_flow")
async def ingest_flow(flow: IngestFlowRequest):
    """Allows local/remote sniffers to send completed flow features to the API."""
    flow_data = flow.model_dump()
    is_anomaly, attack_type = model_manager.predict(flow_data["features"])
    db.insert_flow(flow_data, is_anomaly, attack_type)

    await ws_manager.broadcast(
        scrub(
            {
                "event": "flow_processed",
                "flow": {
                    **flow_data,
                    "is_anomaly": is_anomaly,
                    "attack_type": attack_type,
                },
                "stats": db.get_stats(),
                "alerts": db.get_alerts(limit=10),
                "flows": db.get_recent_flows(limit=20),
            }
        )
    )

    return {
        "accepted": True,
        "is_anomaly": is_anomaly,
        "attack_type": attack_type,
    }


@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    """Streams real-time flow/alert updates to dashboard clients."""
    await ws_manager.connect(websocket)
    try:
        await websocket.send_json(
            scrub(
                {
                    "event": "snapshot",
                    "stats": db.get_stats(),
                    "alerts": db.get_alerts(limit=10),
                    "flows": db.get_recent_flows(limit=20),
                }
            )
        )
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)

# To run this directly for testing: uvicorn nids_engine.backend.api:app --reload
