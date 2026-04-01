# AI-Powered Network Intrusion Detection System

Production-grade, Python-first NIDS that modernizes the original C++ DPI analyzer into a modular real-time platform with packet inspection, ML anomaly detection, API services, and a live React dashboard.

## Why this project matters

- Converts protocol parsing + DPI from C++ to maintainable Python modules.
- Adds real-time flow analytics and ML-based detection for modern network defense workflows.
- Ships with backend APIs, persistence, dashboard, logging, optional email alerts, and Dockerized services.
- Built to be resume-worthy and easy to demo locally.

## Architecture

```text
packet_analyzer/
├── nids_engine/
│   ├── capture/      # scapy live capture + pcap replay
│   ├── parser/       # TCP/UDP/DNS/HTTP/TLS parsing and SNI extraction
│   ├── features/     # packet-to-flow aggregation, CICIDS-style features
│   ├── ml/           # sklearn training/inference + joblib models
│   ├── storage/      # SQLite persistence for flows/alerts/stats
│   └── backend/      # FastAPI endpoints for inference and dashboard
├── dashboard/        # React + Vite + Tailwind + Recharts + Framer Motion
├── main_engine.py    # runtime orchestrator
└── train_models.py   # training CLI (CICIDS CSV or synthetic bootstrap)
```

## Data flow

1. `capture` sniffs packets or replays a pcap stream.
2. `parser` extracts protocol metadata and DPI signals (HTTP method, DNS query, TLS SNI).
3. `features` groups packets into bidirectional flows and computes CICIDS-aligned features.
4. `ml` predicts benign/anomaly (Isolation Forest) and optional attack class (Random Forest).
5. `storage` writes flows and alerts to SQLite.
6. `backend` serves `/predict`, `/stats`, `/api/*` to dashboard and local sniffer.
7. `dashboard` updates near real-time with traffic charts, protocol mix, top IPs, and alerts.

## Implemented capabilities

- Real-time and offline packet processing with `scapy`.
- Protocol parsing: TCP, UDP, DNS, HTTP, TLS (+ SNI extraction).
- Flow-level feature extraction (duration, packet/byte rates, packet length stats, flags).
- ML integration:
  - Isolation Forest for anomaly detection.
  - Random Forest training support for attack classification labels.
- FastAPI endpoints:
  - `POST /predict` and `POST /api/predict`
  - `GET /stats` and `GET /api/stats`
  - `GET /api/flows`, `GET /api/alerts`
  - `POST /api/ingest_flow` for local/remote sniffer ingestion.
- SQLite persistence for dashboard queries.
- Logging to console and `logs/nids.log`.
- Optional email alerts via SMTP environment variables.
- Heuristic attack labeling fallback (`DDoS`, `SYN Flood`, `Brute Force`, etc.).
- Dockerfiles for backend and dashboard.

## Quick start

### 1) Backend + engine dependencies

```bash
pip install -r requirements.txt
```

### 2) Train models

Synthetic bootstrap:

```bash
python train_models.py --samples 5000
```

Train with CICIDS CSV (recommended):

```bash
python train_models.py --cicids-csv "/path/to/CICIDS2017.csv"
```

### 3) Run API

```bash
uvicorn nids_engine.backend.api:app --host 0.0.0.0 --port 8000 --reload
```

### 4) Run engine

Replay pcap:

```bash
python main_engine.py -r test_dpi.pcap --flow-timeout 30
```

Live capture:

```bash
python main_engine.py -i "<interface_name>" --flow-timeout 30
```

Optional: send flows to API instead of local DB write

```bash
python main_engine.py -r test_dpi.pcap --api-url "http://127.0.0.1:8000"
```

### 5) Run dashboard

```bash
cd dashboard
npm install
npm run dev
```

Open `http://localhost:3000`.

## API contract

- `POST /predict`

```json
{
  "features": {
    "Flow Duration": 1.2,
    "Total Fwd Packets": 10,
    "Total Backward Packets": 8
  }
}
```

- `GET /stats` returns:
  - total flows, total alerts, protocol distribution, top source/destination IPs.

## Environment variables (email alerts)

- `NIDS_SMTP_HOST`
- `NIDS_SMTP_PORT` (default: `587`)
- `NIDS_SMTP_USER`
- `NIDS_SMTP_PASSWORD`
- `NIDS_ALERT_FROM`
- `NIDS_ALERT_TO`

## Docker

Backend:

```bash
docker build -f Dockerfile.backend -t nids-backend .
docker run -p 8000:8000 nids-backend
```

Dashboard:

```bash
cd dashboard
docker build -t nids-dashboard .
docker run -p 3000:3000 nids-dashboard
```

Or run full stack together:

```bash
docker compose up --build
```

This starts:
- `backend` on `http://localhost:8000`
- `dashboard` on `http://localhost:3000`
- `engine` replaying `test_dpi.pcap` and streaming events to backend

## Frontend design notes

- Minimal, neutral palette with soft grayscale surfaces.
- Interactive animations via Framer Motion.
- Real-time updates via WebSocket stream (`/ws/events`).

## Testing and CI

Run tests locally:

```bash
pytest -q
```

CI is configured in `.github/workflows/ci.yml` to run:
- Python tests
- Dashboard production build
- Key visual blocks: traffic line chart, protocol distribution, alerts table, top source IP cards.

## Resume-ready bullets

- Architected and delivered a real-time AI-powered NIDS pipeline in Python, replacing legacy C++ DPI logic.
- Implemented CICIDS-aligned flow feature extraction and integrated unsupervised/supervised sklearn models for threat detection.
- Built production-style FastAPI services and a modern React observability dashboard with live security alerts.
- Added persistence, structured logging, Docker packaging, and SMTP alerting for operational readiness.

## Suggested next improvements

- Add Kafka or NATS between engine and backend for horizontal scaling.
- Add unit/integration tests and CI workflows.
- Add model monitoring (drift, false positive rate) and scheduled retraining.
- Replace polling with WebSockets/SSE for lower-latency dashboard updates.
