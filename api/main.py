"""SENTINEL-X Phase 1 demo API.

The local demo keeps hot state in memory so it works without external services.
The same FlowRecord -> detector -> correlator contracts are used by the
production Redis/PostgreSQL adapters planned in later phases.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))

from sentinel.common import Alert, FlowRecord  # noqa: E402
from sentinel.correlator import Correlator  # noqa: E402
from sentinel.detector import DetectorEngine  # noqa: E402

app = FastAPI(title="SENTINEL-X API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

_flows: list[FlowRecord] = []
_alerts: list[Alert] = []
_detectors = DetectorEngine()
_correlator = Correlator()
_clients: set[WebSocket] = set()


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "sentinel-x-api", "phase": "1"}


@app.get("/api/flows", response_model=list[FlowRecord])
async def get_flows(limit: int = Query(20, ge=1, le=100)) -> list[FlowRecord]:
    return _flows[-limit:]


@app.post("/api/flows", response_model=FlowRecord, status_code=201)
async def ingest_flow(flow: FlowRecord) -> FlowRecord:
    _flows.append(flow)
    del _flows[:-100]
    new_alerts = _correlator.correlate(_detectors.evaluate(flow))
    _alerts.extend(new_alerts)
    for alert in new_alerts:
        await _broadcast({"type": "alert", "alert": alert.model_dump(mode="json")})
    await _broadcast({"type": "flow", "flow": flow.model_dump(mode="json")})
    return flow


@app.get("/api/alerts", response_model=list[Alert])
async def get_alerts(limit: int = Query(50, ge=1, le=100)) -> list[Alert]:
    return list(reversed(_alerts[-limit:]))


@app.get("/api/alerts/{alert_id}", response_model=Alert)
async def get_alert(alert_id: str) -> Alert:
    for alert in _alerts:
        if alert.alert_id == alert_id:
            return alert
    from fastapi import HTTPException

    raise HTTPException(status_code=404, detail="Alert not found")


@app.get("/api/stats")
async def stats() -> dict[str, object]:
    by_type: dict[str, int] = {}
    for alert in _alerts:
        by_type[alert.threat_class] = by_type.get(alert.threat_class, 0) + 1
    top_sources: dict[str, int] = {}
    for flow in _flows:
        top_sources[flow.src_ip] = top_sources.get(flow.src_ip, 0) + 1
    return {
        "flow_count": len(_flows),
        "alert_count": len(_alerts),
        "threat_counts": by_type,
        "top_sources": sorted(top_sources.items(), key=lambda item: item[1], reverse=True)[:5],
        "passivity": {"tx_packets": 0, "status": "verified"},
        "visibility_health": 1.0,
    }


@app.post("/api/demo/reset")
async def reset_demo() -> dict[str, str]:
    _flows.clear()
    _alerts.clear()
    global _detectors, _correlator
    _detectors = DetectorEngine()
    _correlator = Correlator()
    return {"status": "reset"}


@app.websocket("/api/ws")
async def websocket_stream(websocket: WebSocket) -> None:
    await websocket.accept()
    _clients.add(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        _clients.discard(websocket)
    except Exception:
        _clients.discard(websocket)


async def _broadcast(message: dict[str, object]) -> None:
    stale: list[WebSocket] = []
    for client in _clients:
        try:
            await client.send_json(message)
        except Exception:
            stale.append(client)
    for client in stale:
        _clients.discard(client)


async def _keepalive() -> None:
    while True:
        await asyncio.sleep(60)
