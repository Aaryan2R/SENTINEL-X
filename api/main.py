"""SENTINEL-X API — minimal hello-flow endpoint (T-008).

Full API in T-025. This provides just enough for the dashboard to show a flow.
SEC-8: binds to enclave network only (via compose config).
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from sentinel.common import FlowRecord

app = FastAPI(
    title="SENTINEL-X API",
    description="Passive network threat detection — API",
    version="0.1.0",
)

# CORS for dashboard (enclave only in production; permissive for dev)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_methods=["GET"],
    allow_headers=["*"],
)

# In-memory store for hello-flow demo (replaced by Redis/Postgres in later tasks)
_recent_flows: list[FlowRecord] = []
MAX_RECENT = 100


@app.get("/api/health")
async def health() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "ok", "service": "sentinel-x-api"}


@app.get("/api/flows", response_model=list[FlowRecord])
async def get_flows(limit: int = 20) -> list[FlowRecord]:
    """Get recent flows (hello-flow demo)."""
    return _recent_flows[-min(limit, MAX_RECENT) :]


@app.post("/api/flows", response_model=FlowRecord, status_code=201)
async def ingest_flow(flow: FlowRecord) -> FlowRecord:
    """Ingest a flow record (hello-flow demo; replaced by stream consumer later)."""
    _recent_flows.append(flow)
    if len(_recent_flows) > MAX_RECENT:
        _recent_flows.pop(0)
    return flow
