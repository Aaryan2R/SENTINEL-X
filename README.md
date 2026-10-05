# SENTINEL-X

Passive, read-only network threat detection for one-way (data-diode) monitored networks.

**Three pillars:** provable passivity · diode-aware visibility · evidence-chained incidents.

## Quickstart — Phase 1 demo

### Prerequisites

- Docker & Docker Compose
- Linux host (or WSL2) for sensor/capture components
- Python 3.13+ for the local API demo (3.14+ with `uv` for engine development)
- Node.js 22+ for frontend development

### Run the demo

```bash
# 1. Start the local API from the repository root (no external services required)
pip install fastapi uvicorn pydantic redis structlog
# PowerShell:
$env:PYTHONPATH = "$PWD\engine"
python -m uvicorn api.main:app --reload
# bash/WSL:
PYTHONPATH="$PWD/engine" python -m uvicorn api.main:app --reload

# 2. Start the dashboard in another terminal
cd frontend
npm ci
npm run dev

# 3. In a third terminal at the repository root, replay a seeded scan
python traffic/replay/demo_replay.py --scenario port_scan
```

If the API reports `ModuleNotFoundError: No module named 'sentinel'`, confirm
the terminal is at the repository root and set `PYTHONPATH` as shown above.
Also make sure you are running the checkout containing the Phase 1 changes;
the separate `Downloads\SENTINEL-X` checkout may still point at `main`.

The `normal` scenario is a benign regression (no alerts); `syn_flood` produces
an explained SYN-flood alert. The demo is metadata-only and keeps state in
memory so it runs on Windows, Linux, and WSL without Redis or PostgreSQL.
`docker compose --profile demo up --build` remains available for the hardened
service layout; the sensor/netns passivity emulation requires Linux.

### Development

```bash
# Python (engine)
cd engine
uv sync
uv run ruff check .
uv run mypy .
uv run pytest

# Frontend
cd frontend
npm ci
npm run dev
```

## Phase 1 capabilities

- bounded event-time detector state for port scans, SYN floods, volumetric DDoS, and DGA-like DNS
- deduplicated alerts with severity, evidence, computed contributions, and a SHA-256 evidence chain
- REST endpoints for flows, alerts, alert detail, stats, reset, plus a live WebSocket stream
- dashboard panels for passivity, visibility health, live flows, detections, and evidence detail
- deterministic replay scripts and a benign no-alert path

## Repository layout

```
sentinel-x/
  compose.yaml                 # profiles: core, demo
  infra/   netns/  nftables/  tc/
  sensor/  Dockerfile  zeek/local.zeek  zeek/packages.txt
  engine/  pyproject.toml  uv.lock
           sentinel/  common/ normaliser/ detector/ correlator/ evidence/ monitor/ bundles/
                      detectors/  (c2, dga, dns_tunnel, scan, ddos, syn, udp_amp, tls, exfil)
                      features/   (shared by training and inference)
           models/  tests/
  api/        # FastAPI
  frontend/   # React + TypeScript + Vite
  traffic/    generator/ scenarios/ replay/
  bench/      # benchmark harness and report templates
  docs/       # PRD, design document, tech stack, ADRs
```

## Key documents

- [Architecture](architecture.md) — system structure
- [Rules](rules.md) — project invariants and coding rules
- [Tasks](task.md) — phased work breakdown
- [Memory](memory.md) — persistent project context

## Licence

Not yet determined. See `docs/` for dependency licence notes.
