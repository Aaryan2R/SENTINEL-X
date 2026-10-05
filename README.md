# SENTINEL-X

Passive, read-only network threat detection for one-way (data-diode) monitored networks.

**Three pillars:** provable passivity · diode-aware visibility · evidence-chained incidents.

## Quickstart

### Prerequisites

- Docker & Docker Compose
- Linux host (or WSL2) for sensor/capture components
- Python 3.14+ with `uv` for engine development
- Node.js 22+ for frontend development

### Run the demo

```bash
# 1. Copy and edit environment
cp .env.example .env
# Edit .env with your values

# 2. Start all services
docker compose --profile demo up

# 3. Replay traffic (generates alerts)
# Details in traffic/README.md
```

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
