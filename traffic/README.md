# Phase 1 replay

Start the API with `uvicorn api.main:app --reload` from the repository root,
then run `python traffic/replay/demo_replay.py --scenario port_scan`. The
dashboard at <http://localhost:5173> shows the resulting evidence-backed alert.
Use `normal` to verify a benign replay stays quiet or `syn_flood` for the
volumetric handshake detector. The replay is deterministic and sends only
metadata to the local demo API.

## Source provenance

The replay tooling is intentionally offline and metadata-only. See
[`../docs/DATASETS.md`](../docs/DATASETS.md) for the official traffic-generator
and dataset sources proposed by the submission brief, licensing cautions, and
the boundary between current seeded regression scenarios and future lab data.
