# SIH submission readiness

## Verified demo story

1. Start the complete local demo with `.\scripts\demo.ps1 -InstallFrontend`.
2. Open `http://localhost:5173`.
3. Show the passivity panel: Linux reports the selected kernel TX counter;
   Windows explicitly shows `PASSIVITY EMULATED`.
4. Replay `normal` to show a benign run with no alerts.
5. Reset the demo, then replay `port_scan` or `syn_flood`.
6. Open the alert to show confidence, evidence, computed contributions, ATT&CK
   technique, and the evidence hash chain fields.
7. Click **VERIFY CHAIN** and show that the complete chain is valid.

The replay is deterministic in shape and uses metadata-only synthetic flows.
The local demo stores state in memory and is intended for Windows, Linux, and
WSL. It is a software emulation of a one-way monitoring boundary, not a claim
of a hardware data diode.

The planned traffic-source expansion is documented in
[DATASETS.md](DATASETS.md). Third-party captures and DGA lists are not bundled;
the current measured claims use only the checked-in seeded scenarios.

## Claims we can make

- A seeded benign replay remains quiet.
- Seeded scan and SYN-flood replays produce explained alerts.
- Alert evidence is linked with SHA-256 `evidence_hash` and `prev_hash` values.
- The chain can be independently recomputed through the API or dashboard.
- The dashboard exposes the demo passivity status and visibility health.
- The API, dashboard, replay, and detector tests are reproducible offline.

## Claims reserved for future hardening

tc/nftables enforcement, Redis stream workers,
PostgreSQL persistence, trained DGA models, full event-time sketch rollups,
and hardware data-diode guarantees are not part of this local demo. They are
tracked in `task.md` and should be presented as the engineering roadmap.

## Reproducibility checklist

- Record the commit SHA used for the presentation.
- Use the same scenario names and command lines from `README.md`.
- Capture the Python, Node, OS, and browser versions.
- Do not publish performance numbers until they are measured on the target
  presentation machine.
