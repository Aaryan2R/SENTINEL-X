# Measured evaluation

Run the API first, then execute:

```powershell
python scripts\evaluate_demo.py --seed 42
```

This runs `normal`, `port_scan`, and `syn_flood`, resets the in-memory API
between scenarios, records flow counts, observed alerts, true-positive status,
false-positive status, coverage, and measured API latency, and writes the
machine-specific result to `docs/evaluation/latest.json`. The generated file
is intentionally not committed as a universal benchmark: results depend on
the machine, OS, Python version, and API process state.

The expected regression is:

| Scenario | Expected alerts | Expected result |
|---|---:|---|
| normal | 0 | benign run stays quiet |
| port_scan | >= 1 | `PORT_SCAN` observed |
| syn_flood | >= 1 | `SYN_FLOOD` observed |

For Linux/WSL passivity proof, wrap the relevant replay command:

```bash
python scripts/assert_tx_zero.py --interface <capture-interface> \
  python traffic/replay/demo_replay.py --scenario port_scan \
  --api http://localhost:8000
```

The script fails if the selected interface TX counter changes. On Windows,
the dashboard deliberately labels passivity as `software-emulation`; it does
not claim a kernel counter or hardware data-diode guarantee.

Loss injection is available for visibility demonstrations:

```powershell
.\scripts\demo.ps1 -Scenario port_scan -LossRate 0.05
```
