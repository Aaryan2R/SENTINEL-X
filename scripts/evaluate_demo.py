"""Run all deterministic demo scenarios and write measured results.

The API must already be running. No performance numbers are checked in; this
command records measurements from the machine on which it is executed.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.request import Request, urlopen

SCENARIOS = {
    "normal": {"count": 20, "expected": set()},
    "port_scan": {"count": 80, "expected": {"PORT_SCAN"}},
    "syn_flood": {"count": 80, "expected": {"SYN_FLOOD"}},
}


def request(base: str, path: str, method: str = "GET", body: dict | None = None) -> dict | list:
    data = json.dumps(body).encode() if body is not None else None
    req = Request(f"{base}{path}", data=data, method=method)  # noqa: S310
    if data:
        req.add_header("Content-Type", "application/json")
    with urlopen(req, timeout=10) as response:  # noqa: S310
        return json.loads(response.read())


def flow(scenario: str, index: int, ts: float) -> dict[str, object]:
    scan = scenario == "port_scan"
    syn = scenario == "syn_flood"
    return {
        "sensor_id": "evaluation-sensor",
        "seq": index + 1,
        "uid": f"eval-{scenario}-{index}",
        "ts_start": ts,
        "src_ip": "192.168.1.100" if not syn else "192.168.1.101",
        "src_port": 40000 + index,
        "dst_ip": "10.0.0.1",
        "dst_port": 1000 + index if scan else 443,
        "proto": "tcp",
        "conn_state": "S0" if syn else "SF",
        "history": "S",
        "orig_pkts": 1,
        "resp_pkts": 0,
        "orig_bytes": 64,
        "resp_bytes": 0,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api", default="http://localhost:8000")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", type=Path, default=Path("docs/evaluation/latest.json"))
    args = parser.parse_args()
    started = datetime.now(UTC)
    results = []
    for name, expected in SCENARIOS.items():
        request(args.api, "/api/demo/reset", "POST")
        latencies = []
        sent = time.monotonic()
        for index in range(expected["count"]):
            before = time.perf_counter()
            event_time = 1_000_000 + index * 0.25 + args.seed
            request(args.api, "/api/flows", "POST", flow(name, index, event_time))
            latencies.append((time.perf_counter() - before) * 1000)
        alerts = request(args.api, "/api/alerts")
        observed = {item["threat_class"] for item in alerts}
        results.append(
            {
                "scenario": name,
                "seed": args.seed,
                "flows_sent": expected["count"],
                "alerts": len(alerts),
                "observed_threats": sorted(observed),
                "expected_threats": sorted(expected["expected"]),
                "true_positive": (
                    expected["expected"] <= observed if expected["expected"] else not observed
                ),
                "false_positive": bool(observed - expected["expected"]),
                "coverage": len(expected["expected"] & observed)
                / max(1, len(expected["expected"])),
                "replay_seconds": round(time.monotonic() - sent, 6),
                "latency_ms": {
                    "p50": round(statistics.median(latencies), 3),
                    "p95": round(sorted(latencies)[int(len(latencies) * 0.95) - 1], 3),
                },
            }
        )
    report = {
        "generated_at": started.isoformat(),
        "api": args.api,
        "seed": args.seed,
        "software": {"python": sys.version.split()[0], "platform": platform.platform()},
        "scenarios": results,
        "note": (
            "Measurements are from this run and must not be generalized to production performance."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    sys.stdout.write(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
