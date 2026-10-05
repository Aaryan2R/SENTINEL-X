"""Replay a deterministic Phase 1 flow scenario into the local API."""

from __future__ import annotations

import argparse
import json
import time
from datetime import UTC, datetime
from urllib.request import Request, urlopen


def post(base: str, flow: dict[str, object]) -> None:
    request = Request(
        f"{base}/api/flows",
        data=json.dumps(flow).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=5):
        pass


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", choices=["normal", "port_scan", "syn_flood"], default="port_scan")
    parser.add_argument("--api", default="http://localhost:8000")
    args = parser.parse_args()
    base_ts = datetime.now(UTC).timestamp()
    count = 80 if args.scenario != "normal" else 20
    for index in range(count):
        is_scan = args.scenario == "port_scan"
        is_syn = args.scenario == "syn_flood"
        post(
            args.api,
            {
                "sensor_id": "demo-sensor", "seq": index + 1, "uid": f"demo-{args.scenario}-{index}",
                "ts_start": base_ts + index * 0.25, "src_ip": "192.168.1.100" if not is_syn else "192.168.1.101",
                "src_port": 40000 + index, "dst_ip": "10.0.0.1", "dst_port": (1000 + index if is_scan else 443),
                "proto": "tcp", "conn_state": "S0" if is_syn else "SF", "history": "S",
                "orig_pkts": 1, "resp_pkts": 0, "orig_bytes": 64, "resp_bytes": 0,
            },
        )
        if args.scenario == "normal":
            time.sleep(0.01)
    print(f"Replayed {count} {args.scenario} flows into {args.api}")


if __name__ == "__main__":
    main()
