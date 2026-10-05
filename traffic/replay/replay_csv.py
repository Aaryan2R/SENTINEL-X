"""Replay a local flow CSV into the API without inspecting payloads."""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from pathlib import Path
from urllib.request import Request, urlopen


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("csv_file", type=Path)
    parser.add_argument("--api", default="http://localhost:8000")
    parser.add_argument("--label", default="real_data")
    parser.add_argument("--delay", type=float, default=0.0)
    args = parser.parse_args()
    with args.csv_file.open(newline="", encoding="utf-8-sig") as handle:
        for index, row in enumerate(csv.DictReader(handle), start=1):
            flow = {
                "sensor_id": "offline-csv",
                "seq": index,
                "uid": f"csv-{args.csv_file.stem}-{index}",
                "ts_start": float(row.get("ts_start") or index),
                "src_ip": row.get("src_ip") or row.get("Source IP") or "192.0.2.1",
                "src_port": int(float(row.get("src_port") or row.get("Source Port") or 0)),
                "dst_ip": row.get("dst_ip") or row.get("Destination IP") or "198.51.100.1",
                "dst_port": int(float(row.get("dst_port") or row.get("Destination Port") or 0)),
                "proto": (row.get("proto") or row.get("Protocol") or "unknown").lower(),
                "duration": float(row.get("duration") or row.get("Flow Duration") or 0),
                "orig_bytes": int(
                    float(row.get("orig_bytes") or row.get("Total Length of Fwd Packets") or 0)
                ),
                "resp_bytes": int(
                    float(row.get("resp_bytes") or row.get("Total Length of Bwd Packets") or 0)
                ),
                "orig_pkts": int(float(row.get("orig_pkts") or row.get("Tot Fwd Pkts") or 0)),
                "resp_pkts": int(float(row.get("resp_pkts") or row.get("Tot Bwd Pkts") or 0)),
                "service": row.get("service"),
                "conn_state": row.get("conn_state"),
            }
            request = Request(  # noqa: S310
                f"{args.api}/api/flows",
                data=json.dumps(flow).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(request, timeout=10):  # noqa: S310
                pass
            if args.delay:
                time.sleep(args.delay)
    sys.stdout.write(f"Replayed {index} metadata flows from {args.csv_file} (label={args.label})\n")


if __name__ == "__main__":
    main()
