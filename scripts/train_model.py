"""Train a provenance-aware metadata baseline from local flow CSV files.

CSV files must contain SENTINEL-X flow fields plus ``label``. Common CIC-style
column names are mapped by the loader. Raw datasets remain outside the repo.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))

from sentinel.features.baseline import save_model, train_centroids

ALIASES = {
    "src_ip": ("src_ip", "Source IP"),
    "dst_ip": ("dst_ip", "Destination IP"),
    "src_port": ("src_port", "Source Port"),
    "dst_port": ("dst_port", "Destination Port"),
    "proto": ("proto", "Protocol"),
    "duration": ("duration", "Flow Duration"),
    "orig_bytes": ("orig_bytes", "Total Length of Fwd Packets", "TotLen Fwd Pkts"),
    "resp_bytes": ("resp_bytes", "Total Length of Bwd Packets", "TotLen Bwd Pkts"),
    "orig_pkts": ("orig_pkts", "Tot Fwd Pkts", "Total Fwd Packets"),
    "resp_pkts": ("resp_pkts", "Tot Bwd Pkts", "Total Backward Packets"),
    "conn_state": ("conn_state", "Label"),
    "label": ("label", "Attack", "Class", "Label"),
}


def read_csv(path: Path, source: str) -> tuple[list[tuple[dict[str, Any], str]], dict[str, Any]]:
    rows: list[tuple[dict[str, Any], str]] = []
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        for raw in reader:
            flow: dict[str, Any] = {}
            for field, aliases in ALIASES.items():
                key = next((candidate for candidate in aliases if candidate in raw), None)
                if key is not None:
                    flow[field] = raw[key]
            label = str(flow.pop("label", "")).strip()
            if not label:
                raise ValueError(f"{path}: every row needs a label column")
            rows.append((flow, label))
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return rows, {"path": str(path), "source": source, "sha256": digest, "rows": len(rows)}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", action="append", required=True, metavar="SOURCE=CSV")
    parser.add_argument(
        "--output", type=Path, default=Path("datasets/models/metadata_centroid.json")
    )
    parser.add_argument("--manifest", type=Path, default=Path("datasets/models/manifest.json"))
    args = parser.parse_args()
    rows: list[tuple[dict[str, Any], str]] = []
    provenance = []
    for item in args.input:
        source, separator, filename = item.partition("=")
        if not separator or not source or not filename:
            parser.error("--input must be SOURCE=CSV")
        loaded, record = read_csv(Path(filename), source)
        rows.extend(loaded)
        provenance.append(record)
    model = train_centroids(rows)
    model["trained_at"] = datetime.now(UTC).isoformat()
    model["training_rows"] = len(rows)
    model["provenance"] = provenance
    save_model(model, args.output)
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
    sys.stdout.write(json.dumps(
        {"output": str(args.output), "rows": len(rows), "classes": sorted(model["classes"])},
        indent=2,
    ) + "\n")


if __name__ == "__main__":
    main()
