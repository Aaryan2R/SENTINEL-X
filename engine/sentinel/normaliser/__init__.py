"""SENTINEL-X Normaliser — minimal version for hello-flow (T-008).

Reads Zeek JSON conn.log lines, maps to FlowRecord, publishes to Redis stream.
Full implementation in T-011.

INV-4: no outbound network calls.
PY-7: structlog JSON logging (no print).
SEC-4: bounds input sizes.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import structlog

from sentinel.common import FlowRecord

logger = structlog.get_logger()

# SEC-4: bound input sizes
MAX_LINE_BYTES = 64 * 1024  # 64 KiB max per log line
MAX_FIELD_LEN = 1024  # Max string field length


def _clip(value: str | None, max_len: int = MAX_FIELD_LEN) -> str | None:
    """Clip string field length (SEC-4)."""
    if value is None:
        return None
    return value[:max_len]


_seq_counter = 0


def parse_zeek_conn_line(line: str) -> FlowRecord | None:
    """Parse a single Zeek conn.log JSON line into a FlowRecord.

    Returns None for malformed lines (DAT-5: malformed → dead-letter, don't crash).
    """
    global _seq_counter

    if len(line.encode("utf-8", errors="replace")) > MAX_LINE_BYTES:
        logger.warning("line_too_large", size=len(line))
        return None

    try:
        raw: dict[str, Any] = json.loads(line)
    except json.JSONDecodeError:
        logger.warning("invalid_json", line_preview=line[:100])
        return None

    # Zeek conn.log required fields
    try:
        _seq_counter += 1
        flow = FlowRecord(
            uid=str(raw.get("uid", ""))[:MAX_FIELD_LEN],
            ts=float(raw["ts"]),
            src_ip=_clip(str(raw["id.orig_h"])) or "",
            src_port=int(raw["id.orig_p"]),
            dst_ip=_clip(str(raw["id.resp_h"])) or "",
            dst_port=int(raw["id.resp_p"]),
            proto=_clip(str(raw.get("proto", "unknown"))) or "unknown",
            service=_clip(raw.get("service")),
            duration=float(raw["duration"]) if raw.get("duration") is not None else None,
            orig_bytes=int(raw["orig_bytes"]) if raw.get("orig_bytes") is not None else None,
            resp_bytes=int(raw["resp_bytes"]) if raw.get("resp_bytes") is not None else None,
            conn_state=_clip(raw.get("conn_state")),
            seq=_seq_counter,
        )
    except (KeyError, ValueError, TypeError) as exc:
        logger.warning("parse_error", error=str(exc), keys=list(raw.keys())[:20])
        return None

    return flow


def parse_conn_log(log_path: Path) -> list[FlowRecord]:
    """Parse an entire Zeek conn.log file (JSON format)."""
    flows: list[FlowRecord] = []
    with log_path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            flow = parse_zeek_conn_line(line)
            if flow is not None:
                flows.append(flow)

    logger.info("parsed_conn_log", path=str(log_path), flow_count=len(flows))
    return flows


if __name__ == "__main__":
    # Quick CLI test: parse a conn.log and print flows as JSON
    if len(sys.argv) < 2:
        logger.error("usage", msg="python -m sentinel.normaliser <conn.log>")
        sys.exit(1)

    log_file = Path(sys.argv[1])
    for flow in parse_conn_log(log_file):
        sys.stdout.write(flow.model_dump_json() + "\n")
