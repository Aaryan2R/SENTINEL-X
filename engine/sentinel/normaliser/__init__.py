"""SENTINEL-X Normaliser (T-011).

Parses Zeek JSON logs (conn, dns, ssl), maps to FlowRecord schema,
adds monotonic seq and event time, publishes to src_ip and dst_ip Redis streams.

FR-01: Metadata extraction from mirrored traffic.
FR-03: Stream-based pipeline.

INV-4: No outbound network calls.
PY-4: No blocking calls in async code.
PY-7: structlog JSON logging.
SEC-4: Bounds input sizes.
DAT-2: Uses event time from flow record, not processing time.
ARC-5: Shard by src_ip (primary) and dst_ip (secondary).
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import structlog

from sentinel.common.schemas import FlowRecord

logger = structlog.get_logger()

# SEC-4: bound input sizes
MAX_LINE_BYTES = 64 * 1024  # 64 KiB max per log line
MAX_FIELD_LEN = 1024  # Max string field length

# Stream names (ARC-5)
STREAM_BY_SRC = "flows:src"
STREAM_BY_DST = "flows:dst"


def _clip(value: str | None, max_len: int = MAX_FIELD_LEN) -> str | None:
    """Clip string field length (SEC-4)."""
    if value is None:
        return None
    return value[:max_len]


def _shard_key(ip: str) -> str:
    """Compute shard key from IP (ARC-5). Deterministic hash for partitioning."""
    return hashlib.md5(ip.encode(), usedforsecurity=False).hexdigest()[:8]


class Normaliser:
    """Parses Zeek JSON logs and produces FlowRecords.

    Stateful: maintains per-sensor monotonic sequence counter.
    """

    def __init__(self, sensor_id: str = "default") -> None:
        self.sensor_id = sensor_id
        self._seq: int = 0

    def _next_seq(self) -> int:
        """Generate next monotonic sequence number."""
        self._seq += 1
        return self._seq

    def parse_line(self, line: str) -> FlowRecord | None:
        """Parse a single Zeek JSON log line into a FlowRecord.

        Handles conn.log, dns.log, and ssl.log formats.
        Returns None for malformed lines (DAT-5).
        """
        if len(line.encode("utf-8", errors="replace")) > MAX_LINE_BYTES:
            logger.warning("line_too_large", size=len(line))
            return None

        try:
            raw: dict[str, Any] = json.loads(line)
        except json.JSONDecodeError:
            logger.warning("invalid_json", line_preview=line[:100])
            return None

        return self._map_to_flow(raw)

    def _map_to_flow(self, raw: dict[str, Any]) -> FlowRecord | None:
        """Map a parsed Zeek JSON record to FlowRecord."""
        try:
            ts_val = float(raw["ts"])
            duration_val = float(raw["duration"]) if raw.get("duration") is not None else None

            flow = FlowRecord(
                sensor_id=self.sensor_id,
                seq=self._next_seq(),
                uid=str(raw.get("uid", ""))[:MAX_FIELD_LEN],
                ts_start=ts_val,
                ts_end=(ts_val + duration_val) if duration_val is not None else None,
                # Five-tuple
                src_ip=_clip(str(raw["id.orig_h"])) or "",
                src_port=int(raw["id.orig_p"]),
                dst_ip=_clip(str(raw["id.resp_h"])) or "",
                dst_port=int(raw["id.resp_p"]),
                proto=_clip(str(raw.get("proto", "unknown"))) or "unknown",
                # Connection metadata
                service=_clip(raw.get("service")),
                conn_state=_clip(raw.get("conn_state")),
                history=_clip(raw.get("history")),
                # Volume
                duration=duration_val,
                orig_bytes=(int(raw["orig_bytes"]) if raw.get("orig_bytes") is not None else None),
                resp_bytes=(int(raw["resp_bytes"]) if raw.get("resp_bytes") is not None else None),
                orig_pkts=(int(raw["orig_pkts"]) if raw.get("orig_pkts") is not None else None),
                resp_pkts=(int(raw["resp_pkts"]) if raw.get("resp_pkts") is not None else None),
                # DNS fields (from dns.log or merged)
                dns_query=_clip(raw.get("query")),
                dns_qtype=(_clip(str(raw["qtype_name"])) if raw.get("qtype_name") else None),
                dns_rcode=(int(raw["rcode"]) if raw.get("rcode") is not None else None),
                # TLS fields (from ssl.log or merged)
                tls_ja3=_clip(raw.get("ja3")),
                tls_ja4=_clip(raw.get("ja4")),
                tls_sni=_clip(raw.get("server_name")),
                tls_version=(_clip(raw.get("version")) if "version" in raw else None),
            )
        except (KeyError, ValueError, TypeError) as exc:
            logger.warning("parse_error", error=str(exc), keys=list(raw.keys())[:20])
            return None

        return flow

    def parse_log_file(self, log_path: Path) -> list[FlowRecord]:
        """Parse an entire Zeek log file (JSON format)."""
        flows: list[FlowRecord] = []
        with log_path.open() as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                flow = self.parse_line(line)
                if flow is not None:
                    flows.append(flow)
                else:
                    logger.debug("skipped_line", file=str(log_path), line=line_num)

        logger.info("parsed_log", path=str(log_path), flow_count=len(flows))
        return flows


def flow_to_stream_entry(flow: FlowRecord) -> dict[str, str]:
    """Convert FlowRecord to a flat dict for Redis XADD.

    Redis streams store string key-value pairs.
    """
    return {"data": flow.model_dump_json()}


def stream_key_for_src(flow: FlowRecord) -> str:
    """Get the sharded stream key for src_ip (ARC-5 primary)."""
    return f"{STREAM_BY_SRC}:{_shard_key(flow.src_ip)}"


def stream_key_for_dst(flow: FlowRecord) -> str:
    """Get the sharded stream key for dst_ip (ARC-5 secondary)."""
    return f"{STREAM_BY_DST}:{_shard_key(flow.dst_ip)}"


# ── Legacy compat (used by T-008 tests) ──

_legacy_normaliser = Normaliser()


def parse_zeek_conn_line(line: str) -> FlowRecord | None:
    """Parse a single Zeek conn.log JSON line. Legacy wrapper."""
    return _legacy_normaliser.parse_line(line)


def parse_conn_log(log_path: Path) -> list[FlowRecord]:
    """Parse an entire Zeek conn.log file. Legacy wrapper."""
    return _legacy_normaliser.parse_log_file(log_path)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        logger.error("usage", msg="python -m sentinel.normaliser <logfile>")
        sys.exit(1)

    normaliser = Normaliser()
    log_file = Path(sys.argv[1])
    for flow in normaliser.parse_log_file(log_file):
        sys.stdout.write(flow.model_dump_json() + "\n")
