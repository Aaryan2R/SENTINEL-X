"""Tests for the normaliser (T-008 hello-flow)."""

from __future__ import annotations

import json

from sentinel.normaliser import parse_zeek_conn_line

# Sample Zeek conn.log JSON line (based on Zeek JSON format)
SAMPLE_CONN_LINE = json.dumps(
    {
        "ts": 1735689600.123456,
        "uid": "CYf0EE1w8JxHGCnMFa",
        "id.orig_h": "192.168.1.10",
        "id.orig_p": 54321,
        "id.resp_h": "10.0.0.1",
        "id.resp_p": 80,
        "proto": "tcp",
        "service": "http",
        "duration": 1.234,
        "orig_bytes": 512,
        "resp_bytes": 2048,
        "conn_state": "SF",
    }
)


def test_parse_valid_conn_line() -> None:
    """Valid Zeek conn.log line parses to FlowRecord."""
    flow = parse_zeek_conn_line(SAMPLE_CONN_LINE)
    assert flow is not None
    assert flow.src_ip == "192.168.1.10"
    assert flow.dst_ip == "10.0.0.1"
    assert flow.src_port == 54321
    assert flow.dst_port == 80
    assert flow.proto == "tcp"
    assert flow.service == "http"
    assert flow.duration == 1.234
    assert flow.orig_bytes == 512
    assert flow.resp_bytes == 2048
    assert flow.conn_state == "SF"
    assert flow.seq > 0


def test_parse_invalid_json() -> None:
    """Invalid JSON returns None (DAT-5)."""
    assert parse_zeek_conn_line("not json at all") is None


def test_parse_missing_required_field() -> None:
    """Missing required field returns None."""
    incomplete = json.dumps({"ts": 1234.0, "uid": "abc"})
    assert parse_zeek_conn_line(incomplete) is None


def test_parse_oversized_line() -> None:
    """Oversized line is rejected (SEC-4)."""
    big_line = json.dumps({"ts": 1234.0, "data": "x" * 100_000})
    assert parse_zeek_conn_line(big_line) is None


def test_parse_optional_fields_missing() -> None:
    """Optional fields can be missing."""
    minimal = json.dumps(
        {
            "ts": 1735689600.0,
            "uid": "test123",
            "id.orig_h": "1.2.3.4",
            "id.orig_p": 1234,
            "id.resp_h": "5.6.7.8",
            "id.resp_p": 80,
            "proto": "tcp",
        }
    )
    flow = parse_zeek_conn_line(minimal)
    assert flow is not None
    assert flow.duration is None
    assert flow.orig_bytes is None
    assert flow.service is None
