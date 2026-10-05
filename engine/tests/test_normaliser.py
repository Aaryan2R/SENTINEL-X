"""Tests for schemas (T-010), normaliser (T-011), and stream publishing."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest

from sentinel.common import (
    Alert,
    AlertExplanation,
    CorrelationGroup,
    FlowRecord,
    Severity,
    Signal,
    SignalContribution,
    severity_from_score,
)
from sentinel.normaliser import (
    Normaliser,
    flow_to_stream_entry,
    parse_zeek_conn_line,
    stream_key_for_dst,
    stream_key_for_src,
)
from sentinel.normaliser.publisher import RedisStreamPublisher

# ── Schema tests ──


def test_flow_record_round_trip() -> None:
    """FlowRecord serialises and deserialises correctly."""
    flow = FlowRecord(
        uid="CYf0EE1w8JxHGCnMFa",
        ts_start=1735689600.0,
        src_ip="192.168.1.10",
        src_port=54321,
        dst_ip="10.0.0.1",
        dst_port=80,
        proto="tcp",
        seq=1,
    )
    data = flow.model_dump_json()
    restored = FlowRecord.model_validate_json(data)
    assert restored.uid == flow.uid
    assert restored.ts_start == flow.ts_start
    assert restored.proto == "tcp"


def test_signal_requires_evidence_and_contributions() -> None:
    """Signal cannot be created without evidence/contributions (DET-3)."""
    sig = Signal(
        entity="192.168.1.100",
        threat_class="PORT_SCAN",
        score=0.85,
        group=CorrelationGroup.SCAN,
        evidence={"unique_ports": 50, "failed_ratio": 0.9},
        contributions=[SignalContribution(name="unique_ports", value=0.6)],
        window=(1735689600.0, 1735689610.0),
        detector="scan_detector@1.0.0",
        attack_technique="T1046",
    )
    assert sig.score == 0.85
    assert len(sig.contributions) >= 1


def test_signal_score_bounded() -> None:
    """Signal rejects out-of-range scores (DET-2)."""
    with pytest.raises(Exception):  # noqa: B017
        Signal(
            entity="x",
            threat_class="x",
            score=1.5,
            group=CorrelationGroup.SCAN,
            evidence={"k": "v"},
            contributions=[SignalContribution(name="x", value=0.5)],
            window=(0.0, 1.0),
            detector="d@1.0.0",
            attack_technique="T1046",
        )


def test_alert_round_trip() -> None:
    """Alert serialises with ISO-8601 UTC timestamps (DAT-1)."""
    alert = Alert(
        alert_id="alert-001",
        timestamp=datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC),
        source_ip="192.168.1.100",
        destination_ip="10.0.0.1",
        destination_port=80,
        threat_class="PORT_SCAN",
        attack_technique="T1046",
        severity=Severity.HIGH,
        confidence=0.95,
        visibility_health=0.85,
        evidence={"ports_scanned": 50},
        explanation=[AlertExplanation(signal="scan_detector", contribution=0.95)],
        detector_version="scan_detector@1.0.0",
        evidence_hash="abc123",
        prev_hash="000000",
    )
    data = json.loads(alert.model_dump_json())
    assert "2026" in data["timestamp"]
    restored = Alert.model_validate(data)
    assert restored.severity == Severity.HIGH


def test_severity_mapping() -> None:
    """Severity thresholds match memory.md."""
    assert severity_from_score(0.95) == Severity.HIGH
    assert severity_from_score(0.90) == Severity.HIGH
    assert severity_from_score(0.80) == Severity.MEDIUM
    assert severity_from_score(0.70) == Severity.MEDIUM
    assert severity_from_score(0.50) == Severity.LOW
    assert severity_from_score(0.40) == Severity.LOW


# ── Normaliser tests ──


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
    assert flow.ts_start == 1735689600.123456
    assert flow.ts_end is not None
    assert abs(flow.ts_end - (1735689600.123456 + 1.234)) < 0.001


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
    assert flow.ts_end is None


def test_parse_dns_fields() -> None:
    """DNS fields are extracted when present."""
    dns_line = json.dumps(
        {
            "ts": 1735689600.0,
            "uid": "dns001",
            "id.orig_h": "1.2.3.4",
            "id.orig_p": 5353,
            "id.resp_h": "10.0.0.53",
            "id.resp_p": 53,
            "proto": "udp",
            "query": "example.com",
            "qtype_name": "A",
            "rcode": 0,
        }
    )
    flow = parse_zeek_conn_line(dns_line)
    assert flow is not None
    assert flow.dns_query == "example.com"
    assert flow.dns_qtype == "A"
    assert flow.dns_rcode == 0


def test_parse_ssl_fields() -> None:
    """TLS/SSL fields are extracted when present."""
    ssl_line = json.dumps(
        {
            "ts": 1735689600.0,
            "uid": "ssl001",
            "id.orig_h": "1.2.3.4",
            "id.orig_p": 44444,
            "id.resp_h": "10.0.0.1",
            "id.resp_p": 443,
            "proto": "tcp",
            "ja3": "abc123hash",
            "ja4": "t13d301200_abc",
            "server_name": "example.com",
            "version": "TLSv13",
        }
    )
    flow = parse_zeek_conn_line(ssl_line)
    assert flow is not None
    assert flow.tls_ja3 == "abc123hash"
    assert flow.tls_ja4 == "t13d301200_abc"
    assert flow.tls_sni == "example.com"
    assert flow.tls_version == "TLSv13"


# ── Normaliser class tests ──


def test_normaliser_monotonic_seq() -> None:
    """Normaliser produces monotonic sequence numbers."""
    norm = Normaliser(sensor_id="test-sensor")
    flow1 = norm.parse_line(SAMPLE_CONN_LINE)
    flow2 = norm.parse_line(SAMPLE_CONN_LINE)
    assert flow1 is not None and flow2 is not None
    assert flow2.seq == flow1.seq + 1
    assert flow1.sensor_id == "test-sensor"


# ── Stream key tests ──


def test_stream_keys_deterministic() -> None:
    """Stream shard keys are deterministic for the same IP."""
    flow = FlowRecord(
        uid="test",
        ts_start=1.0,
        src_ip="192.168.1.10",
        src_port=1234,
        dst_ip="10.0.0.1",
        dst_port=80,
        proto="tcp",
        seq=1,
    )
    key1 = stream_key_for_src(flow)
    key2 = stream_key_for_src(flow)
    assert key1 == key2
    assert key1.startswith("flows:src:")

    dst_key = stream_key_for_dst(flow)
    assert dst_key.startswith("flows:dst:")


def test_flow_to_stream_entry() -> None:
    """Flow converts to Redis-compatible entry."""
    flow = FlowRecord(
        uid="test",
        ts_start=1.0,
        src_ip="1.2.3.4",
        src_port=1234,
        dst_ip="5.6.7.8",
        dst_port=80,
        proto="tcp",
        seq=1,
    )
    entry = flow_to_stream_entry(flow)
    assert "data" in entry
    restored = FlowRecord.model_validate_json(entry["data"])
    assert restored.uid == "test"


# ── Publisher tests (mocked Redis) ──


@pytest.mark.anyio
async def test_publisher_publishes_to_both_streams() -> None:
    """Publisher sends to both src and dst streams (ARC-5)."""
    mock_redis = AsyncMock()
    mock_redis.xadd = AsyncMock()

    publisher = RedisStreamPublisher(mock_redis)
    flow = FlowRecord(
        uid="pub-test",
        ts_start=1.0,
        src_ip="192.168.1.10",
        src_port=1234,
        dst_ip="10.0.0.1",
        dst_port=80,
        proto="tcp",
        seq=1,
    )

    await publisher.publish(flow)
    assert mock_redis.xadd.call_count == 2

    # Verify the two calls used different stream keys
    call_args = [call.args[0] for call in mock_redis.xadd.call_args_list]
    assert any("src" in k for k in call_args)
    assert any("dst" in k for k in call_args)


@pytest.mark.anyio
async def test_publisher_batch() -> None:
    """Batch publish returns count of successful publishes."""
    mock_redis = AsyncMock()
    mock_redis.xadd = AsyncMock()

    publisher = RedisStreamPublisher(mock_redis)
    flows = [
        FlowRecord(
            uid=f"batch-{i}",
            ts_start=float(i),
            src_ip="1.2.3.4",
            src_port=1000 + i,
            dst_ip="5.6.7.8",
            dst_port=80,
            proto="tcp",
            seq=i,
        )
        for i in range(5)
    ]

    count = await publisher.publish_batch(flows)
    assert count == 5
    assert mock_redis.xadd.call_count == 10  # 2 per flow
