"""SENTINEL-X data schemas v1.0.

Pydantic models for the core data contracts (PY-3, DAT-6).
Based on architecture.md sections 6.1-6.3 and memory.md section 7.

Schema version: 1.0 — additive changes only; bump version for breaking (DAT-6).
Timestamps: float epoch seconds internally (DAT-1); ISO-8601 UTC with Z for alerts.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator

# ── Enums ──


class Proto(StrEnum):
    """Transport protocol."""

    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    UNKNOWN = "unknown"


class Severity(StrEnum):
    """Alert severity per memory.md §7: P>=0.90 HIGH, 0.70-0.90 MED, 0.40-0.70 LOW."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class CorrelationGroup(StrEnum):
    """Signal correlation groups per architecture.md §8."""

    VOLUME = "volume"
    PERIODICITY = "periodicity"
    DNS = "dns"
    TLS = "tls"
    SCAN = "scan"


# ── Flow Record (§6.1) ──


class FlowRecord(BaseModel):
    """Normalised flow record from Zeek logs.

    Timestamps are float epoch seconds (DAT-1).
    Published to Redis streams sharded by src_ip (ARC-5).
    """

    # Identity and sequencing
    sensor_id: str = Field(default="default", description="Sensor identifier")
    seq: int = Field(description="Per-sensor monotonic sequence for gap detection")
    uid: str = Field(description="Zeek connection ID")

    # Timing
    ts_start: float = Field(description="Connection start time (epoch seconds)")
    ts_end: float | None = Field(default=None, description="Connection end time (epoch seconds)")

    # Five-tuple
    src_ip: str = Field(description="Source IP address")
    src_port: int = Field(description="Source port")
    dst_ip: str = Field(description="Destination IP address")
    dst_port: int = Field(description="Destination port")
    proto: str = Field(description="Transport protocol (tcp/udp/icmp)")

    # Connection metadata
    service: str | None = Field(default=None, description="Application protocol (http, dns, ssl)")
    conn_state: str | None = Field(default=None, description="Connection state (S0, SF, REJ, etc)")
    history: str | None = Field(default=None, description="Zeek connection history string")

    # Volume
    duration: float | None = Field(default=None, description="Connection duration (seconds)")
    orig_bytes: int | None = Field(default=None, description="Bytes from originator")
    resp_bytes: int | None = Field(default=None, description="Bytes from responder")
    orig_pkts: int | None = Field(default=None, description="Packets from originator")
    resp_pkts: int | None = Field(default=None, description="Packets from responder")

    # DNS fields
    dns_query: str | None = Field(default=None, description="DNS query name")
    dns_qtype: str | None = Field(default=None, description="DNS query type")
    dns_rcode: int | None = Field(default=None, description="DNS response code")

    # TLS fields
    tls_ja3: str | None = Field(default=None, description="JA3 fingerprint")
    tls_ja4: str | None = Field(default=None, description="JA4 fingerprint")
    tls_sni: str | None = Field(default=None, description="TLS server name indication")
    tls_version: str | None = Field(default=None, description="TLS version")


# ── Signal (§6.2) ──


class SignalContribution(BaseModel):
    """A single contribution to a signal score."""

    name: str = Field(description="Feature or rule name")
    value: float = Field(description="Contribution value")


class Signal(BaseModel):
    """Detector output — a single scored observation with evidence.

    DET-2: score calibrated to [0, 1].
    DET-3: evidence and contributions mandatory.
    """

    entity: str = Field(description="Entity key (e.g. source IP)")
    threat_class: str = Field(description="Threat classification (e.g. C2_BEACONING)")
    score: float = Field(ge=0.0, le=1.0, description="Calibrated risk score [0, 1]")
    group: CorrelationGroup = Field(description="Correlation group")
    evidence: dict[str, Any] = Field(description="Supporting evidence data")
    contributions: list[SignalContribution] = Field(
        min_length=1, description="Score contributions (DET-3: mandatory)"
    )
    window: tuple[float, float] = Field(description="Time window (start_ts, end_ts)")
    detector: str = Field(description="Detector name@version (DET-1)")
    attack_technique: str = Field(description="ATT&CK technique ID (e.g. T1046)")

    @field_validator("score")
    @classmethod
    def score_bounded(cls, v: float) -> float:
        """DET-2: scores must be calibrated to [0, 1]."""
        if not 0.0 <= v <= 1.0:
            msg = f"Score must be in [0, 1], got {v}"
            raise ValueError(msg)
        return v


# ── Alert (§6.3) ──


class AlertExplanation(BaseModel):
    """Explanation entry for an alert."""

    signal: str = Field(description="Signal/detector name")
    contribution: float = Field(description="Contribution to final score")
    details: str | None = Field(default=None, description="Human-readable detail")


class Alert(BaseModel):
    """Alert schema v1.0 per architecture.md §6.3.

    DAT-1: timestamp is ISO-8601 UTC with Z.
    DAT-6: schema_version is a contract; additive changes only.
    """

    schema_version: str = Field(default="1.0", description="Alert schema version")
    alert_id: str = Field(description="Unique alert identifier")
    incident_id: str | None = Field(default=None, description="Parent incident ID")
    timestamp: datetime = Field(description="Alert time (ISO-8601 UTC with Z)")

    # Flow reference
    flow_id: str | None = Field(default=None, description="Source flow UID")
    source_ip: str = Field(description="Source IP")
    destination_ip: str = Field(description="Destination IP")
    destination_port: int | None = Field(default=None, description="Destination port")

    # Classification
    threat_class: str = Field(description="Threat classification")
    attack_technique: str = Field(description="ATT&CK technique ID")
    kill_chain_stage: str | None = Field(default=None, description="Kill chain stage")

    # Scoring
    severity: Severity = Field(description="Alert severity")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score [0, 1]")
    visibility_health: float = Field(ge=0.0, le=1.0, description="Visibility Health at alert time")

    # Evidence and explanation
    evidence: dict[str, Any] = Field(description="Supporting evidence")
    explanation: list[AlertExplanation] = Field(description="Score contributions (EXP-2)")
    detector_version: str = Field(description="Detector name@version")

    # Hash chain (DAT-3)
    evidence_hash: str = Field(description="SHA-256 of canonical evidence JSON")
    prev_hash: str = Field(description="Previous evidence hash in chain")

    @field_validator("timestamp")
    @classmethod
    def timestamp_utc(cls, v: datetime) -> datetime:
        """DAT-1: ensure timestamp is UTC."""
        if v.tzinfo is None:
            return v.replace(tzinfo=UTC)
        return v.astimezone(UTC)


def severity_from_score(score: float) -> Severity:
    """Map fused score to severity per memory.md §7."""
    if score >= 0.90:
        return Severity.HIGH
    if score >= 0.70:
        return Severity.MEDIUM
    return Severity.LOW
