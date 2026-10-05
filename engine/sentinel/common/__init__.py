"""SENTINEL-X common schemas.

Pydantic models for the core data types (PY-3).
Schema v1.0 per architecture.md section 6.3 and memory.md §7.
Full schemas defined in T-010; this is the minimal flow schema for hello-flow.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class FlowRecord(BaseModel):
    """Minimal flow record from normalised Zeek conn.log.

    Timestamps are float epoch seconds internally (DAT-1).
    """

    uid: str = Field(description="Zeek unique connection ID")
    ts: float = Field(description="Connection start time (epoch seconds)")
    src_ip: str = Field(description="Source IP address")
    src_port: int = Field(description="Source port")
    dst_ip: str = Field(description="Destination IP address")
    dst_port: int = Field(description="Destination port")
    proto: str = Field(description="Transport protocol (tcp/udp/icmp)")
    service: str | None = Field(default=None, description="Application protocol")
    duration: float | None = Field(default=None, description="Connection duration (seconds)")
    orig_bytes: int | None = Field(default=None, description="Bytes from originator")
    resp_bytes: int | None = Field(default=None, description="Bytes from responder")
    conn_state: str | None = Field(default=None, description="Connection state (S0, SF, etc)")
    seq: int = Field(description="Sequence number assigned by normaliser")
