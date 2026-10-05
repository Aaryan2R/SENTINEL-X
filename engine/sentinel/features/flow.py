"""Shared, payload-free features for offline training and live scoring."""

from __future__ import annotations

import math
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping
    from typing import Any

FEATURE_NAMES = (
    "duration",
    "orig_bytes",
    "resp_bytes",
    "orig_pkts",
    "resp_pkts",
    "byte_ratio",
    "packet_ratio",
    "dst_port",
    "is_tcp",
    "is_udp",
    "is_dns",
    "is_syn_failure",
)


def _number(value: Any) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def flow_features(flow: Mapping[str, Any]) -> dict[str, float]:
    """Extract deterministic metadata-only features from a flow mapping."""
    orig_bytes = _number(flow.get("orig_bytes"))
    resp_bytes = _number(flow.get("resp_bytes"))
    orig_pkts = _number(flow.get("orig_pkts"))
    resp_pkts = _number(flow.get("resp_pkts"))
    proto = str(flow.get("proto") or "").lower()
    state = str(flow.get("conn_state") or "").upper()
    return {
        "duration": _number(flow.get("duration")),
        "orig_bytes": orig_bytes,
        "resp_bytes": resp_bytes,
        "orig_pkts": orig_pkts,
        "resp_pkts": resp_pkts,
        "byte_ratio": resp_bytes / max(1.0, orig_bytes),
        "packet_ratio": resp_pkts / max(1.0, orig_pkts),
        "dst_port": _number(flow.get("dst_port")),
        "is_tcp": float(proto == "tcp"),
        "is_udp": float(proto == "udp"),
        "is_dns": float(
            str(flow.get("service") or "").lower() == "dns" or _number(flow.get("dst_port")) == 53
        ),
        "is_syn_failure": float(proto == "tcp" and state in {"S0", "REJ"}),
    }


def vector(flow: Mapping[str, Any]) -> list[float]:
    features = flow_features(flow)
    return [features[name] for name in FEATURE_NAMES]


def standardised_distance(values: list[float], mean: list[float], scale: list[float]) -> float:
    return math.sqrt(
        sum(
            ((value - center) / max(1e-9, spread)) ** 2
            for value, center, spread in zip(values, mean, scale, strict=True)
        )
    )
