"""Bounded, deterministic Phase 1 detectors.

The demo deliberately uses metadata-only rules so every score is explainable
and reproducible without downloading a model or contacting an external service.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from math import floor, log2
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

from sentinel.common.schemas import (
    CorrelationGroup,
    FlowRecord,
    Signal,
    SignalContribution,
)


@dataclass
class _EntityWindow:
    flows: deque[FlowRecord] = field(default_factory=lambda: deque(maxlen=2_000))


class DetectorEngine:
    """Evaluate the Phase 1 detector set over a bounded event-time window."""

    def __init__(self, window_seconds: float = 60.0) -> None:
        self.window_seconds = window_seconds
        self._entities: dict[str, _EntityWindow] = defaultdict(_EntityWindow)

    def evaluate(self, flow: FlowRecord) -> list[Signal]:
        state = self._entities[flow.src_ip]
        state.flows.append(flow)
        cutoff = flow.ts_start - self.window_seconds
        bucket_start = floor(flow.ts_start / self.window_seconds) * self.window_seconds
        window = (bucket_start, bucket_start + self.window_seconds)
        while state.flows and state.flows[0].ts_start < cutoff:
            state.flows.popleft()
        flows = list(state.flows)
        signals: list[Signal] = []
        if len({item.dst_port for item in flows if item.dst_ip == flow.dst_ip}) >= 20:
            ports = len({item.dst_port for item in flows if item.dst_ip == flow.dst_ip})
            score = min(1.0, 0.45 + ports / 100)
            signals.append(
                Signal(
                    entity=flow.src_ip,
                    threat_class="PORT_SCAN",
                    score=score,
                    group=CorrelationGroup.SCAN,
                    evidence={"unique_ports": ports, "target": flow.dst_ip},
                    contributions=[SignalContribution(name="unique_ports", value=score)],
                    window=window,
                    detector="port_scan@1.0.0",
                    attack_technique="T1046",
                )
            )

        syns = [
            item for item in flows if item.proto.lower() == "tcp" and "S" in (item.history or "S")
        ]
        if len(syns) >= 20:
            incomplete = sum(
                1 for item in syns if (item.conn_state or "").upper() in {"S0", "REJ", "RSTO"}
            )
            ratio = incomplete / len(syns)
            if ratio >= 0.7:
                score = min(1.0, 0.55 + ratio * 0.4)
                signals.append(
                    Signal(
                        entity=flow.src_ip,
                        threat_class="SYN_FLOOD",
                        score=score,
                        group=CorrelationGroup.VOLUME,
                        evidence={
                            "syn_rate": len(syns) / self.window_seconds,
                            "incomplete_ratio": ratio,
                        },
                        contributions=[
                            SignalContribution(name="incomplete_handshakes", value=ratio),
                            SignalContribution(name="syn_rate", value=min(1.0, len(syns) / 100)),
                        ],
                        window=window,
                        detector="syn_flood@1.0.0",
                        attack_technique="T1498.001",
                    )
                )

        udp = [item for item in flows if item.proto.lower() == "udp"]
        if len(udp) >= 30:
            destinations = len({item.dst_ip for item in udp})
            bytes_total = sum(item.resp_bytes or 0 for item in udp)
            sources = len({item.src_ip for item in udp})
            entropy = _entropy(item.dst_ip for item in udp)
            score = min(1.0, 0.45 + len(udp) / 150 + (bytes_total / 1_000_000))
            signals.append(
                Signal(
                    entity=flow.dst_ip,
                    threat_class="VOLUMETRIC_DDOS",
                    score=score,
                    group=CorrelationGroup.VOLUME,
                    evidence={
                        "packets": len(udp),
                        "unique_destinations": destinations,
                        "unique_sources": sources,
                        "destination_entropy": round(entropy, 3),
                    },
                    contributions=[
                        SignalContribution(name="packet_rate", value=min(1.0, len(udp) / 100))
                    ],
                    window=window,
                    detector="volumetric_ddos@1.0.0",
                    attack_technique="T1498",
                )
            )

        if flow.dns_query and _looks_like_dga(flow.dns_query):
            score = 0.82
            signals.append(
                Signal(
                    entity=flow.src_ip,
                    threat_class="DGA",
                    score=score,
                    group=CorrelationGroup.DNS,
                    evidence={"query": flow.dns_query, "length": len(flow.dns_query)},
                    contributions=[
                        SignalContribution(name="label_entropy", value=score),
                        SignalContribution(name="digit_ratio", value=_digit_ratio(flow.dns_query)),
                    ],
                    window=window,
                    detector="dga_rules@1.0.0",
                    attack_technique="T1568.002",
                )
            )
        return signals


def _digit_ratio(value: str) -> float:
    return sum(char.isdigit() for char in value) / max(1, len(value))


def _looks_like_dga(query: str) -> bool:
    label = query.rstrip(".").split(".")[0]
    if len(label) < 12:
        return False
    digits = _digit_ratio(label)
    vowels = sum(char in "aeiou" for char in label.lower()) / len(label)
    return digits >= 0.18 or vowels < 0.2


def _entropy(values: Iterable[object]) -> float:
    counts: dict[str, int] = defaultdict(int)
    total = 0
    for value in values:
        counts[str(value)] += 1
        total += 1
    return (
        -sum((count / total) * log2(count / total) for count in counts.values()) if total else 0.0
    )
