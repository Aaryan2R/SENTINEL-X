"""Passivity and visibility monitors for Phase 2."""

from __future__ import annotations

import hashlib
import json
import os
import platform
from dataclasses import dataclass, field
from pathlib import Path


def read_tx_packets(interface: str | None = None) -> int | None:
    """Read Linux kernel TX packets; return None when unavailable."""
    name = interface or os.getenv("SENTINEL_CAPTURE_INTERFACE")
    if platform.system() != "Linux" or not name:
        return None
    try:
        return int((Path("/sys/class/net") / name / "statistics" / "tx_packets").read_text())
    except (FileNotFoundError, OSError, ValueError):
        return None


@dataclass(frozen=True)
class PassivitySample:
    tx_packets: int
    status: str
    mode: str
    interface: str | None = None
    policy_hash: str | None = None


class PassivityMonitor:
    """Collect passivity evidence without claiming unavailable host facts."""

    def __init__(self, interface: str | None = None) -> None:
        self.interface = interface or os.getenv("SENTINEL_CAPTURE_INTERFACE")

    def sample(self) -> PassivitySample:
        tx = read_tx_packets(self.interface)
        policy = os.getenv("SENTINEL_POLICY_TEXT", "")
        policy_hash = hashlib.sha256(policy.encode()).hexdigest() if policy else None
        if tx is None:
            return PassivitySample(0, "emulated", "software-emulation", self.interface, policy_hash)
        return PassivitySample(
            tx,
            "verified" if tx == 0 else "failed",
            "linux-kernel-counter",
            self.interface,
            policy_hash,
        )


@dataclass
class VisibilityMonitor:
    capture_loss: float = 0.0
    interface_drops: float = 0.0
    sequence_gaps: float = 0.0
    queue_lag: float = 0.0
    shedding: list[str] = field(default_factory=list)

    @property
    def health(self) -> float:
        return max(
            0.0,
            1.0
            - (
                0.4 * min(1.0, self.capture_loss)
                + 0.3 * min(1.0, self.interface_drops)
                + 0.2 * min(1.0, self.sequence_gaps)
                + 0.1 * min(1.0, self.queue_lag)
            ),
        )

    def observe_sequence(self, previous: int | None, current: int) -> None:
        if previous is not None and current > previous + 1:
            self.sequence_gaps += current - previous - 1

    def observe_capture_loss(self, lost: int, seen: int) -> None:
        if seen > 0:
            self.capture_loss = min(1.0, max(0.0, lost / seen))

    def observe_lag(self, lag: float, threshold: float = 100.0) -> None:
        self.queue_lag = min(1.0, max(0.0, lag / max(1.0, threshold)))

    def shed_if_needed(self, lag: float, threshold: float = 100.0) -> list[str]:
        self.observe_lag(lag, threshold)
        if self.queue_lag >= 1.0 and "secondary-detectors" not in self.shedding:
            self.shedding.append("secondary-detectors")
        return list(self.shedding)

    def as_dict(self) -> dict[str, object]:
        return {
            "health": round(self.health, 4),
            "capture_loss": self.capture_loss,
            "interface_drops": self.interface_drops,
            "sequence_gaps": self.sequence_gaps,
            "queue_lag": self.queue_lag,
            "shedding": list(self.shedding),
        }


def canonical_policy_hash(ruleset: dict[str, object]) -> str:
    return hashlib.sha256(json.dumps(ruleset, sort_keys=True).encode()).hexdigest()
