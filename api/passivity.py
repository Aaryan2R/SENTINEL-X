"""Passivity attestation helpers for the local demo and Linux deployments."""

from __future__ import annotations

import os
import platform
from pathlib import Path

from sentinel.monitor import PassivityMonitor


def tx_packets() -> int | None:
    """Read the kernel TX counter for the configured capture interface."""
    interface = os.environ.get("SENTINEL_CAPTURE_INTERFACE")
    if platform.system() != "Linux" or not interface:
        return None
    counter = Path("/sys/class/net") / interface / "statistics" / "tx_packets"
    try:
        return int(counter.read_text(encoding="ascii").strip())
    except (FileNotFoundError, OSError, ValueError):
        return None


def snapshot() -> dict[str, int | str | None]:
    """Return measured Linux attestation or an explicit demo fallback."""
    sample = PassivityMonitor().sample()
    return {
        "tx_packets": sample.tx_packets,
        "status": sample.status,
        "mode": sample.mode,
        "interface": sample.interface,
        "policy_hash": sample.policy_hash,
    }
