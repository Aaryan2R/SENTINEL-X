"""Passivity attestation helpers for the local demo and Linux deployments."""

from __future__ import annotations

import os
import platform
from pathlib import Path


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
    interface = os.environ.get("SENTINEL_CAPTURE_INTERFACE")
    measured = tx_packets()
    if measured is None:
        return {
            "tx_packets": 0,
            "status": "emulated",
            "mode": "software-emulation",
            "interface": interface,
        }
    return {
        "tx_packets": measured,
        "status": "verified" if measured == 0 else "failed",
        "mode": "linux-kernel-counter",
        "interface": interface,
    }
