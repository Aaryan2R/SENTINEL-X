"""Fail if a Linux interface transmits during a command."""

from __future__ import annotations

import argparse
import os
import platform
import subprocess
import sys
from pathlib import Path


def read_counter(interface: str) -> int:
    path = Path("/sys/class/net") / interface / "statistics" / "tx_packets"
    try:
        return int(path.read_text(encoding="ascii").strip())
    except (FileNotFoundError, OSError, ValueError) as exc:
        raise SystemExit(f"Cannot read TX counter for {interface}: {exc}") from exc


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", required=True)
    parser.add_argument("command", nargs="+")
    args = parser.parse_args()
    if platform.system() != "Linux":
        raise SystemExit("TX counter proof requires Linux/WSL; Windows demo status is emulated.")
    before = read_counter(args.interface)
    env = os.environ.copy()
    env["SENTINEL_CAPTURE_INTERFACE"] = args.interface
    result = subprocess.run(args.command, env=env, check=False)  # noqa: S603
    after = read_counter(args.interface)
    if result.returncode != 0:
        raise SystemExit(result.returncode)
    if after != before:
        raise SystemExit(f"TX counter changed on {args.interface}: {before} -> {after}")
    sys.stdout.write(f"TX=0 verified on {args.interface} ({before} packets before and after)\n")


if __name__ == "__main__":
    main()
