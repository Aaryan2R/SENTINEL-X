"""SENTINEL-X traffic generator v1.

Generates seeded, deterministic PCAP files for demo and testing.
Scenarios: normal traffic + port scan.

This is demo tooling only (Scapy is GPL). Never import from engine/.
INV-4: no outbound network calls — all traffic is synthetic.
TST-1: fixed seed, deterministic output.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from scapy.all import (  # type: ignore[import-untyped]
    DNS,
    DNSQR,
    IP,
    TCP,
    UDP,
    Ether,
    wrpcap,
)


@dataclass
class ScenarioConfig:
    """Configuration for a traffic scenario."""

    name: str
    seed: int
    description: str
    label: str  # "benign" or attack type
    packets: list[dict[str, Any]] = field(default_factory=list)


def _seeded_random(seed: int) -> random.Random:
    """Create a seeded Random instance for deterministic generation."""
    return random.Random(seed)


def _rand_mac(rng: random.Random) -> str:
    """Generate a deterministic random MAC address using seeded RNG."""
    octets = [rng.randint(0x00, 0xFF) for _ in range(6)]
    # Ensure locally administered, unicast
    octets[0] = (octets[0] | 0x02) & 0xFE
    return ":".join(f"{b:02x}" for b in octets)


def generate_normal_traffic(rng: random.Random, count: int = 100) -> list[Any]:
    """Generate benign traffic: HTTP, DNS, HTTPS connections."""
    packets = []
    src_ips = [f"192.168.1.{rng.randint(10, 50)}" for _ in range(5)]
    dst_ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    domains = ["example.com", "cdn.example.com", "api.example.com", "static.example.com"]

    for i in range(count):
        src = rng.choice(src_ips)
        dst = rng.choice(dst_ips)
        sport = rng.randint(1024, 65535)
        ip_id = rng.randint(0, 65535)
        tcp_seq = rng.randint(0, 2**32 - 1)

        pkt_type = rng.choices(["tcp_http", "tcp_https", "dns"], weights=[40, 40, 20])[0]

        if pkt_type == "tcp_http":
            pkt = (
                Ether(src=_rand_mac(rng), dst=_rand_mac(rng))
                / IP(src=src, dst=dst, id=ip_id)
                / TCP(sport=sport, dport=80, flags="S", seq=tcp_seq)
            )
        elif pkt_type == "tcp_https":
            pkt = (
                Ether(src=_rand_mac(rng), dst=_rand_mac(rng))
                / IP(src=src, dst=dst, id=ip_id)
                / TCP(sport=sport, dport=443, flags="S", seq=tcp_seq)
            )
        else:
            domain = rng.choice(domains)
            pkt = (
                Ether(src=_rand_mac(rng), dst=_rand_mac(rng))
                / IP(src=src, dst="10.0.0.53", id=ip_id)
                / UDP(sport=sport, dport=53)
                / DNS(id=ip_id & 0xFFFF, rd=1, qd=DNSQR(qname=domain))
            )

        packets.append(pkt)

    return packets


def generate_port_scan(
    rng: random.Random,
    scanner_ip: str = "192.168.1.100",
    target_ip: str = "10.0.0.1",
    port_count: int = 50,
) -> list[Any]:
    """Generate a vertical port scan (SYN scan on sequential ports)."""
    packets = []
    sport = rng.randint(1024, 65535)

    # Scan common ports plus random ones
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 8080, 8443]
    random_ports = [rng.randint(1, 65535) for _ in range(port_count - len(common_ports))]
    scan_ports = common_ports + random_ports
    rng.shuffle(scan_ports)

    for dport in scan_ports:
        ip_id = rng.randint(0, 65535)
        tcp_seq = rng.randint(0, 2**32 - 1)
        pkt = (
            Ether(src=_rand_mac(rng), dst=_rand_mac(rng))
            / IP(src=scanner_ip, dst=target_ip, id=ip_id)
            / TCP(sport=sport, dport=dport, flags="S", seq=tcp_seq)
        )
        packets.append(pkt)

    return packets


def generate_scenario(
    scenario_name: str, seed: int, output_dir: Path
) -> tuple[Path, dict[str, Any]]:
    """Generate a complete scenario with PCAP and label file."""
    rng = _seeded_random(seed)
    output_dir.mkdir(parents=True, exist_ok=True)

    if scenario_name == "normal":
        packets = generate_normal_traffic(rng, count=100)
        label = "benign"
        description = "Normal HTTP/HTTPS/DNS traffic from internal hosts"
    elif scenario_name == "port_scan":
        # Mix: some normal traffic, then a scan
        normal_pkts = generate_normal_traffic(rng, count=30)
        scan_pkts = generate_port_scan(rng)
        packets = normal_pkts + scan_pkts
        label = "port_scan"
        description = "Normal traffic followed by vertical SYN port scan"
    else:
        print(f"Unknown scenario: {scenario_name}", file=sys.stderr)
        sys.exit(1)

    pcap_path = output_dir / f"{scenario_name}.pcap"
    label_path = output_dir / f"{scenario_name}.label.json"

    # Set deterministic timestamps (TST-1): fixed base + increments
    base_time = 1735689600.0  # 2026-01-01T00:00:00Z
    for idx, pkt in enumerate(packets):
        pkt.time = base_time + idx * 0.01  # 10ms intervals

    wrpcap(str(pcap_path), packets)

    label_data = {
        "scenario": scenario_name,
        "seed": seed,
        "description": description,
        "label": label,
        "packet_count": len(packets),
        "pcap_file": pcap_path.name,
    }

    if scenario_name == "port_scan":
        label_data["attack_details"] = {
            "type": "vertical_syn_scan",
            "scanner_ip": "192.168.1.100",
            "target_ip": "10.0.0.1",
            "technique": "T1046",  # ATT&CK: Network Service Discovery
        }

    label_path.write_text(json.dumps(label_data, indent=2))

    return pcap_path, label_data


def main() -> None:
    """Generate traffic scenarios."""
    parser = argparse.ArgumentParser(description="SENTINEL-X traffic generator v1")
    parser.add_argument(
        "--scenario",
        choices=["normal", "port_scan", "all"],
        default="all",
        help="Scenario to generate",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for deterministic generation (default: 42)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).parent.parent / "scenarios",
        help="Output directory",
    )

    args = parser.parse_args()

    scenarios = ["normal", "port_scan"] if args.scenario == "all" else [args.scenario]

    for name in scenarios:
        pcap_path, label_data = generate_scenario(name, seed=args.seed, output_dir=args.output)
        print(f"[sentinel] Generated {name}: {pcap_path} ({label_data['packet_count']} packets)")


if __name__ == "__main__":
    main()
