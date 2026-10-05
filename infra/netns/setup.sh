#!/usr/bin/env bash
# SENTINEL-X: Create isolated capture namespace
# Creates a veth pair where the sensor side has no IP, no ARP, no IPv6,
# ensuring INV-1 (sensor cannot transmit toward monitored network).
#
# Usage: sudo ./setup.sh [namespace_name] [host_veth] [sensor_veth]
# Teardown: ./teardown.sh [namespace_name] [host_veth]
#
# Requires: Linux kernel with netns support, iproute2

set -euo pipefail

NS_NAME="${1:-sentinel_sensor}"
VETH_HOST="${2:-veth_host}"
VETH_SENSOR="${3:-veth_sensor}"

echo "[sentinel] Creating namespace: ${NS_NAME}"

# Create the network namespace
ip netns add "${NS_NAME}"

# Create veth pair
ip link add "${VETH_HOST}" type veth peer name "${VETH_SENSOR}"

# Move sensor end into the namespace
ip link set "${VETH_SENSOR}" netns "${NS_NAME}"

# Host side: bring up (traffic source for replay)
ip link set "${VETH_HOST}" up

# Sensor side: NO IP address, ARP off, IPv6 off, promisc on (receive only)
ip netns exec "${NS_NAME}" ip link set lo up
ip netns exec "${NS_NAME}" ip link set "${VETH_SENSOR}" up
ip netns exec "${NS_NAME}" ip link set "${VETH_SENSOR}" arp off
ip netns exec "${NS_NAME}" sysctl -w "net.ipv6.conf.${VETH_SENSOR}.disable_ipv6=1" >/dev/null
ip netns exec "${NS_NAME}" ip link set "${VETH_SENSOR}" promisc on

# Verify: no IP assigned
ADDRS=$(ip netns exec "${NS_NAME}" ip -4 addr show "${VETH_SENSOR}" | grep -c "inet " || true)
if [ "${ADDRS}" -ne 0 ]; then
    echo "[sentinel] ERROR: sensor veth has an IP address — aborting" >&2
    exit 1
fi

echo "[sentinel] Namespace ${NS_NAME} ready. Sensor iface: ${VETH_SENSOR} (no IP, no ARP, no IPv6)"
echo "[sentinel] Next: apply tc egress drop and nftables output drop"
