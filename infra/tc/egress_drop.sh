#!/usr/bin/env bash
# SENTINEL-X: Drop all egress traffic on the sensor interface via tc
# Raw AF_PACKET sends bypass nftables output hooks, so tc is the backstop.
# See memory.md: "Raw AF_PACKET sends bypass nftables output hooks"
#
# Usage: sudo ./egress_drop.sh [namespace_name] [sensor_veth]

set -euo pipefail

NS_NAME="${1:-sentinel_sensor}"
VETH_SENSOR="${2:-veth_sensor}"

echo "[sentinel] Applying tc egress drop on ${VETH_SENSOR} in ${NS_NAME}"

# Add a prio qdisc and a filter that drops everything on egress
ip netns exec "${NS_NAME}" tc qdisc add dev "${VETH_SENSOR}" root prio bands 3 priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
ip netns exec "${NS_NAME}" tc filter add dev "${VETH_SENSOR}" parent 1:0 protocol all u32 match u32 0 0 action drop

# Verify: show the filter
ip netns exec "${NS_NAME}" tc filter show dev "${VETH_SENSOR}"

echo "[sentinel] tc egress drop active on ${VETH_SENSOR}"
