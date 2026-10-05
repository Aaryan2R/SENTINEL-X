#!/usr/bin/env bash
# SENTINEL-X: Full passivity setup — namespace + tc + nftables
# Usage: sudo ./setup_all.sh [namespace_name] [host_veth] [sensor_veth]
# Teardown: sudo ./teardown_all.sh [namespace_name] [host_veth]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

NS_NAME="${1:-sentinel_sensor}"
VETH_HOST="${2:-veth_host}"
VETH_SENSOR="${3:-veth_sensor}"

echo "=========================================="
echo " SENTINEL-X Passivity Setup"
echo "=========================================="

# 1. Create namespace with veth pair
"${SCRIPT_DIR}/netns/setup.sh" "${NS_NAME}" "${VETH_HOST}" "${VETH_SENSOR}"

# 2. tc egress drop (backstop for AF_PACKET)
"${SCRIPT_DIR}/tc/egress_drop.sh" "${NS_NAME}" "${VETH_SENSOR}"

# 3. nftables output drop (belt-and-suspenders)
"${SCRIPT_DIR}/nftables/output_drop.sh" "${NS_NAME}"

echo ""
echo "=========================================="
echo " Setup complete. Sensor interface: ${VETH_SENSOR}"
echo " Namespace: ${NS_NAME}"
echo " TC egress drop: active"
echo " nftables output drop: active"
echo "=========================================="
