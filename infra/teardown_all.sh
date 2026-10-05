#!/usr/bin/env bash
# SENTINEL-X: Full passivity teardown
# Usage: sudo ./teardown_all.sh [namespace_name] [host_veth]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

NS_NAME="${1:-sentinel_sensor}"
VETH_HOST="${2:-veth_host}"

echo "=========================================="
echo " SENTINEL-X Passivity Teardown"
echo "=========================================="

# nftables cleanup happens automatically when namespace is deleted
"${SCRIPT_DIR}/netns/teardown.sh" "${NS_NAME}" "${VETH_HOST}"

echo ""
echo " Teardown complete."
echo "=========================================="
