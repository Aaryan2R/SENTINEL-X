#!/usr/bin/env bash
# SENTINEL-X: Tear down the capture namespace
# Usage: sudo ./teardown.sh [namespace_name] [host_veth]

set -euo pipefail

NS_NAME="${1:-sentinel_sensor}"
VETH_HOST="${2:-veth_host}"

echo "[sentinel] Tearing down namespace: ${NS_NAME}"

# Delete namespace (also removes the veth pair)
if ip netns list | grep -qw "${NS_NAME}"; then
    ip netns del "${NS_NAME}"
    echo "[sentinel] Namespace ${NS_NAME} deleted"
else
    echo "[sentinel] Namespace ${NS_NAME} not found, skipping"
fi

# Clean up host veth if it still exists (shouldn't after netns del)
if ip link show "${VETH_HOST}" &>/dev/null; then
    ip link del "${VETH_HOST}"
    echo "[sentinel] Host veth ${VETH_HOST} deleted"
fi

echo "[sentinel] Teardown complete"
