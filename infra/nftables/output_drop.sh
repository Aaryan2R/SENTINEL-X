#!/usr/bin/env bash
# SENTINEL-X: nftables output drop on the sensor namespace
# Belt-and-suspenders with tc: drops all output at the nftables layer.
#
# Usage: sudo ./output_drop.sh [namespace_name]

set -euo pipefail

NS_NAME="${1:-sentinel_sensor}"

echo "[sentinel] Applying nftables output drop in ${NS_NAME}"

# Create nftables ruleset: drop all output
ip netns exec "${NS_NAME}" nft -f - <<'EOF'
table inet sentinel_passivity {
    chain output {
        type filter hook output priority 0; policy drop;
        # Log dropped packets for attestation
        counter log prefix "SENTINEL_TX_DROP: " drop
    }
}
EOF

# Show the ruleset for verification
ip netns exec "${NS_NAME}" nft list ruleset

echo "[sentinel] nftables output drop active in ${NS_NAME}"
