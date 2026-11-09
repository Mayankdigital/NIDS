#!/usr/bin/env bash
# =============================================================================
# gen_network_recon.sh — NETWORK_RECON (class 5) traffic generator
# Target: your own machine (127.0.0.1)
# Interface: lo
# =============================================================================
# HOW THIS DIFFERS FROM PORT_SCAN (important for class separability):
#
#   PORT_SCAN     = rapid, exhaustive port enumeration
#                   • Many unique dst_ports touched
#                   • ~1-3 packets per flow
#                   • Very short flow duration (ms)
#                   • High new-flow rate (thousands/min)
#
#   NETWORK_RECON = purposeful service identification and fingerprinting
#                   • Few target ports (known services only)
#                   • More packets per flow (OS probe sequences, banner grabs)
#                   • Longer per-flow duration (waiting for banner response)
#                   • Slower rate (seconds between probes, not milliseconds)
#                   • Includes service version probing, NSE scripts
#                   • Inter-flow delay is human-like or deliberate
#
# NFStream distinguishable features:
#   RECON has: larger bidirectional_packets/flow, longer duration/flow,
#              lower new-flow rate, fewer unique dst_port values
# =============================================================================
set -euo pipefail

TARGET="127.0.0.1"

echo "========================================"
echo "  NETWORK_RECON Traffic Generator"
echo "  Target: $TARGET (own machine)"
echo "  Type: Service enum + OS fingerprinting"
echo "  Interface: lo"
echo "  Rate: SLOW (deliberate, probe-style)"
echo "========================================"

if ! command -v nmap &>/dev/null; then
    echo "[ERROR] nmap not found. Install: sudo apt install nmap"
    exit 1
fi

# Phase 1: OS fingerprinting (multi-packet probes, slow)
echo "[RECON-1] OS fingerprinting"
sudo nmap -O --osscan-guess \
    -p 22,80,443,8080,8081,8082 \
    --max-retries 2 --host-timeout 60s \
    -T2 "$TARGET" > /dev/null 2>&1 || true
sleep 5

# Phase 2: Service version detection (banner grabbing)
echo "[RECON-2] Service version detection"
nmap -sV --version-intensity 7 \
    -p 22,80,443,8080,8081,8082,3306,5432,6379 \
    --host-timeout 60s -T2 \
    "$TARGET" > /dev/null 2>&1 || true
sleep 5

# Phase 3: NSE script enumeration
echo "[RECON-3] NSE script enumeration"
nmap --script="http-headers,http-methods,http-title,banner" \
    -p 8080,8081,8082 \
    --host-timeout 60s -T2 \
    "$TARGET" > /dev/null 2>&1 || true
sleep 5

# Phase 4: Manual banner grabbing via curl (slow, human-paced)
echo "[RECON-4] Manual banner grabbing"
for PORT in 8080 8081 8082; do
    echo "  Probing port $PORT ..."
    curl -sv --connect-timeout 3 --max-time 5 \
        "http://$TARGET:$PORT/" 2>&1 | grep -E "^[<>]" | head -10 || true
    sleep 3
done

# Phase 5: Slow repeated probes (mimics human-speed recon)
echo "[RECON-5] Slow repeated service probes"
for round in $(seq 1 5); do
    echo "  Round $round/5"
    nmap -sV --version-intensity 3 \
        -p 8080,8081,8082 --max-retries 1 \
        -T2 --host-timeout 30s \
        "$TARGET" > /dev/null 2>&1 || true
    DELAY=$(( RANDOM % 10 + 5 ))
    sleep "$DELAY"
done

echo "[RECON] Complete."
