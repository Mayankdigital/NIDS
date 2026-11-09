#!/usr/bin/env bash
# =============================================================================
# gen_port_scan.sh  —  Generate PORT_SCAN (class 1) traffic
# Target: your own machine (127.0.0.1)
# Tool: nmap
# Interface: lo  (because target is 127.0.0.1)
# =============================================================================
# PORT_SCAN flow-level characteristics (visible to NFStream):
#   - Many short-lived TCP flows: rapid port progression
#   - High count of unique destination ports
#   - Very small packet count per flow (often 1-3 pkts: SYN, RST or SYN-ACK)
#   - Very short flow duration (milliseconds)
#   - Very low bytes per flow
#   - High new-flow rate per second
#
# This DIFFERS from NETWORK_RECON in:
#   PORT_SCAN:   high port count, tiny per-flow stats, very fast
#   NETWORK_RECON: fewer ports, more packets per flow, slower rate
# =============================================================================
set -euo pipefail

TARGET="127.0.0.1"

echo "========================================"
echo "  PORT_SCAN Traffic Generator"
echo "  Target: $TARGET (your own machine only)"
echo "  Interface: lo"
echo "========================================"

if ! command -v nmap &>/dev/null; then
    echo "[ERROR] nmap not found. Install: sudo apt install nmap"
    exit 1
fi

# Scan 1: SYN scan common ports
echo "[SCAN 1] SYN scan ports 1-1024"
nmap -sS -p 1-1024 --max-retries 1 --host-timeout 30s \
    -T4 --min-rate 100 "$TARGET" > /dev/null 2>&1 || true
sleep 2

# Scan 2: Full TCP connect scan
echo "[SCAN 2] TCP connect scan ports 1-65535"
nmap -sT -p 1-65535 --max-retries 0 --host-timeout 120s \
    -T4 --min-rate 500 "$TARGET" > /dev/null 2>&1 || true
sleep 2

# Scan 3: UDP scan of common ports
echo "[SCAN 3] UDP scan common ports"
nmap -sU -p 53,67,68,69,123,137,138,161,500 --max-retries 0 \
    -T4 --host-timeout 30s "$TARGET" > /dev/null 2>&1 || true
sleep 2

# Scan 4: Version detection on known ports
echo "[SCAN 4] Version detection scan"
nmap -sV --version-intensity 3 -p 22,80,443,8080,8081,8082 \
    --host-timeout 30s "$TARGET" > /dev/null 2>&1 || true
sleep 2

# Scan 5: Repeat quick scans for volume
echo "[SCAN 5] Repeated quick scans for flow volume"
for i in $(seq 1 5); do
    echo "  Repeat $i/5 ..."
    nmap -sT -p 1-1024 --max-retries 0 -T5 --min-rate 1000 \
        "$TARGET" -oN /tmp/nids_portscan_repeat_$i.txt 2>&1 | tail -2
    sleep 1
done

echo "[SCAN] Complete."
