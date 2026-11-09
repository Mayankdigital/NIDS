#!/usr/bin/env bash
# =============================================================================
# gen_ddos_simulated.sh — DDOS (class 3) via TCP SYN flood with spoofed IPs
# =============================================================================
#
# HOW THIS WORKS:
#   hping3 --syn --rand-source sends TCP SYN packets to 127.0.0.1:8080
#   with a DIFFERENT random source IP for every single packet.
#
#   NFStream groups packets into flows by 5-tuple:
#     (src_ip, src_port, dst_ip, dst_port, protocol)
#
#   Since src_ip changes every packet → each packet = a NEW unique flow.
#   4 parallel threads × 5000 pkts/sec × 60s = ~1,200,000 flows per run.
#
# WHY THIS IS QUALITY DATA (SYN flood is the most common real DDoS type):
#   Real DDoS signature vs. other classes:
#     DDOS  → protocol=TCP, dst_port=8080, bidirectional_packets=1-2,
#              bidirectional_bytes=40-80B, expiration=RST, many random src_ips
#     DOS   → protocol=TCP, dst_port=8080, bidirectional_packets=10+,
#              bidirectional_bytes=1-5KB, full HTTP exchange (FIN expiration)
#     PORT_SCAN → protocol=TCP, many different dst_ports, few packets each
#
#   These features are all preserved after dropping src_ip, so XGBoost
#   can distinguish DDOS from DOS and PORT_SCAN cleanly.
#
# CAPTURE INTERFACE: lo (standard Ethernet, NFStream compatible)
# =============================================================================
set -uo pipefail

TARGET="127.0.0.1"
TARGET_PORT="8080"
DURATION="${1:-60}"
THREADS="${2:-6}"   # parallel hping3 processes

echo "======================================================"
echo "  DDOS Generator — TCP SYN Flood (Spoofed Sources)"
echo "  Target  : $TARGET:$TARGET_PORT"
echo "  Duration: ${DURATION}s"
echo "  Threads : $THREADS"
echo "  Expected: ~$(( THREADS * 5000 * DURATION )) flows"
echo "======================================================"

if ! command -v hping3 &>/dev/null; then
    echo "[ERROR] hping3 not found. Install: sudo apt install hping3"
    exit 1
fi

PIDS=()
for t in $(seq 1 "$THREADS"); do
    # Each thread: random source IP per packet, send to port 8080
    # --rand-source: different src_ip every packet = different flow
    # --interval u200: 5000 packets/sec per thread
    # --count 9999999: run until killed by timeout
    sudo hping3 --syn \
        -p "$TARGET_PORT" \
        --rand-source \
        --count 9999999 \
        --interval u200 \
        "$TARGET" > /dev/null 2>&1 &
    PIDS+=($!)
    echo "[DDOS] Thread $t started (PID=${PIDS[-1]})"
done

echo "[DDOS] Flooding for ${DURATION}s..."
sleep "$DURATION"

echo "[DDOS] Stopping all threads..."
for pid in "${PIDS[@]}"; do
    sudo kill "$pid" 2>/dev/null || true
done
wait 2>/dev/null || true
echo "[DDOS] Done."
