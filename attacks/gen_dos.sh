#!/usr/bin/env bash
# =============================================================================
# gen_dos.sh  —  Generate DoS-like (class 2) traffic pattern
# Target: local HTTP service on 127.0.0.1:8080
# Interface: lo
# =============================================================================
# SINGLE-LAPTOP LIMITATION:
#   The attack source and target share the same CPU and kernel network stack.
#   Linux loopback throughput is extremely high (limited by CPU, not network).
#   The service may become slow, but the OS stack itself is rarely affected.
#   KEEP RATE LIMITS SANE — this is for generating labeled flow patterns,
#   not for genuinely trying to crash your own machine.
#
# NFStream observable characteristics:
#   - Very high packets/sec in short time window
#   - Very high bytes/sec
#   - Many flows from same src_ip to same dst_ip:dst_port
#   - High new-flow rate
#   - SYN-heavy TCP flag pattern (for SYN flood variant)
#   - Short individual flow durations with high packet count
# =============================================================================
set -euo pipefail

TARGET="127.0.0.1"
TARGET_PORT="8080"
DURATION="${1:-120}"

echo "========================================"
echo "  DoS Pattern Traffic Generator"
echo "  Target: $TARGET:$TARGET_PORT"
echo "  Duration: ${DURATION}s"
echo "  Interface: lo"
echo "  NOTE: Rate-limited — own machine only"
echo "========================================"

AB_PID=""
HPING_PID=""

# Method 1: Apache Bench HTTP flood (controlled concurrency)
if command -v ab &>/dev/null; then
    echo "[DOS-1] Apache Bench HTTP flood (concurrency=50)"
    ab -n 100000 -c 50 -k \
        "http://$TARGET:$TARGET_PORT/" \
        > /tmp/nids_dos_ab.txt 2>&1 &
    AB_PID=$!
    echo "[DOS-1] ab PID=$AB_PID"
else
    echo "[DOS-1] ab not found (install: sudo apt install apache2-utils)"
    echo "[DOS-1] Falling back to curl loop"
    ( END=$(( $(date +%s) + DURATION ))
      while [ $(date +%s) -lt $END ]; do
          curl -s -o /dev/null "http://$TARGET:$TARGET_PORT/" &
          curl -s -o /dev/null "http://$TARGET:$TARGET_PORT/health" &
          sleep 0.05
      done ) &
    AB_PID=$!
fi

sleep 5

# Method 2: hping3 SYN flood (rate-limited)
if command -v hping3 &>/dev/null; then
    echo "[DOS-2] hping3 SYN flood — rate-limited"
    sudo hping3 --syn -p "$TARGET_PORT" \
        --count 30000 --interval u2000 \
        "$TARGET" > /tmp/nids_dos_hping3.txt 2>&1 &
    HPING_PID=$!
    echo "[DOS-2] hping3 PID=$HPING_PID"
else
    echo "[DOS-2] hping3 not found (install: sudo apt install hping3)"
fi

echo "[DOS] Running for ${DURATION}s ..."
sleep "$DURATION"

echo "[DOS] Stopping ..."
[ -n "$AB_PID" ]    && kill "$AB_PID"    2>/dev/null || true
[ -n "$HPING_PID" ] && sudo kill "$HPING_PID" 2>/dev/null || true
wait 2>/dev/null || true
echo "[DOS] Done."
