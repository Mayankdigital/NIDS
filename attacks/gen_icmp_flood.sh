#!/usr/bin/env bash
# =============================================================================
# gen_icmp_flood.sh  —  Generate ICMP_FLOOD (class 7) traffic
# =============================================================================
# WHY --rand-source maintains quality (not a hack):
#   Real ICMP floods (Smurf attacks, ICMP botnet floods) come from spoofed
#   or distributed source IPs. Using --rand-source correctly simulates this.
#
#   NFStream flow features that distinguish ICMP_FLOOD from everything else:
#     - protocol = 1 (ICMP) — no other class uses this
#     - Very high packet rate per flow
#     - Very short bidirectional_duration_ms
#     - Very small bidirectional_bytes (fixed-size ICMP echo header)
#     - dst_ip always 127.0.0.1 (or target)
#
#   Using --rand-source creates MANY distinct flows (one per src IP), which is
#   exactly what we need — more training rows with consistent ICMP characteristics.
#
# FLOW COUNT: 30s × ~2000 packets/s = ~60,000 packets = ~60,000 distinct flows
# =============================================================================
set -uo pipefail

TARGET="127.0.0.1"
DURATION="${1:-60}"

echo "========================================"
echo "  ICMP_FLOOD Generator"
echo "  Target: $TARGET"
echo "  Duration: ${DURATION}s"
echo "  Method: hping3 --rand-source (realistic spoofed-src DDoS)"
echo "  Expected flows: ~$(( DURATION * 800 ))+"
echo "========================================"

if ! command -v hping3 &>/dev/null; then
    echo "[ERROR] hping3 not found. Install: sudo apt install hping3"
    exit 1
fi

PIDS=()

# Launch multiple parallel hping3 processes to maximise packet rate
for thread in {1..4}; do
    sudo hping3 --icmp --rand-source \
        --count 200000 --interval u200 \
        "$TARGET" > /dev/null 2>&1 &
    PIDS+=($!)
    echo "[ICMP] Thread $thread started (PID=${PIDS[-1]})"
done

echo "[ICMP] Running for ${DURATION}s ..."
sleep "$DURATION"

echo "[ICMP] Stopping ..."
for pid in "${PIDS[@]}"; do
    sudo kill "$pid" 2>/dev/null || true
done
wait 2>/dev/null || true
echo "[ICMP] Done."
