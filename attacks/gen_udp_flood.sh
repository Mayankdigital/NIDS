#!/usr/bin/env bash
# =============================================================================
# gen_udp_flood.sh  —  Generate UDP_FLOOD (class 6) traffic
# Target: 127.0.0.1:9999 (dummy UDP listener)
# Interface: lo
# =============================================================================
# NFStream observable features distinguishing UDP_FLOOD from normal UDP:
#   - Very high bidirectional_packets/sec (>> normal DNS/NTP UDP)
#   - Very high bidirectional_bytes/sec
#   - Near-zero inter-packet arrival time (bidirectional_min_piat_ms ~0)
#   - Uniform packet sizes (constant payload)
#   - Single destination port (floods one endpoint)
#   - Protocol = UDP (17), NOT ICMP or TCP
#   - Very short flow duration with extreme packet density
#
# Compare to normal UDP (DNS): 1-2 pkts/flow, variable timing, port 53
# =============================================================================
set -uo pipefail

TARGET="127.0.0.1"
TARGET_PORT="9999"
DURATION="${1:-120}"

echo "========================================"
echo "  UDP Flood Generator"
echo "  Target: $TARGET:$TARGET_PORT"
echo "  Duration: ${DURATION}s"
echo "  Interface: lo"
echo "========================================"

LISTENER_PID=""
HPING_PID=""

# Start a dummy UDP listener
if command -v ncat &>/dev/null; then
    echo "[UDP] Starting dummy listener on $TARGET:$TARGET_PORT"
    ncat -u -l -k "$TARGET_PORT" > /dev/null 2>&1 &
    LISTENER_PID=$!
elif command -v nc &>/dev/null; then
    nc -u -l -k -p "$TARGET_PORT" > /dev/null 2>&1 &
    LISTENER_PID=$!
else
    echo "[UDP] No netcat available. Packets will generate ICMP unreachable replies (still visible to NFStream)."
fi
sleep 1

# Method 1: hping3 UDP flood
if command -v hping3 &>/dev/null; then
    echo "[UDP-1] hping3 UDP flood (rate-limited)"
    sudo hping3 --udp -k -p "$TARGET_PORT" \
        --count 50000 --interval u500 \
        "$TARGET" > /tmp/nids_udp_hping.txt 2>&1 &
    HPING_PID=$!
    echo "[UDP-1] PID=$HPING_PID"
else
    # Fallback: Python socket flood
    echo "[UDP-1] hping3 not found. Using Python socket fallback."
    python3 - "$TARGET" "$TARGET_PORT" "$DURATION" &
    HPING_PID=$!
fi

echo "[UDP] Running for ${DURATION}s ..."
sleep "$DURATION"

echo "[UDP] Stopping ..."
[ -n "$HPING_PID" ]    && sudo kill "$HPING_PID"    2>/dev/null || true
[ -n "$LISTENER_PID" ] && kill      "$LISTENER_PID" 2>/dev/null || true
wait 2>/dev/null || true
echo "[UDP] Done."
