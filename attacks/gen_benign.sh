#!/usr/bin/env bash
# =============================================================================
# gen_benign.sh  —  Generate BENIGN (class 0) traffic
# =============================================================================
# Generates realistic mixed HTTP traffic with multiple concurrent connections.
# Each concurrent connection = different src_port = unique NFStream flow.
# Target: ~500-1000 flows per minute (15K flows in ~15-20 minutes total).
#
# Benign traffic characteristics:
#   - Mix of GET and POST requests
#   - Multiple endpoints (/, /health, /api/data, /login, etc.)
#   - Varied connection sizes (small health checks, large API responses)
#   - Normal flow durations (complete request+response cycles)
#   - Single source IP (127.0.0.1) — distinguishes from DDOS multi-IP
# =============================================================================
set -uo pipefail

HOST="127.0.0.1"
PORT="8080"
DURATION="${1:-120}"
CONCURRENCY="${2:-30}"   # concurrent curl processes = ~30 flows/batch

ENDTIME=$(( $(date +%s) + DURATION ))

ENDPOINTS=(
    "/"
    "/health"
    "/api/data"
    "/api/users"
    "/api/users?limit=10"
    "/api/users?limit=50"
    "/api/data?page=1"
    "/api/data?page=2"
    "/api/data?page=3"
    "/files/report.txt"
    "/files/data.csv"
    "/login"
    "/logout"
    "/dashboard"
    "/metrics"
    "/status"
    "/api/search?q=test"
    "/api/search?q=admin"
    "/api/config"
    "/api/version"
)

POST_PAYLOADS=(
    '{"action":"login","user":"alice","ts":"NOW"}'
    '{"action":"update","id":42,"value":"test"}'
    '{"query":"select * from users","limit":10}'
    '{"event":"page_view","path":"/home"}'
    '{"key":"config","value":"production"}'
)

echo "======================================================"
echo "  BENIGN Traffic Generator"
echo "  Target     : $HOST:$PORT"
echo "  Duration   : ${DURATION}s"
echo "  Concurrency: $CONCURRENCY parallel requests/batch"
echo "  Expected   : ~$(( CONCURRENCY * DURATION / 2 )) flows"
echo "======================================================"

BATCH=0
while [ $(date +%s) -lt $ENDTIME ]; do
    PIDS=()

    # Launch CONCURRENCY parallel curl requests
    for i in $(seq 1 "$CONCURRENCY"); do
        IDX=$(( (BATCH * CONCURRENCY + i) % ${#ENDPOINTS[@]} ))
        ENDPOINT="${ENDPOINTS[$IDX]}"

        # Mix GET and POST (every 5th request is POST)
        if [ $(( i % 5 )) -eq 0 ]; then
            PIDX=$(( i % ${#POST_PAYLOADS[@]} ))
            PAYLOAD="${POST_PAYLOADS[$PIDX]}"
            PAYLOAD="${PAYLOAD/NOW/$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
            curl -s -o /dev/null \
                -X POST \
                -H "Content-Type: application/json" \
                -d "$PAYLOAD" \
                --connect-timeout 2 --max-time 4 \
                "http://$HOST:$PORT/api/data" 2>/dev/null &
        else
            curl -s -o /dev/null \
                --connect-timeout 2 --max-time 4 \
                "http://$HOST:$PORT$ENDPOINT" 2>/dev/null &
        fi
        PIDS+=($!)
    done

    # Wait for this batch to finish
    for pid in "${PIDS[@]}"; do
        wait "$pid" 2>/dev/null || true
    done

    BATCH=$(( BATCH + 1 ))
    [ $(( BATCH % 20 )) -eq 0 ] && echo "[BENIGN] Batch $BATCH done (~$(( BATCH * CONCURRENCY )) requests sent)"
done

echo "[BENIGN] Done. ~$(( BATCH * CONCURRENCY )) total requests sent."
