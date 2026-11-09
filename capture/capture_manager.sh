#!/usr/bin/env bash
# =============================================================================
# capture_manager.sh — Start/stop tcpdump with full experiment metadata logging
# =============================================================================
# Usage:
#   capture_manager.sh start <EXPERIMENT_ID> <CLASS_ID> <CLASS_NAME> \
#                            <INTERFACE> <DST_IP> <DST_PORT> <PROTOCOL>
#   capture_manager.sh stop  <EXPERIMENT_ID>
#
# Examples:
#   capture_manager.sh start DOS_001 2 dos lo 127.0.0.1 8080 TCP
#   capture_manager.sh stop  DOS_001
#
# Interface choices:
#   lo    — for all 127.0.0.1 traffic (most experiments)
#   wlo1  — for traffic to LAN IP (BENIGN background, optional)
#   any   — capture on all interfaces (use if unsure)
# =============================================================================
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../nids_dataset" && pwd)"
META_FILE="$BASE_DIR/metadata/experiments.csv"
PID_DIR="/tmp/nids_pids"
mkdir -p "$PID_DIR"

# Ensure metadata CSV has header
if [ ! -f "$META_FILE" ]; then
    mkdir -p "$BASE_DIR/metadata"
    echo "experiment_id,class_id,class_name,label,start_time,end_time,interface,source_ip,destination_ip,source_port,destination_port,protocol,pcap_file,notes" > "$META_FILE"
fi

usage() {
    echo "Usage:"
    echo "  $0 start <EXP_ID> <CLASS_ID> <CLASS_NAME> <INTERFACE> <DST_IP> <DST_PORT> <PROTOCOL>"
    echo "  $0 stop  <EXP_ID>"
    exit 1
}

[ $# -lt 2 ] && usage

ACTION="$1"
EXP_ID="$2"

if [ "$ACTION" = "start" ]; then
    [ $# -lt 8 ] && usage
    CLASS_ID="$3"
    CLASS_NAME="$4"
    IFACE="$5"
    DST_IP="$6"
    DST_PORT="$7"
    PROTOCOL="$8"
    NOTES="${9:-}"

    # Determine capture directory
    CAPTURE_DIR="$BASE_DIR/captures/$CLASS_NAME"
    mkdir -p "$CAPTURE_DIR"
    PCAP_FILE="$CAPTURE_DIR/${EXP_ID}.pcap"

    START_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    SRC_IP="127.0.0.1"

    # Start tcpdump in background
    echo "[CAPTURE] Starting tcpdump on $IFACE → $PCAP_FILE"
    sudo tcpdump -i "$IFACE" -w "$PCAP_FILE" \
        -s 0 \
        --buffer-size=4096 \
        -Z root \
        2>/tmp/nids_tcpdump_${EXP_ID}.log &
    TCPDUMP_PID=$!
    echo $TCPDUMP_PID > "$PID_DIR/${EXP_ID}.pid"

    echo "[CAPTURE] tcpdump PID=$TCPDUMP_PID"
    echo "[CAPTURE] PCAP: $PCAP_FILE"
    echo "[CAPTURE] Experiment: $EXP_ID | Class: $CLASS_NAME ($CLASS_ID)"

    # Write metadata row (end_time will be updated on stop)
    echo "$EXP_ID,$CLASS_ID,$CLASS_NAME,$CLASS_ID,$START_TIME,RUNNING,$IFACE,$SRC_IP,$DST_IP,$DST_PORT,-,$PROTOCOL,$PCAP_FILE,$NOTES" >> "$META_FILE"
    echo "[CAPTURE] Metadata written. Run attacks now, then call: $0 stop $EXP_ID"

elif [ "$ACTION" = "stop" ]; then
    PID_FILE="$PID_DIR/${EXP_ID}.pid"
    if [ ! -f "$PID_FILE" ]; then
        echo "[ERROR] No PID file found for $EXP_ID. Is it running?"
        exit 1
    fi

    TCPDUMP_PID=$(cat "$PID_FILE")
    END_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    echo "[CAPTURE] Stopping tcpdump PID=$TCPDUMP_PID ..."
    sudo kill -SIGTERM "$TCPDUMP_PID" 2>/dev/null || true
    sleep 2
    sudo kill -9 "$TCPDUMP_PID" 2>/dev/null || true
    rm -f "$PID_FILE"

    # Update end_time in metadata
    # Replace 'RUNNING' with actual end time for this experiment
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "s|^${EXP_ID},\(.*\),RUNNING,|${EXP_ID},\1,${END_TIME},|" "$META_FILE"
    else
        sed -i "s|^${EXP_ID},\(.*\),RUNNING,|${EXP_ID},\1,${END_TIME},|" "$META_FILE"
    fi

    echo "[CAPTURE] Stopped. End time: $END_TIME"
    echo "[CAPTURE] Check PCAP with: tcpdump -r <pcap_file> | head -20"
else
    usage
fi
