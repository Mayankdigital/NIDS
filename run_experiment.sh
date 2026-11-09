#!/usr/bin/env bash
# =============================================================================
# run_experiment.sh  —  Master orchestration script
# =============================================================================
# Usage:
#   ./run_experiment.sh <CLASS_NAME> <EXPERIMENT_NUM> [DURATION_SECONDS]
#
# Examples:
#   ./run_experiment.sh benign 1 300
#   ./run_experiment.sh port_scan 2
#   ./run_experiment.sh dos 3 120
#
# This script:
#   1. Validates inputs and checks the target service is running
#   2. Records experiment metadata
#   3. Starts tcpdump capture
#   4. Runs the appropriate traffic generator
#   5. Stops capture
#   6. Runs NFStream processing
#   7. Appends labeled flows to the class CSV
# =============================================================================
set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'; BOLD='\033[1m'

# ── Paths ─────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ATTACKS_DIR="$SCRIPT_DIR/attacks"
PROCESS_DIR="$SCRIPT_DIR/process"
DATASET_DIR="$SCRIPT_DIR/nids_dataset"

# ── Venv Python ───────────────────────────────────────────────────────────────
PYTHON="$SCRIPT_DIR/venv/bin/python"
if [ ! -f "$PYTHON" ]; then
    PYTHON="$(command -v python3)"
    echo -e "${YELLOW}[WARN]${NC} venv not found, using system python3: $PYTHON"
fi

# ── Label map ─────────────────────────────────────────────────────────────────
declare -A LABEL_MAP=(
    [benign]=0
    [port_scan]=1
    [dos]=2
    [ddos]=3
    [brute_force]=4
    [network_recon]=5
    [udp_flood]=6
    [icmp_flood]=7
    [web_attack]=8
)

# ── Service ports ──────────────────────────────────────────────────────────────
declare -A SERVICE_PORT=(
    [benign]=8080
    [port_scan]=8080
    [dos]=8080
    [ddos]=8080
    [brute_force]=8081
    [network_recon]=8080
    [udp_flood]=0
    [icmp_flood]=0          # ICMP, no port
    [web_attack]=8080
)

# ── Interface ─────────────────────────────────────────────────────────────────
declare -A IFACE_MAP=(
    [benign]=lo
    [port_scan]=lo
    [dos]=lo
    [ddos]=lo
    [brute_force]=lo
    [network_recon]=lo
    [udp_flood]=lo
    [icmp_flood]=lo
    [web_attack]=lo
)

usage() {
    echo -e "${BOLD}Usage:${NC} $0 <class_name> <experiment_num> [duration_seconds]"
    echo ""
    echo -e "${BOLD}Classes:${NC}"
    for cls in "${!LABEL_MAP[@]}"; do
        echo "  ${cls}  (label=${LABEL_MAP[$cls]})"
    done | sort
    echo ""
    echo -e "${BOLD}Examples:${NC}"
    echo "  $0 benign 1 300"
    echo "  $0 port_scan 2"
    echo "  $0 dos 3 120"
    exit 1
}

# ── Args ───────────────────────────────────────────────────────────────────────
[ $# -lt 2 ] && usage

CLASS_NAME="${1,,}"     # lowercase
EXP_NUM="$2"
DURATION="${3:-300}"   # default 5 minutes

if [ -z "${LABEL_MAP[$CLASS_NAME]+x}" ]; then
    echo -e "${RED}[ERROR]${NC} Unknown class: $CLASS_NAME"
    usage
fi

CLASS_ID="${LABEL_MAP[$CLASS_NAME]}"
IFACE="${IFACE_MAP[$CLASS_NAME]}"
PORT="${SERVICE_PORT[$CLASS_NAME]}"
EXP_ID="${CLASS_NAME^^}_$(printf '%03d' "$EXP_NUM")"
PCAP_FILE="$DATASET_DIR/captures/$CLASS_NAME/${EXP_ID}.pcap"
CSV_OUTPUT="$DATASET_DIR/processed/${CLASS_NAME}.csv"

# ── Header ─────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${BLUE}║  NIDS Experiment Runner                              ║${NC}"
echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BOLD}Experiment ID:${NC} $EXP_ID"
echo -e "  ${BOLD}Class:${NC}         $CLASS_NAME (label=$CLASS_ID)"
echo -e "  ${BOLD}Interface:${NC}     $IFACE"
echo -e "  ${BOLD}Duration:${NC}      ${DURATION}s"
echo -e "  ${BOLD}PCAP:${NC}          $PCAP_FILE"
echo -e "  ${BOLD}Output CSV:${NC}    $CSV_OUTPUT"
echo ""

# ── Step 0: Create directories ────────────────────────────────────────────────
mkdir -p "$DATASET_DIR/captures/$CLASS_NAME"
mkdir -p "$DATASET_DIR/processed"
mkdir -p "$DATASET_DIR/metadata"
mkdir -p "$DATASET_DIR/final"

# ── Step 1: Check services ────────────────────────────────────────────────────
echo -e "${YELLOW}[STEP 1]${NC} Checking prerequisites ..."

check_port() {
    local port="$1"
    if [ "$port" -eq 0 ]; then return 0; fi
    if ss -tlnp 2>/dev/null | grep -q ":$port "; then
        echo -e "  ${GREEN}[OK]${NC} Service listening on port $port"
        return 0
    else
        echo -e "  ${RED}[MISSING]${NC} Nothing listening on port $port"
        return 1
    fi
}

SERVICE_OK=true
if [ "$PORT" -gt 0 ]; then
    if ! check_port "$PORT"; then
        echo ""
        echo -e "  ${YELLOW}Start the required service:${NC}"
        case "$CLASS_NAME" in
            benign|port_scan|dos|ddos|network_recon)
                echo "    $PYTHON $SCRIPT_DIR/services/start_http_service.py &"
                echo ""
                read -p "  Service not running. Start it now and press Enter, or Ctrl+C to abort: "
                ;;
            brute_force)
                echo "    $PYTHON $SCRIPT_DIR/services/start_auth_service.py &"
                echo ""
                read -p "  Service not running. Start it now and press Enter, or Ctrl+C to abort: "
                ;;
            web_attack)
                echo "    $PYTHON $SCRIPT_DIR/services/start_web_app.py &"
                echo ""
                read -p "  Service not running. Start it now and press Enter, or Ctrl+C to abort: "
                ;;
            udp_flood)
                echo "    # UDP listener is started by the attack script itself"
                echo "    # Continuing automatically..."
                ;;
        esac
    fi
fi

# ── Step 2: Record metadata ────────────────────────────────────────────────────
echo -e "${YELLOW}[STEP 2]${NC} Recording experiment metadata ..."
"$PYTHON" "$PROCESS_DIR/metadata_manager.py" record \
    --experiment-id "$EXP_ID" \
    --class-id "$CLASS_ID" \
    --class-name "$CLASS_NAME" \
    --interface "$IFACE" \
    --src-ip "127.0.0.1" \
    --dst-ip "127.0.0.1" \
    --dst-port "$PORT" \
    --protocol "TCP" \
    --notes "Duration=${DURATION}s  auto-run" \
    --force 2>/dev/null || true

# ── Step 3: Start capture ──────────────────────────────────────────────────────
echo -e "${YELLOW}[STEP 3]${NC} Starting tcpdump capture on interface: $IFACE"
sudo tcpdump -i "$IFACE" -w "$PCAP_FILE" -s 0 -B 4096 -Z root \
    > /dev/null 2>&1 &
TCPDUMP_PID=$!
echo "  tcpdump PID=$TCPDUMP_PID  PCAP=$PCAP_FILE"
sleep 2   # let tcpdump initialize

# Mark experiment start
"$PYTHON" "$PROCESS_DIR/metadata_manager.py" start \
    --experiment-id "$EXP_ID" 2>/dev/null || true

# ── Step 4: Generate traffic ───────────────────────────────────────────────────
echo -e "${YELLOW}[STEP 4]${NC} Running traffic generator: $CLASS_NAME"
echo ""

ATTACK_EXIT=0
case "$CLASS_NAME" in
    benign)
        bash "$ATTACKS_DIR/gen_benign.sh" "$DURATION" || ATTACK_EXIT=$?
        ;;
    port_scan)
        bash "$ATTACKS_DIR/gen_port_scan.sh" || ATTACK_EXIT=$?
        ;;
    dos)
        bash "$ATTACKS_DIR/gen_dos.sh" "$DURATION" || ATTACK_EXIT=$?
        ;;
    ddos)
        bash "$ATTACKS_DIR/gen_ddos_simulated.sh" 20 "$DURATION" || ATTACK_EXIT=$?
        ;;
    brute_force)
        "$PYTHON" "$ATTACKS_DIR/gen_brute_force.py" \
            --host 127.0.0.1 --port 8081 \
            --duration "$DURATION" --workers 50 --mode random || ATTACK_EXIT=$?
        ;;
    network_recon)
        bash "$ATTACKS_DIR/gen_network_recon.sh" || ATTACK_EXIT=$?
        ;;
    udp_flood)
        bash "$ATTACKS_DIR/gen_udp_flood.sh" "$DURATION" || ATTACK_EXIT=$?
        ;;
    icmp_flood)
        bash "$ATTACKS_DIR/gen_icmp_flood.sh" "$DURATION" || ATTACK_EXIT=$?
        ;;
    web_attack)
        "$PYTHON" "$ATTACKS_DIR/gen_web_attack.py" \
            --host 127.0.0.1 --port 8080 \
            --duration "$DURATION" --workers 40 || ATTACK_EXIT=$?
        ;;
    *)
        echo -e "${RED}[ERROR]${NC} No generator for class: $CLASS_NAME"
        ATTACK_EXIT=1
        ;;
esac

echo ""
if [ "$ATTACK_EXIT" -ne 0 ]; then
    echo -e "${YELLOW}[WARN]${NC} Attack generator exited with code $ATTACK_EXIT (may be normal)"
fi

# ── Step 5: Stop capture ───────────────────────────────────────────────────────
echo -e "${YELLOW}[STEP 5]${NC} Stopping capture ..."
sleep 2  # let last packets be written
sudo kill -SIGTERM "$TCPDUMP_PID" 2>/dev/null || true
sleep 3
sudo kill -9 "$TCPDUMP_PID" 2>/dev/null || true

# Mark experiment end
"$PYTHON" "$PROCESS_DIR/metadata_manager.py" stop \
    --experiment-id "$EXP_ID" 2>/dev/null || true

PCAP_SIZE=$(stat -c%s "$PCAP_FILE" 2>/dev/null || echo 0)
echo "  PCAP size: $((PCAP_SIZE/1024)) KB"

if [ "$PCAP_SIZE" -lt 1024 ]; then
    echo -e "  ${YELLOW}[WARN]${NC} Very small PCAP. Traffic may not have captured."
    echo "  Verify with: sudo tcpdump -r $PCAP_FILE | head -20"
fi

# ── Step 6: Process with NFStream ─────────────────────────────────────────────
echo ""
echo -e "${YELLOW}[STEP 6]${NC} Processing PCAP with NFStream ..."
"$PYTHON" "$PROCESS_DIR/nfstream_processor.py" \
    --pcap "$PCAP_FILE" \
    --experiment-id "$EXP_ID" \
    --class-id "$CLASS_ID" \
    --class-name "$CLASS_NAME" \
    --output "$CSV_OUTPUT" \
    --append

# ── Done ───────────────────────────────────────────────────────────────────────
echo ""
FLOW_COUNT=$("$PYTHON" -c "
import pandas as pd, sys
try:
    df = pd.read_csv('$CSV_OUTPUT')
    cls = df[df['experiment_id']=='$EXP_ID']
    print(len(cls))
except:
    print('?')
" 2>/dev/null)

echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  EXPERIMENT COMPLETE: $EXP_ID${NC}"
echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Flows captured this run: ${BOLD}$FLOW_COUNT${NC}"
echo -e "  CSV:  $CSV_OUTPUT"
echo -e "  PCAP: $PCAP_FILE"
echo ""
echo -e "  ${BLUE}Next experiment:${NC}"
echo -e "    $0 $CLASS_NAME $((EXP_NUM+1)) $DURATION"
echo ""
echo -e "  ${BLUE}Validate dataset:${NC}"
echo -e "    python3 validate/dataset_validator.py --csv $CSV_OUTPUT"
echo ""
