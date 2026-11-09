#!/usr/bin/env bash
# =============================================================================
# run_all_collection.sh — Run ALL 36 experiments automatically (unattended)
# =============================================================================
# WARNING: This takes ~2–3 hours total. Start services first.
#
# Prerequisites (must be done BEFORE running this):
#   1. python3 services/start_http_service.py &
#   2. python3 services/start_auth_service.py &
#   3. python3 services/start_web_app.py &
#
# Then run:
#   sudo bash run_all_collection.sh
#
# Or with a custom log file:
#   sudo bash run_all_collection.sh 2>&1 | tee logs/collection_$(date +%Y%m%d_%H%M).log
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNNER="$SCRIPT_DIR/run_experiment.sh"
LOG_DIR="$SCRIPT_DIR/logs"
mkdir -p "$LOG_DIR"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

PASS=0; FAIL=0; SKIP=0
RESULTS=()

run_exp() {
    local class="$1"; local num="$2"; local duration="${3:-}"
    local exp_id="${class^^}_$(printf '%03d' "$num")"
    local pcap="$SCRIPT_DIR/nids_dataset/captures/$class/${exp_id}.pcap"

    # Skip if PCAP already exists and is non-empty (resume support)
    if [ -f "$pcap" ] && [ "$(stat -c%s "$pcap" 2>/dev/null || echo 0)" -gt 4096 ]; then
        echo -e "${YELLOW}[SKIP]${NC} $exp_id — PCAP already exists ($(du -sh "$pcap" | cut -f1))"
        SKIP=$(( SKIP + 1 ))
        RESULTS+=("SKIP  $exp_id")
        return
    fi

    echo ""
    echo -e "${BOLD}${BLUE}━━━ Running: $exp_id ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    local cmd=("$RUNNER" "$class" "$num")
    [ -n "$duration" ] && cmd+=("$duration")

    if bash "${cmd[@]}"; then
        PASS=$(( PASS + 1 ))
        RESULTS+=("PASS  $exp_id")
        echo -e "${GREEN}[PASS]${NC} $exp_id"
    else
        FAIL=$(( FAIL + 1 ))
        RESULTS+=("FAIL  $exp_id  ← check logs/")
        echo -e "${RED}[FAIL]${NC} $exp_id — continuing with next experiment"
    fi

    # Brief pause between experiments
    sleep 5
}

# ─── Preflight checks ────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${BLUE}║  NIDS Automated Collection — Full Run             ║${NC}"
echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo "  Checking required services..."

check_port() {
    local port="$1"; local name="$2"
    if ss -tlnp 2>/dev/null | grep -q ":$port "; then
        echo -e "  ${GREEN}[OK]${NC}  $name → port $port"
    else
        echo -e "  ${RED}[MISSING]${NC}  $name NOT running on port $port"
        echo "  Start it:  python3 $SCRIPT_DIR/services/${3} &"
        MISSING_SERVICES=true
    fi
}

MISSING_SERVICES=false
check_port 8080 "HTTP service"   "start_http_service.py"
check_port 8081 "Auth service"   "start_auth_service.py"
check_port 8082 "Web app"        "start_web_app.py"

if [ "$MISSING_SERVICES" = "true" ]; then
    echo ""
    echo -e "${YELLOW}[WARN]${NC} Some services are not running."
    echo "  Experiments targeting missing services will fail or produce empty PCAPs."
    echo "  Start them now (press Ctrl+C to abort), or press Enter to continue anyway."
    read -r -p "  Continue? [Enter/Ctrl+C]: " _
fi

echo ""
echo -e "  ${YELLOW}Starting full collection in 5 seconds...${NC}"
echo "  Use Ctrl+C to abort at any time."
echo "  Resume is supported — already-captured experiments will be skipped."
sleep 5

# ─── Experiment sequence ─────────────────────────────────────────────────────
# 9 classes × 4 experiments = 36 total

# Class 0: BENIGN
run_exp benign 1 300
run_exp benign 2 300
run_exp benign 3 300
run_exp benign 4 300

# Class 1: PORT_SCAN
run_exp port_scan 1
run_exp port_scan 2
run_exp port_scan 3
run_exp port_scan 4

# Class 2: DOS
run_exp dos 1 120
run_exp dos 2 120
run_exp dos 3 120
run_exp dos 4 120

# Class 3: DDOS (simulated via namespaces)
run_exp ddos 1 120
run_exp ddos 2 120
run_exp ddos 3 120
run_exp ddos 4 120

# Class 4: BRUTE_FORCE
run_exp brute_force 1
run_exp brute_force 2
run_exp brute_force 3
run_exp brute_force 4

# Class 5: NETWORK_RECON
run_exp network_recon 1
run_exp network_recon 2
run_exp network_recon 3
run_exp network_recon 4

# Class 6: UDP_FLOOD
run_exp udp_flood 1 120
run_exp udp_flood 2 120
run_exp udp_flood 3 120
run_exp udp_flood 4 120

# Class 7: ICMP_FLOOD
run_exp icmp_flood 1 120
run_exp icmp_flood 2 120
run_exp icmp_flood 3 120
run_exp icmp_flood 4 120

# Class 8: WEB_ATTACK
run_exp web_attack 1
run_exp web_attack 2
run_exp web_attack 3
run_exp web_attack 4

# ─── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${BLUE}║  Collection Complete — Summary                    ║${NC}"
echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo "  PASS:  $PASS"
echo "  SKIP:  $SKIP (already captured, skipped)"
echo "  FAIL:  $FAIL"
echo ""
echo "  Experiment results:"
for r in "${RESULTS[@]}"; do
    if [[ "$r" == PASS* ]]; then
        echo -e "    ${GREEN}$r${NC}"
    elif [[ "$r" == SKIP* ]]; then
        echo -e "    ${YELLOW}$r${NC}"
    else
        echo -e "    ${RED}$r${NC}"
    fi
done

echo ""
echo -e "  ${BOLD}Next steps:${NC}"
echo ""
echo -e "  ${BLUE}1. Merge all per-class CSVs:${NC}"
echo -e "     python3 process/merge_dataset.py"
echo ""
echo -e "  ${BLUE}2. Validate the dataset:${NC}"
echo -e "     python3 validate/dataset_validator.py"
echo ""
echo -e "  ${BLUE}3. Train ML models:${NC}"
echo -e "     python3 ml/train_eval.py"
echo ""
echo -e "  ${BLUE}4. Check experiment registry:${NC}"
echo -e "     python3 process/metadata_manager.py summary"
echo ""
