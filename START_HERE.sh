#!/usr/bin/env bash
# =============================================================================
# START_HERE.sh — Interactive setup & quick-start for NIDS Data Collection
# =============================================================================
# Run this first:  bash START_HERE.sh
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="$SCRIPT_DIR/venv/bin/python"
[ ! -f "$PYTHON" ] && PYTHON="$(command -v python3)"

print_header() {
    echo ""
    echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${BLUE}║       NIDS Dataset Collection — Quick Start Guide            ║${NC}"
    echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_step() {
    local n="$1"; local msg="$2"
    echo -e "${BOLD}${CYAN}[STEP $n]${NC} $msg"
}

print_ok()   { echo -e "  ${GREEN}[✓]${NC} $1"; }
print_warn() { echo -e "  ${YELLOW}[!]${NC} $1"; }
print_err()  { echo -e "  ${RED}[✗]${NC} $1"; }

pause() {
    echo ""
    read -r -p "  Press [Enter] to continue..." _
    echo ""
}

# ─────────────────────────────────────────────────────────────────────────────
print_header

echo -e "  This script will guide you through:"
echo "    1. Checking & installing dependencies"
echo "    2. Creating the dataset directory tree"
echo "    3. (Optionally) starting the target services"
echo "    4. Running your first experiment"
echo ""
echo -e "  ${YELLOW}NOTE:${NC} Some commands require sudo (tcpdump, hping3)."
echo ""

pause

# ─────────────────────────────────────────────────────────────────────────────
print_step 1 "Checking dependencies"
echo ""
bash "$SCRIPT_DIR/setup/check_deps.sh"

echo ""
echo -e "  ${YELLOW}If anything is MISSING, install it now before continuing.${NC}"
echo -e "  Common install commands are printed above."
pause

# ─────────────────────────────────────────────────────────────────────────────
print_step 2 "Creating dataset directories"
echo ""
bash "$SCRIPT_DIR/setup/create_dirs.sh"
print_ok "Directories created under: $SCRIPT_DIR/nids_dataset/"
pause

# ─────────────────────────────────────────────────────────────────────────────
print_step 3 "Starting target services"
echo ""
echo -e "  You need ${BOLD}3 services${NC} running in separate terminals:"
echo ""
echo -e "  ${BOLD}Terminal A  (HTTP — for benign, port_scan, dos, ddos, network_recon):${NC}"
echo -e "    ${CYAN}$PYTHON $SCRIPT_DIR/services/start_http_service.py${NC}"
echo ""
echo -e "  ${BOLD}Terminal B  (Auth — for brute_force):${NC}"
echo -e "    ${CYAN}$PYTHON $SCRIPT_DIR/services/start_auth_service.py${NC}"
echo ""
echo -e "  ${BOLD}Terminal C  (Web App — for web_attack):${NC}"
echo -e "    ${CYAN}$PYTHON $SCRIPT_DIR/services/start_web_app.py${NC}"
echo ""
echo -e "  ${YELLOW}Start them now in other terminals, then come back here.${NC}"
pause

# Quick service check
echo -e "  Checking which services are running..."
check_port() {
    local port="$1"; local name="$2"
    if ss -tlnp 2>/dev/null | grep -q ":$port "; then
        print_ok "$name on port $port"
    else
        print_warn "$name NOT running on port $port (start it if needed)"
    fi
}
check_port 8080 "HTTP service"
check_port 8081 "Auth service"
check_port 8082 "Web app"
echo ""
pause

# ─────────────────────────────────────────────────────────────────────────────
print_step 4 "Run your first experiment"
echo ""
echo -e "  Use ${BOLD}run_experiment.sh${NC} to run any experiment:"
echo ""
echo -e "  ${BOLD}Format:${NC}"
echo -e "    ${CYAN}./run_experiment.sh <class> <number> [duration_seconds]${NC}"
echo ""
echo -e "  ${BOLD}Quickest test — BENIGN traffic for 60 seconds:${NC}"
echo -e "    ${CYAN}sudo bash $SCRIPT_DIR/run_experiment.sh benign 1 60${NC}"
echo ""
echo -e "  ${BOLD}Full collection sequence (run 4× each class):${NC}"
echo ""

CLASSES=(
    "benign       1 300"
    "benign       2 300"
    "benign       3 300"
    "benign       4 300"
    "port_scan    1"
    "port_scan    2"
    "port_scan    3"
    "port_scan    4"
    "dos          1 120"
    "dos          2 120"
    "dos          3 120"
    "dos          4 120"
    "ddos         1 120"
    "ddos         2 120"
    "ddos         3 120"
    "ddos         4 120"
    "brute_force  1"
    "brute_force  2"
    "brute_force  3"
    "brute_force  4"
    "network_recon 1"
    "network_recon 2"
    "network_recon 3"
    "network_recon 4"
    "udp_flood    1 120"
    "udp_flood    2 120"
    "udp_flood    3 120"
    "udp_flood    4 120"
    "icmp_flood   1 120"
    "icmp_flood   2 120"
    "icmp_flood   3 120"
    "icmp_flood   4 120"
    "web_attack   1"
    "web_attack   2"
    "web_attack   3"
    "web_attack   4"
)

for cmd in "${CLASSES[@]}"; do
    echo -e "    ${CYAN}sudo bash run_experiment.sh $cmd${NC}"
done

echo ""
echo -e "  ${YELLOW}TIP:${NC} Run at least 4 experiments per class for proper train/val/test splits."
pause

# ─────────────────────────────────────────────────────────────────────────────
print_step 5 "After all experiments — merge, validate, train"
echo ""
echo -e "  ${BOLD}Merge all per-class CSVs:${NC}"
echo -e "    ${CYAN}$PYTHON $SCRIPT_DIR/process/merge_dataset.py${NC}"
echo ""
echo -e "  ${BOLD}Validate the dataset:${NC}"
echo -e "    ${CYAN}$PYTHON $SCRIPT_DIR/validate/dataset_validator.py${NC}"
echo ""
echo -e "  ${BOLD}Train and evaluate ML models:${NC}"
echo -e "    ${CYAN}$PYTHON $SCRIPT_DIR/ml/train_eval.py${NC}"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  Setup complete! You are ready to collect data.${NC}"
echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BOLD}Key files:${NC}"
echo -e "    README.md                      ← Full documentation"
echo -e "    run_experiment.sh              ← Main experiment runner"
echo -e "    setup/check_deps.sh            ← Dependency checker"
echo -e "    services/start_http_service.py ← HTTP target (port 8080)"
echo -e "    services/start_auth_service.py ← Auth target (port 8081)"
echo -e "    services/start_web_app.py      ← Web app target (port 8082)"
echo -e "    process/merge_dataset.py       ← Merge CSVs after collection"
echo -e "    validate/dataset_validator.py  ← Validate dataset"
echo -e "    ml/train_eval.py               ← Train RF + XGBoost"
echo ""
echo -e "  ${BOLD}Dataset output:${NC}"
echo -e "    nids_dataset/captures/         ← Raw PCAPs"
echo -e "    nids_dataset/processed/        ← Per-class labeled CSVs"
echo -e "    nids_dataset/final/            ← Merged + split dataset"
echo -e "    nids_dataset/metadata/         ← Experiment registry"
echo ""
