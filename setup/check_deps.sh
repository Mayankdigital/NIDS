#!/usr/bin/env bash
# =============================================================================
# check_deps.sh  —  Verify all tools needed for NIDS dataset generation
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
MISSING=()

check() {
    local cmd=$1
    if command -v "$cmd" &>/dev/null; then
        echo -e "${GREEN}[OK]${NC}  $cmd  →  $(command -v "$cmd")"
    else
        echo -e "${RED}[MISSING]${NC}  $cmd"
        MISSING+=("$cmd")
    fi
}

echo "=========================================="
echo "  NIDS Dataset — Dependency Check"
echo "=========================================="

echo ""
echo "--- Network Tools ---"
check nmap
check hping3
check tcpdump
check tshark
check ncat
check curl
check wget

echo ""
echo "--- Python ---"
check python3
check pip3

echo ""
echo "--- Python Packages ---"
py_check() {
    local pkg=$1
    local import_name=${2:-$1}
    if python3 -c "import $import_name" 2>/dev/null; then
        echo -e "${GREEN}[OK]${NC}  python3 package: $pkg"
    else
        echo -e "${RED}[MISSING]${NC}  python3 package: $pkg"
        MISSING+=("pip3:$pkg")
    fi
}
py_check nfstream
py_check scapy
py_check flask Flask
py_check requests
py_check pandas
py_check numpy
py_check scikit-learn sklearn
py_check xgboost
py_check matplotlib
py_check seaborn
py_check imbalanced-learn imblearn

echo ""
echo "--- Optional but Useful ---"
check ab          # apache bench
check hydra       # brute-force (optional, we use Python instead)
check iperf3
check netstat     # or 'ss' is fine

echo ""
echo "=========================================="
if [ ${#MISSING[@]} -eq 0 ]; then
    echo -e "${GREEN}All dependencies satisfied!${NC}"
else
    echo -e "${YELLOW}Missing dependencies:${NC}"
    for item in "${MISSING[@]}"; do
        if [[ "$item" == pip3:* ]]; then
            pkg="${item#pip3:}"
            echo "  pip3 install $pkg"
        else
            echo "  sudo apt install $item"
        fi
    done

    echo ""
    echo "--- Quick install command for apt packages ---"
    APT_PKGS=()
    for item in "${MISSING[@]}"; do
        case "$item" in
            nmap)     APT_PKGS+=(nmap) ;;
            hping3)   APT_PKGS+=(hping3) ;;
            tcpdump)  APT_PKGS+=(tcpdump) ;;
            tshark)   APT_PKGS+=(tshark) ;;
            ncat)     APT_PKGS+=(ncat) ;;
            curl)     APT_PKGS+=(curl) ;;
            wget)     APT_PKGS+=(wget) ;;
            ab)       APT_PKGS+=(apache2-utils) ;;
            iperf3)   APT_PKGS+=(iperf3) ;;
        esac
    done
    if [ ${#APT_PKGS[@]} -gt 0 ]; then
        echo "  sudo apt update && sudo apt install -y ${APT_PKGS[*]}"
    fi

    echo ""
    echo "--- Quick install command for pip packages ---"
    PIP_PKGS=()
    for item in "${MISSING[@]}"; do
        if [[ "$item" == pip3:* ]]; then
            PIP_PKGS+=("${item#pip3:}")
        fi
    done
    if [ ${#PIP_PKGS[@]} -gt 0 ]; then
        echo "  pip3 install ${PIP_PKGS[*]}"
    fi
fi
echo "=========================================="
