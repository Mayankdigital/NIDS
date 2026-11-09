#!/usr/bin/env bash
# =============================================================================
# create_dirs.sh  —  Create the full NIDS dataset directory tree
# =============================================================================
BASE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

DIRS=(
    "$BASE/nids_dataset/captures/benign"
    "$BASE/nids_dataset/captures/port_scan"
    "$BASE/nids_dataset/captures/dos"
    "$BASE/nids_dataset/captures/ddos"
    "$BASE/nids_dataset/captures/brute_force"
    "$BASE/nids_dataset/captures/network_recon"
    "$BASE/nids_dataset/captures/udp_flood"
    "$BASE/nids_dataset/captures/icmp_flood"
    "$BASE/nids_dataset/captures/web_attack"
    "$BASE/nids_dataset/processed"
    "$BASE/nids_dataset/metadata"
    "$BASE/nids_dataset/final"
    "$BASE/logs"
)

for d in "${DIRS[@]}"; do
    mkdir -p "$d"
    echo "Created: $d"
done

# Initialize metadata CSV if it doesn't exist
META="$BASE/nids_dataset/metadata/experiments.csv"
if [ ! -f "$META" ]; then
    echo "experiment_id,class_id,class_name,label,start_time,end_time,interface,source_ip,destination_ip,source_port,destination_port,protocol,pcap_file,notes" > "$META"
    echo "Initialized: $META"
fi

echo ""
echo "Directory tree:"
find "$BASE/nids_dataset" -type d | sort | sed 's|[^/]*/|  |g'
echo ""
echo "Done."
