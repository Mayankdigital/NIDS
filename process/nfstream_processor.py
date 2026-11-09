#!/home/mayank/Desktop/DATACOLLECTION/venv/bin/python
"""
nfstream_processor.py — PCAP → NFStream → Labeled CSV
=======================================================
This is the CORE processing script.

Usage:
    python3 process/nfstream_processor.py \\
        --pcap nids_dataset/captures/port_scan/PORT_SCAN_001.pcap \\
        --experiment-id PORT_SCAN_001 \\
        --class-id 1 \\
        --class-name port_scan \\
        --output nids_dataset/processed/port_scan.csv \\
        --append

Or process an entire class directory:
    python3 process/nfstream_processor.py \\
        --class-dir nids_dataset/captures/port_scan \\
        --class-id 1 \\
        --class-name port_scan \\
        --output nids_dataset/processed/port_scan.csv

NFStream Flow Features Extracted:
    - src_ip, dst_ip, src_port, dst_port (metadata, NOT ML features)
    - protocol
    - bidirectional_packets, bidirectional_bytes, bidirectional_duration_ms
    - src2dst_packets, src2dst_bytes, dst2src_packets, dst2src_bytes
    - bidirectional_min/mean/stddev/max_ps (packet sizes)
    - bidirectional_min/mean/stddev/max_piat_ms (inter-arrival times)
    - src2dst and dst2src equivalents of above
    - splt features if enabled
    - expiration_id (how flow expired: 0=idle, 1=active, 2=rst, 3=fin)
"""
import argparse
import json
import logging
import math
import os
import sys
import glob
from datetime import datetime
from pathlib import Path

import pandas as pd
import numpy as np

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [PROCESSOR] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("nfstream_processor")

# Label mapping — must match project spec exactly
LABEL_MAP = {
    "benign":        0,
    "port_scan":     1,
    "dos":           2,
    "ddos":          3,
    "brute_force":   4,
    "network_recon": 5,
    "udp_flood":     6,
    "icmp_flood":    7,
    "web_attack":    8,
}

# Columns to drop for ML training (data leakage / non-generalizable identifiers)
# These are kept in CSV but documented as "drop before ML"
ML_DROP_COLUMNS = [
    "src_ip", "dst_ip", "src_mac", "dst_mac",
    "src_port", "dst_port",           # port may carry class-specific info
    "experiment_id", "class_name", "label",
    "expiration_id", "id",
    "src_oui", "dst_oui",
    "application_name", "application_category_name",
    "application_is_guessed", "application_confidence",
    "requested_server_name", "client_fingerprint",
    "server_fingerprint", "user_agent", "content_type",
    "first_seen", "last_seen",        # timestamps leak experiment order
]


def try_import_nfstream():
    try:
        import nfstream
        return nfstream
    except ImportError:
        log.error("NFStream not installed. Run: pip3 install nfstream")
        sys.exit(1)


def _convert_pcap_to_ethernet(pcap_path: str) -> str:
    """
    Convert a Linux cooked (SLL/SLL2) PCAP to standard Ethernet format using
    editcap. Required when tcpdump captures on 'any' interface.
    Returns path to converted file, or original path if conversion fails.
    """
    import subprocess, shutil, tempfile
    if not shutil.which("editcap"):
        return pcap_path
    out_path = pcap_path.replace(".pcap", "_eth.pcap")
    try:
        result = subprocess.run(
            ["editcap", "-F", "pcap", "-T", "ether", pcap_path, out_path],
            capture_output=True, text=True, timeout=120
        )
        if os.path.exists(out_path) and os.path.getsize(out_path) > 0:
            log.info("Converted SLL2→Ethernet PCAP: %s", out_path)
            return out_path
    except Exception as e2:
        log.warning("editcap conversion failed: %s", e2)
    return pcap_path


def process_pcap(pcap_path: str, experiment_id: str,
                 class_id: int, class_name: str,
                 nfstream) -> pd.DataFrame:
    """
    Process a single PCAP file with NFStream and return a DataFrame.
    Automatically converts SLL2 (tcpdump -i any) to Ethernet if needed.
    """
    log.info("Processing: %s", pcap_path)
    log.info("Experiment: %s | Class: %s (%d)", experiment_id, class_name, class_id)

    if not os.path.exists(pcap_path):
        log.error("PCAP not found: %s", pcap_path)
        return pd.DataFrame()

    pcap_size = os.path.getsize(pcap_path)
    log.info("PCAP size: %.2f MB", pcap_size / 1e6)

    if pcap_size == 0:
        log.warning("Empty PCAP file: %s", pcap_path)
        return pd.DataFrame()

    def _run_nfstream(path):
        streamer = nfstream.NFStreamer(
            source=path,
            decode_tunnels=True,
            statistical_analysis=True,
            splt_analysis=10,
            n_dissections=20,
            idle_timeout=120,
            active_timeout=1800,
        )
        return streamer.to_pandas(columns_to_anonymize=())

    df = None
    try:
        df = _run_nfstream(pcap_path)
    except Exception as e:
        log.warning("NFStream failed on original PCAP (%s) — trying SLL2→Ethernet conversion...", e)
        converted = _convert_pcap_to_ethernet(pcap_path)
        if converted != pcap_path:
            try:
                df = _run_nfstream(converted)
            except Exception as e2:
                log.error("NFStream failed after conversion: %s", e2)

    if df is None or df.empty:
        log.error("NFStream error processing %s: no flows extracted", pcap_path)
        return pd.DataFrame()

    # Add metadata columns
    df["experiment_id"] = experiment_id
    df["class_name"]    = class_name
    df["label"]         = class_id
    df["pcap_file"]     = os.path.basename(pcap_path)
    df["processed_at"]  = datetime.utcnow().isoformat()

    log.info("Extracted %d flows from %s", len(df), os.path.basename(pcap_path))
    return df


def clean_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Clean the dataframe:
    - Replace inf with NaN
    - Fill NaN with 0 for numeric columns
    - Remove duplicate flows
    - Remove flows with zero duration AND zero bytes (likely artifacts)
    """
    if df.empty:
        return df

    original_len = len(df)

    # Replace inf/-inf with NaN
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Count NaN before filling
    nan_counts = df.isnull().sum()
    high_nan = nan_counts[nan_counts > 0]
    if not high_nan.empty:
        log.info("NaN counts before fill:\n%s", high_nan.to_string())

    # Fill numeric NaN with 0
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    df[numeric_cols] = df[numeric_cols].fillna(0)

    # Fill string NaN with empty string
    string_cols = df.select_dtypes(include=["object"]).columns
    df[string_cols] = df[string_cols].fillna("")

    # Deduplicate: NFStream may produce duplicate flows in some edge cases
    dup_mask = df.duplicated(
        subset=["src_ip", "dst_ip", "src_port", "dst_port",
                "protocol", "bidirectional_first_seen_ms"],
        keep="first"
    )
    n_dups = dup_mask.sum()
    if n_dups > 0:
        log.warning("Removed %d duplicate flows", n_dups)
        df = df[~dup_mask].reset_index(drop=True)

    # Remove zero-packet artifact flows
    if "bidirectional_packets" in df.columns:
        zero_pkt = df["bidirectional_packets"] == 0
        if zero_pkt.sum() > 0:
            log.warning("Removing %d zero-packet flows", zero_pkt.sum())
            df = df[~zero_pkt].reset_index(drop=True)

    log.info("Cleaned: %d → %d flows (removed %d)",
             original_len, len(df), original_len - len(df))
    return df


def validate_dataframe(df: pd.DataFrame, class_name: str) -> bool:
    """
    Basic validation checks.
    Returns True if the dataframe passes, False otherwise.
    """
    if df.empty:
        log.error("VALIDATION FAILED: Empty dataframe for %s", class_name)
        return False

    log.info("=== Validation Report: %s ===", class_name)
    log.info("Flow count:  %d", len(df))

    if "label" in df.columns:
        log.info("Label check: %s", df["label"].unique().tolist())

    if "protocol" in df.columns:
        log.info("Protocols:\n%s", df["protocol"].value_counts().to_string())

    if "bidirectional_bytes" in df.columns:
        log.info("Bytes stats:\n%s",
                 df["bidirectional_bytes"].describe().to_string())

    if "bidirectional_packets" in df.columns:
        log.info("Packets stats:\n%s",
                 df["bidirectional_packets"].describe().to_string())

    if "bidirectional_duration_ms" in df.columns:
        log.info("Duration (ms) stats:\n%s",
                 df["bidirectional_duration_ms"].describe().to_string())

    # Check for constant features (low information)
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    constant_cols = [c for c in numeric_cols if df[c].nunique() <= 1]
    if constant_cols:
        log.warning("Constant features (zero variance): %s", constant_cols)

    return True


def save_csv(df: pd.DataFrame, output_path: str, append: bool = False):
    """Save or append the processed DataFrame to a CSV file."""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    if append and os.path.exists(output_path):
        existing = pd.read_csv(output_path, low_memory=False)
        df = pd.concat([existing, df], ignore_index=True)
        log.info("Appended to existing CSV. Total rows: %d", len(df))
    else:
        log.info("Writing new CSV: %s", output_path)

    df.to_csv(output_path, index=False)
    log.info("Saved: %s  (%d rows, %d cols)", output_path, len(df), len(df.columns))


def main():
    parser = argparse.ArgumentParser(
        description="Process PCAP files with NFStream and produce labeled CSV"
    )
    # Single PCAP mode
    parser.add_argument("--pcap", help="Path to a single PCAP file")
    parser.add_argument("--experiment-id", help="Experiment ID (e.g. PORT_SCAN_001)")

    # Directory mode
    parser.add_argument("--class-dir", help="Directory of PCAP files for one class")

    # Required for both modes
    parser.add_argument("--class-id", type=int, required=True,
                        help="Class ID (0-8). See LABEL_MAP.")
    parser.add_argument("--class-name", required=True,
                        choices=list(LABEL_MAP.keys()),
                        help="Class name")
    parser.add_argument("--output", required=True,
                        help="Output CSV path")
    parser.add_argument("--append", action="store_true",
                        help="Append to existing CSV instead of overwriting")
    args = parser.parse_args()

    # Validate class_id vs class_name
    expected_id = LABEL_MAP[args.class_name]
    if args.class_id != expected_id:
        log.error("class_id=%d does not match class_name='%s' (expected %d)",
                  args.class_id, args.class_name, expected_id)
        sys.exit(1)

    nfstream = try_import_nfstream()
    all_dfs = []

    if args.pcap:
        exp_id = args.experiment_id or Path(args.pcap).stem
        df = process_pcap(args.pcap, exp_id, args.class_id, args.class_name, nfstream)
        if not df.empty:
            df = clean_dataframe(df)
            validate_dataframe(df, args.class_name)
            all_dfs.append(df)

    elif args.class_dir:
        pcap_files = sorted(glob.glob(os.path.join(args.class_dir, "*.pcap")))
        if not pcap_files:
            log.error("No PCAP files found in: %s", args.class_dir)
            sys.exit(1)
        log.info("Found %d PCAP files in %s", len(pcap_files), args.class_dir)
        for pcap_path in pcap_files:
            exp_id = Path(pcap_path).stem
            df = process_pcap(pcap_path, exp_id, args.class_id, args.class_name, nfstream)
            if not df.empty:
                df = clean_dataframe(df)
                all_dfs.append(df)
    else:
        parser.print_help()
        sys.exit(1)

    if not all_dfs:
        log.error("No data extracted. Check PCAP files.")
        sys.exit(1)

    final_df = pd.concat(all_dfs, ignore_index=True)
    log.info("Total flows for class '%s': %d", args.class_name, len(final_df))
    validate_dataframe(final_df, args.class_name)

    # Print columns that should be dropped for ML
    log.info("\n=== ML DROP LIST (do not use as features) ===")
    present_drops = [c for c in ML_DROP_COLUMNS if c in final_df.columns]
    log.info("Columns to drop before ML training: %s", present_drops)

    save_csv(final_df, args.output, args.append)

    log.info("\nProcessing complete.")
    log.info("Output: %s", args.output)


if __name__ == "__main__":
    main()
