#!/home/mayank/Desktop/DATACOLLECTION/venv/bin/python
"""
merge_dataset.py — Merge all per-class CSVs into one final labeled dataset
===========================================================================
Usage:
    python3 process/merge_dataset.py
    python3 process/merge_dataset.py --output nids_dataset/final/nids_dataset.csv

Reads from: nids_dataset/processed/*.csv
Writes to:
    nids_dataset/final/nids_dataset.csv          — full merged, cleaned dataset
    nids_dataset/final/nids_dataset_splits.csv   — with train/val/test split column
    nids_dataset/final/nids_dataset_ml.csv       — ML-ready (leakage cols dropped)
    nids_dataset/final/dataset_report.txt        — EDA summary report

Improvements over v1:
    1. splt_* string-list cols → 30 individual numeric cols
    2. Zero-variance + high-null columns auto-dropped
    3. protocol_name decoded (TCP/UDP/ICMP/OTHER)
    4. ML-leakage columns physically removed from nids_dataset_ml.csv
    5. Auto-generated EDA report
"""
import os
import sys
import glob
import logging
import textwrap
from pathlib import Path
from collections import defaultdict
from io import StringIO

import numpy as np
import pandas as pd

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [MERGE] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("merge")

BASE_DIR   = Path(__file__).parent.parent / "nids_dataset"
PROC_DIR   = BASE_DIR / "processed"
FINAL_DIR  = BASE_DIR / "final"
FINAL_CSV  = FINAL_DIR / "nids_dataset.csv"
SPLITS_CSV = FINAL_DIR / "nids_dataset_splits.csv"
ML_CSV     = FINAL_DIR / "nids_dataset_ml.csv"
REPORT_TXT = FINAL_DIR / "dataset_report.txt"

LABEL_MAP = {
    "benign": 0, "port_scan": 1, "dos": 2, "ddos": 3,
    "brute_force": 4, "web_attack": 5,
    # icmp_flood removed — too few real samples
    # network_recon removed — overlaps with port_scan, too few samples
}

EXCLUDE_CLASSES = {"icmp_flood", "network_recon", "udp_flood"}  # dropped from training

# Columns to physically remove from ML CSV (leakage, identifiers, non-generalizable)
ML_DROP_COLUMNS = [
    "id", "expiration_id",
    "src_ip", "dst_ip", "src_mac", "dst_mac", "src_oui", "dst_oui",
    "src_port", "dst_port",
    "bidirectional_first_seen_ms", "bidirectional_last_seen_ms",
    "src2dst_first_seen_ms", "src2dst_last_seen_ms",
    "dst2src_first_seen_ms", "dst2src_last_seen_ms",
    "application_name", "application_category_name",
    "application_is_guessed", "application_confidence",
    "requested_server_name", "client_fingerprint",
    "server_fingerprint", "user_agent", "content_type",
    "experiment_id", "class_name", "pcap_file", "processed_at",
    # splt raw string cols — replaced by flattened numeric versions
    "splt_direction", "splt_ps", "splt_piat_ms",
]

PROTOCOL_MAP = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}

NULL_DROP_THRESHOLD = 0.80   # drop columns with >80% nulls across full dataset


# ─────────────────────────────────────────────────────────────────────────────
# Feature engineering helpers
# ─────────────────────────────────────────────────────────────────────────────

def flatten_splt_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Expand splt_direction, splt_ps, splt_piat_ms from string-encoded lists
    (e.g. "[0, 1, 0, ...]") into 30 individual numeric columns:
        splt_direction_0 .. splt_direction_9
        splt_ps_0        .. splt_ps_9
        splt_piat_ms_0   .. splt_piat_ms_9

    Uses a single pd.concat to avoid DataFrame fragmentation.
    """
    splt_cols = {
        "splt_direction": "splt_direction",
        "splt_ps":        "splt_ps",
        "splt_piat_ms":   "splt_piat_ms",
    }

    new_cols = []

    for raw_col, prefix in splt_cols.items():
        if raw_col not in df.columns:
            log.warning("Column %s not found — skipping splt flatten.", raw_col)
            continue

        def safe_parse(val, length=10):
            try:
                if isinstance(val, str):
                    parsed = [float(x) for x in val.strip("[]").split(",")]
                elif isinstance(val, list):
                    parsed = [float(x) for x in val]
                else:
                    return [0.0] * length
                return (parsed + [0.0] * length)[:length]
            except Exception:
                return [0.0] * length

        parsed = df[raw_col].apply(safe_parse)
        expanded = pd.DataFrame(
            parsed.tolist(),
            columns=[f"{prefix}_{i}" for i in range(10)],
            index=df.index,
        )
        new_cols.append(expanded)
        log.info("Flattened '%s' → %s_{0..9}", raw_col, prefix)

    if new_cols:
        df = pd.concat([df] + new_cols, axis=1)

    return df


def add_protocol_name(df: pd.DataFrame) -> pd.DataFrame:
    """Add human-readable protocol_name column next to numeric protocol."""
    if "protocol" in df.columns:
        df.insert(
            df.columns.get_loc("protocol") + 1,
            "protocol_name",
            df["protocol"].map(PROTOCOL_MAP).fillna("OTHER")
        )
        log.info("Added protocol_name column.")
    return df


def add_rate_features(df: pd.DataFrame) -> pd.DataFrame:
    """Add rate-based features to distinguish slow recon from fast port scans."""
    if "bidirectional_duration_ms" in df.columns:
        # Avoid division by zero by clamping minimum duration to 1ms
        duration_s = df["bidirectional_duration_ms"].clip(lower=1.0) / 1000.0
        
        if "bidirectional_packets" in df.columns:
            df["packets_per_sec"] = df["bidirectional_packets"] / duration_s
            df["bytes_per_packet"] = df["bidirectional_bytes"] / df["bidirectional_packets"].clip(lower=1.0)
            
        if "bidirectional_bytes" in df.columns:
            df["bytes_per_sec"] = df["bidirectional_bytes"] / duration_s
            
        log.info("Added rate-based features (packets/sec, bytes/sec, bytes/pkt).")
    return df


def drop_low_info_columns(df: pd.DataFrame) -> pd.DataFrame:
    """
    Drop:
      1. Zero-variance numeric columns (constant value across all rows)
      2. Columns with > NULL_DROP_THRESHOLD fraction of nulls
    Returns cleaned df and prints a report.
    """
    dropped_zero_var = []
    dropped_high_null = []

    numeric_cols = df.select_dtypes(include=[np.number]).columns
    for col in numeric_cols:
        if df[col].nunique(dropna=True) <= 1:
            dropped_zero_var.append(col)

    null_rate = df.isnull().mean()
    for col in df.columns:
        if null_rate[col] > NULL_DROP_THRESHOLD and col not in dropped_zero_var:
            dropped_high_null.append(col)

    all_dropped = dropped_zero_var + dropped_high_null
    if dropped_zero_var:
        log.info("Dropping %d zero-variance columns: %s",
                 len(dropped_zero_var), dropped_zero_var)
    if dropped_high_null:
        log.info("Dropping %d high-null (>%.0f%%) columns: %s",
                 len(dropped_high_null), NULL_DROP_THRESHOLD * 100, dropped_high_null)

    df = df.drop(columns=[c for c in all_dropped if c in df.columns])
    log.info("Column count after low-info drop: %d", len(df.columns))
    return df, dropped_zero_var, dropped_high_null


# ─────────────────────────────────────────────────────────────────────────────
# Split assignment (experiment-level, no leakage)
# ─────────────────────────────────────────────────────────────────────────────

def assign_splits(df: pd.DataFrame) -> pd.DataFrame:
    """
    Standard 80/10/10 stratified split across the entire dataset.
    This guarantees that if you collect >25k flows for a class, ~20k go to Train,
    avoiding the need for SMOTE and ensuring valid evaluation.
    """
    from sklearn.model_selection import train_test_split
    
    if "label" not in df.columns:
        log.warning("No label column. Assigning all to train.")
        df["split"] = "train"
        return df

    # First split into train (80%) and temp (20%)
    train_idx, temp_idx = train_test_split(
        df.index, test_size=0.20, random_state=42, stratify=df["label"]
    )
    
    # Split temp into val (10%) and test (10%)
    val_idx, test_idx = train_test_split(
        temp_idx, test_size=0.50, random_state=42, stratify=df.loc[temp_idx, "label"]
    )
    
    df["split"] = "train"
    df.loc[val_idx, "split"] = "val"
    df.loc[test_idx, "split"] = "test"
    
    return df


# ─────────────────────────────────────────────────────────────────────────────
# EDA Report
# ─────────────────────────────────────────────────────────────────────────────

def generate_report(df: pd.DataFrame, dropped_zero_var, dropped_high_null,
                    report_path: Path):
    """Generate a human-readable EDA report and save to file."""
    buf = StringIO()

    def w(s=""):
        buf.write(s + "\n")

    w("=" * 70)
    w("  NIDS DATASET — EDA REPORT")
    w("=" * 70)
    w()

    w("── DATASET SHAPE ─────────────────────────────────────────────────────")
    w(f"  Total rows    : {len(df):,}")
    w(f"  Total columns : {len(df.columns)}")
    w()

    w("── CLASS DISTRIBUTION ────────────────────────────────────────────────")
    w(f"  {'CLASS':<16} {'LABEL':<6} {'ROWS':>10} {'%':>8}")
    w(f"  {'-'*44}")
    total = len(df)
    for lbl in sorted(df["label"].unique()):
        g = df[df["label"] == lbl]
        cls = g["class_name"].iloc[0] if "class_name" in g.columns else f"class_{lbl}"
        cnt = len(g)
        w(f"  {cls:<16} {int(lbl):<6} {cnt:>10,} {cnt/total*100:>7.2f}%")
    w(f"  {'-'*44}")
    w(f"  {'TOTAL':<16} {'':6} {total:>10,} {'100.00%':>8}")
    imbal = df["label"].value_counts()
    w(f"\n  Max/Min ratio  : {imbal.max()/imbal.min():.0f}x")
    w()

    if "split" in df.columns:
        w("── TRAIN / VAL / TEST SPLIT ──────────────────────────────────────────")
        w(f"  {'CLASS':<16} {'LABEL':<6} {'TRAIN':>8} {'VAL':>8} {'TEST':>8} {'TOTAL':>8}")
        w(f"  {'-'*58}")
        for lbl in sorted(df["label"].unique()):
            g = df[df["label"] == lbl]
            cls = g["class_name"].iloc[0] if "class_name" in g.columns else f"class_{lbl}"
            tr = (g["split"] == "train").sum()
            va = (g["split"] == "val").sum()
            te = (g["split"] == "test").sum()
            w(f"  {cls:<16} {int(lbl):<6} {tr:>8,} {va:>8,} {te:>8,} {len(g):>8,}")
        w(f"  {'-'*58}")
        w(f"  {'TOTAL':<16} {'':6} "
          f"{(df['split']=='train').sum():>8,} "
          f"{(df['split']=='val').sum():>8,} "
          f"{(df['split']=='test').sum():>8,} "
          f"{total:>8,}")
        w()

    if "protocol_name" in df.columns:
        w("── PROTOCOL DISTRIBUTION ─────────────────────────────────────────────")
        proto_counts = df["protocol_name"].value_counts()
        for proto, cnt in proto_counts.items():
            w(f"  {proto:<12}: {cnt:>10,}  ({cnt/total*100:.2f}%)")
        w()

    w("── NULL RATES (top 20 columns with nulls) ────────────────────────────")
    null_rates = (df.isnull().mean() * 100).sort_values(ascending=False)
    null_nonzero = null_rates[null_rates > 0].head(20)
    if null_nonzero.empty:
        w("  None — dataset is fully clean ✓")
    else:
        for col, rate in null_nonzero.items():
            w(f"  {col:<45}: {rate:>6.2f}%")
    w()

    w("── DROPPED COLUMNS ───────────────────────────────────────────────────")
    w(f"  Zero-variance ({len(dropped_zero_var)}):")
    for c in dropped_zero_var:
        w(f"    - {c}")
    w(f"  High-null >80% ({len(dropped_high_null)}):")
    for c in dropped_high_null:
        w(f"    - {c}")
    w()

    w("── NUMERIC FEATURE STATISTICS ────────────────────────────────────────")
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    # Exclude label/id-like columns from stat summary
    stat_cols = [c for c in numeric_cols
                 if c not in {"label", "id", "protocol", "ip_version",
                              "vlan_id", "tunnel_id", "expiration_id"}]
    if stat_cols:
        desc = df[stat_cols].describe().T[["mean", "std", "min", "max"]]
        for col, row in desc.iterrows():
            w(f"  {col:<45}  mean={row['mean']:>12.3f}  std={row['std']:>12.3f}"
              f"  min={row['min']:>12.3f}  max={row['max']:>12.3f}")
    w()

    w("=" * 70)
    w("  Generated by process/merge_dataset.py (v2)")
    w("=" * 70)

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(buf.getvalue())
    log.info("EDA report saved: %s", report_path)


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    FINAL_DIR.mkdir(parents=True, exist_ok=True)

    csv_files = sorted(PROC_DIR.glob("*.csv"))
    if not csv_files:
        log.error("No CSVs found in %s. Run nfstream_processor.py first.", PROC_DIR)
        sys.exit(1)

    # ── Load all per-class CSVs ──────────────────────────────────────────────
    dfs = []
    for csv_file in csv_files:
        log.info("Loading: %s", csv_file.name)
        try:
            df = pd.read_csv(csv_file, low_memory=False)
            log.info("  → %d rows, class=%s",
                     len(df), df.get("class_name", pd.Series(["?"])).iloc[0])
            dfs.append(df)
        except Exception as e:
            log.error("Failed to load %s: %s", csv_file, e)

    if not dfs:
        log.error("No data loaded.")
        sys.exit(1)

    merged = pd.concat(dfs, ignore_index=True)
    log.info("Merged (raw): %d total rows, %d columns", len(merged), len(merged.columns))

    # ── Drop excluded classes ────────────────────────────────────────────────
    if EXCLUDE_CLASSES and "class_name" in merged.columns:
        before = len(merged)
        merged = merged[~merged["class_name"].isin(EXCLUDE_CLASSES)].copy()
        log.info("Dropped excluded classes %s: %d → %d rows",
                 EXCLUDE_CLASSES, before, len(merged))

    # Re-apply label from LABEL_MAP so remapped labels are consistent
    if "class_name" in merged.columns:
        merged["label"] = merged["class_name"].map(LABEL_MAP)
        unmapped = merged["label"].isna().sum()
        if unmapped > 0:
            log.warning("Dropping %d rows with unmapped class names", unmapped)
            merged = merged[merged["label"].notna()].copy()
        merged["label"] = merged["label"].astype(int)

    # ── Feature engineering ──────────────────────────────────────────────────
    log.info("Step 1/5: Flattening splt_* features...")
    merged = flatten_splt_features(merged)

    log.info("Step 2/5: Adding protocol_name...")
    merged = add_protocol_name(merged)
    
    log.info("Step 2.5/5: Adding rate features...")
    merged = add_rate_features(merged)

    # ── Drop low-info columns ────────────────────────────────────────────────
    log.info("Step 3/5: Dropping zero-variance & high-null columns...")
    merged, dropped_zero_var, dropped_high_null = drop_low_info_columns(merged)

    # ── Verify label integrity ───────────────────────────────────────────────
    if "label" in merged.columns and "class_name" in merged.columns:
        mismatches = merged[
            merged["label"] != merged["class_name"].map(LABEL_MAP)
        ]
        if not mismatches.empty:
            log.warning("Label/class_name mismatches: %d rows", len(mismatches))
        else:
            log.info("Label integrity check: OK ✓")

    # ── Sort by class then experiment ────────────────────────────────────────
    sort_cols = []
    if "label" in merged.columns:         sort_cols.append("label")
    if "experiment_id" in merged.columns: sort_cols.append("experiment_id")
    if sort_cols:
        merged = merged.sort_values(sort_cols).reset_index(drop=True)

    # ── Save full merged dataset ─────────────────────────────────────────────
    merged.to_csv(FINAL_CSV, index=False)
    log.info("Saved full merged dataset: %s  (%d rows, %d cols)",
             FINAL_CSV, len(merged), len(merged.columns))

    # ── Assign experiment-level splits ───────────────────────────────────────
    log.info("Step 4/5: Assigning train/val/test splits...")
    merged = assign_splits(merged)

    split_counts = merged["split"].value_counts()
    log.info("Split distribution:\n%s", split_counts.to_string())

    merged.to_csv(SPLITS_CSV, index=False)
    log.info("Saved dataset with splits: %s", SPLITS_CSV)

    # ── Save ML-ready CSV (leakage columns physically removed) ───────────────
    log.info("Step 5/5: Saving ML-ready CSV (leakage columns removed)...")
    ml_drop_present = [c for c in ML_DROP_COLUMNS if c in merged.columns]
    ml_df = merged.drop(columns=ml_drop_present)
    # Also drop the raw splt string columns if still present
    for raw_splt in ["splt_direction", "splt_ps", "splt_piat_ms"]:
        if raw_splt in ml_df.columns:
            ml_df = ml_df.drop(columns=[raw_splt])
    ml_df.to_csv(ML_CSV, index=False)
    log.info("Saved ML-ready CSV: %s  (%d rows, %d cols)",
             ML_CSV, len(ml_df), len(ml_df.columns))
    log.info("Dropped %d leakage/meta columns from ML CSV.", len(ml_drop_present))

    # ── Generate EDA report ──────────────────────────────────────────────────
    generate_report(merged, dropped_zero_var, dropped_high_null, REPORT_TXT)

    # ── Print split summary ──────────────────────────────────────────────────
    print("\n=== Split Summary ===")
    print(f"{'CLASS':<16} {'LABEL':<6} {'TRAIN':>8} {'VAL':>8} {'TEST':>8} {'TOTAL':>8}")
    print("-" * 60)
    for lbl in sorted(merged["label"].unique()):
        grp = merged[merged["label"] == lbl]
        cls = grp["class_name"].iloc[0] if "class_name" in grp.columns else f"class_{lbl}"
        train = (grp["split"] == "train").sum()
        val   = (grp["split"] == "val").sum()
        test  = (grp["split"] == "test").sum()
        total = len(grp)
        print(f"{cls:<16} {int(lbl):<6} {train:>8,} {val:>8,} {test:>8,} {total:>8,}")
    print("-" * 60)
    total = len(merged)
    print(f"{'TOTAL':<16} {'':6} "
          f"{(merged['split']=='train').sum():>8,} "
          f"{(merged['split']=='val').sum():>8,} "
          f"{(merged['split']=='test').sum():>8,} "
          f"{total:>8,}")

    print(f"\n✓ Full dataset   : {FINAL_CSV}")
    print(f"✓ With splits    : {SPLITS_CSV}")
    print(f"✓ ML-ready       : {ML_CSV}")
    print(f"✓ EDA report     : {REPORT_TXT}")
    log.info("Done.")


if __name__ == "__main__":
    main()
