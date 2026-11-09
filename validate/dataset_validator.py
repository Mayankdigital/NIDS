#!/home/mayank/Desktop/DATACOLLECTION/venv/bin/python
"""
dataset_validator.py — Full dataset validation + plots
======================================================
Usage:
    # Validate all per-class CSVs
    python3 validate/dataset_validator.py

    # Validate a specific CSV
    python3 validate/dataset_validator.py --csv nids_dataset/processed/port_scan.csv

    # Validate the merged final dataset
    python3 validate/dataset_validator.py --csv nids_dataset/final/nids_dataset.csv --final

    # Skip plot generation (headless server)
    python3 validate/dataset_validator.py --no-plots
"""
import argparse
import os
import sys
import warnings
from pathlib import Path

import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")

# ── Label map ────────────────────────────────────────────────────────────────
LABEL_MAP = {
    0: "BENIGN", 1: "PORT_SCAN", 2: "DOS", 3: "DDOS",
    4: "BRUTE_FORCE", 5: "NETWORK_RECON",
    6: "UDP_FLOOD", 7: "ICMP_FLOOD", 8: "WEB_ATTACK",
}

CLASS_DIRS = {
    "benign": 0, "port_scan": 1, "dos": 2, "ddos": 3,
    "brute_force": 4, "network_recon": 5,
    "udp_flood": 6, "icmp_flood": 7, "web_attack": 8,
}

BASE_DIR = Path(__file__).parent.parent / "nids_dataset"
PROCESSED_DIR = BASE_DIR / "processed"
FINAL_DIR = BASE_DIR / "final"
PLOT_DIR = BASE_DIR / "final" / "plots"


# ── Helpers ───────────────────────────────────────────────────────────────────
def _sep(title=""):
    w = 70
    if title:
        pad = (w - len(title) - 2) // 2
        print(f"\n{'='*pad} {title} {'='*pad}")
    else:
        print("=" * w)


def _load_csv(path: str) -> pd.DataFrame:
    try:
        df = pd.read_csv(path, low_memory=False)
        print(f"  Loaded: {path}  ({len(df):,} rows, {len(df.columns)} cols)")
        return df
    except Exception as e:
        print(f"  [ERROR] Cannot load {path}: {e}")
        return pd.DataFrame()


def report_basic(df: pd.DataFrame, name: str):
    _sep(f"Basic Report: {name}")
    print(f"  Rows:    {len(df):,}")
    print(f"  Columns: {len(df.columns)}")

    # Label distribution
    if "label" in df.columns:
        print("\n  Label distribution:")
        vc = df["label"].value_counts().sort_index()
        for lbl, cnt in vc.items():
            cls = LABEL_MAP.get(int(lbl), f"class_{lbl}")
            pct = 100 * cnt / len(df)
            bar = "█" * int(pct / 2)
            print(f"    [{int(lbl)}] {cls:<16} {cnt:>8,}  ({pct:5.1f}%)  {bar}")

    if "class_name" in df.columns:
        print("\n  Class name distribution:")
        print(df["class_name"].value_counts().to_string(dtype=False))


def report_missing(df: pd.DataFrame):
    _sep("Missing Values")
    total_cells = df.shape[0] * df.shape[1]
    total_nan = df.isnull().sum().sum()
    print(f"  Total cells: {total_cells:,}")
    print(f"  Total NaN:   {total_nan:,}  ({100*total_nan/total_cells:.3f}%)")

    nan_cols = df.isnull().sum()
    nan_cols = nan_cols[nan_cols > 0]
    if nan_cols.empty:
        print("  No missing values. ✓")
    else:
        print("\n  Columns with NaN:")
        for col, cnt in nan_cols.items():
            print(f"    {col:<50} {cnt:>8,}")


def report_duplicates(df: pd.DataFrame):
    _sep("Duplicate Records")
    n_dup_full = df.duplicated().sum()
    print(f"  Exact duplicate rows: {n_dup_full:,}")

    if "experiment_id" in df.columns and "src_ip" in df.columns:
        flow_cols = ["src_ip", "dst_ip", "src_port", "dst_port", "protocol"]
        available = [c for c in flow_cols if c in df.columns]
        if available:
            n_dup_flow = df.duplicated(subset=available).sum()
            print(f"  Flow-key duplicates:   {n_dup_flow:,}")

    if n_dup_full == 0:
        print("  No duplicates. ✓")


def report_invalid(df: pd.DataFrame):
    _sep("Invalid Values")
    numeric = df.select_dtypes(include=[np.number])

    n_inf = np.isinf(numeric.values).sum()
    n_neg = (numeric < 0).sum().sum()

    print(f"  Infinite values: {n_inf:,}")
    print(f"  Negative values in numeric cols: {n_neg:,}")

    if n_neg > 0:
        neg_cols = numeric.columns[(numeric < 0).any()]
        print(f"  Columns with negatives: {list(neg_cols)}")


def report_constant_features(df: pd.DataFrame):
    _sep("Constant / Near-Zero Variance Features")
    numeric = df.select_dtypes(include=[np.number])
    constant = [c for c in numeric.columns if numeric[c].nunique() <= 1]
    near_zero = [c for c in numeric.columns
                 if numeric[c].std() < 1e-9 and c not in constant]

    if constant:
        print(f"  Constant features ({len(constant)}): {constant}")
    else:
        print("  No constant features. ✓")

    if near_zero:
        print(f"  Near-zero variance ({len(near_zero)}): {near_zero[:10]} ...")
    else:
        print("  No near-zero variance features. ✓")


def report_flow_stats(df: pd.DataFrame):
    _sep("Flow Statistics")

    cols_of_interest = {
        "bidirectional_packets":    "Packets/flow",
        "bidirectional_bytes":      "Bytes/flow",
        "bidirectional_duration_ms": "Duration (ms)",
        "src2dst_packets":          "Src→Dst packets",
        "dst2src_packets":          "Dst→Src packets",
    }

    for col, label in cols_of_interest.items():
        if col in df.columns:
            s = df[col].describe()
            print(f"\n  {label}:")
            print(f"    mean={s['mean']:.1f}  median={df[col].median():.1f}  "
                  f"std={s['std']:.1f}  min={s['min']:.0f}  max={s['max']:.0f}")


def report_protocol(df: pd.DataFrame):
    _sep("Protocol Distribution")
    if "protocol" in df.columns:
        vc = df["protocol"].value_counts()
        for proto, cnt in vc.items():
            pct = 100 * cnt / len(df)
            print(f"  {proto:<10} {cnt:>8,}  ({pct:.1f}%)")
    else:
        print("  'protocol' column not found.")


def report_interface(df: pd.DataFrame):
    _sep("Interface Distribution")
    if "interface" in df.columns:
        print(df["interface"].value_counts().to_string())
    elif "experiment_id" in df.columns:
        # Try to infer from metadata
        print("  'interface' column not in dataset. Check metadata/experiments.csv")
    else:
        print("  No interface info in this dataset.")


def report_leakage_risk(df: pd.DataFrame):
    _sep("Data Leakage Risk Assessment")

    HIGH_RISK = ["src_ip", "dst_ip", "src_port", "dst_port",
                 "src_mac", "dst_mac", "experiment_id",
                 "class_name", "label"]
    MEDIUM_RISK = ["first_seen", "last_seen", "processed_at",
                   "application_name", "application_category_name"]

    present_high = [c for c in HIGH_RISK if c in df.columns]
    present_med  = [c for c in MEDIUM_RISK if c in df.columns]

    print("  HIGH RISK (must drop before ML training):")
    if present_high:
        for c in present_high:
            if c in ("src_ip", "dst_ip") and "label" in df.columns:
                # Check if IP highly correlates with label
                by_label = df.groupby("label")[c].nunique()
                print(f"    [HIGH] {c:<40} unique_per_label: {by_label.to_dict()}")
            else:
                print(f"    [HIGH] {c}")
    else:
        print("    None present.")

    print("\n  MEDIUM RISK (consider dropping):")
    if present_med:
        for c in present_med:
            print(f"    [MED]  {c}")
    else:
        print("    None present.")

    print("\n  ACTION: Before ML training, drop all HIGH RISK columns.")
    print("  The ML train script does this automatically.")


def report_experiment_split(df: pd.DataFrame):
    _sep("Experiment-Level Split Readiness")
    if "experiment_id" not in df.columns:
        print("  'experiment_id' not in dataset. Cannot assess split readiness.")
        return

    if "label" not in df.columns:
        return

    print("  Experiments per class:")
    for lbl, grp in df.groupby("label"):
        cls = LABEL_MAP.get(int(lbl), f"class_{lbl}")
        exps = grp["experiment_id"].nunique()
        exp_list = grp["experiment_id"].unique().tolist()
        rec = ""
        if exps < 4:
            rec = f"  ← Need ≥4 for train/val/test split (have {exps})"
        print(f"    [{int(lbl)}] {cls:<16}  {exps} experiments  "
              f"{exp_list[:4]}{'...' if len(exp_list)>4 else ''}  {rec}")


def make_plots(df: pd.DataFrame, name: str):
    """Generate validation plots. Requires matplotlib and seaborn."""
    try:
        import matplotlib
        matplotlib.use("Agg")  # headless
        import matplotlib.pyplot as plt
        import seaborn as sns
    except ImportError:
        print("  [PLOTS] matplotlib/seaborn not installed. Skipping plots.")
        return

    PLOT_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Flows per class
    if "label" in df.columns:
        fig, ax = plt.subplots(figsize=(12, 5))
        vc = df["label"].value_counts().sort_index()
        labels = [f"[{i}] {LABEL_MAP.get(i, str(i))}" for i in vc.index]
        bars = ax.bar(labels, vc.values, color=sns.color_palette("tab10", len(vc)))
        ax.set_title(f"Flows per Class — {name}", fontsize=14)
        ax.set_xlabel("Class")
        ax.set_ylabel("Flow Count")
        for bar, val in zip(bars, vc.values):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 5,
                    f"{val:,}", ha="center", va="bottom", fontsize=9)
        plt.xticks(rotation=30, ha="right")
        plt.tight_layout()
        out = PLOT_DIR / f"{name.lower().replace(' ','_')}_flows_per_class.png"
        plt.savefig(out, dpi=150)
        plt.close()
        print(f"  [PLOT] {out}")

    # 2. Protocol distribution
    if "protocol" in df.columns:
        fig, ax = plt.subplots(figsize=(8, 5))
        vc = df["protocol"].value_counts()
        ax.pie(vc.values, labels=vc.index, autopct="%1.1f%%", startangle=90)
        ax.set_title(f"Protocol Distribution — {name}")
        out = PLOT_DIR / f"{name.lower().replace(' ','_')}_protocol.png"
        plt.savefig(out, dpi=150)
        plt.close()
        print(f"  [PLOT] {out}")

    # 3. Flow duration box plots per class
    if "bidirectional_duration_ms" in df.columns and "label" in df.columns:
        df_plot = df.copy()
        df_plot["class_label"] = df_plot["label"].map(
            lambda x: f"[{int(x)}]{LABEL_MAP.get(int(x),'?')[:8]}")
        df_clipped = df_plot[df_plot["bidirectional_duration_ms"] < 1e6].copy()

        fig, ax = plt.subplots(figsize=(14, 6))
        order = sorted(df_clipped["class_label"].unique())
        try:
            sns.boxplot(data=df_clipped, x="class_label", y="bidirectional_duration_ms",
                        order=order, ax=ax, palette="tab10")
        except Exception:
            pass
        ax.set_title(f"Flow Duration per Class (ms) — {name}")
        ax.set_xlabel("Class")
        ax.set_ylabel("Duration (ms)")
        plt.xticks(rotation=30, ha="right")
        plt.tight_layout()
        out = PLOT_DIR / f"{name.lower().replace(' ','_')}_duration.png"
        plt.savefig(out, dpi=150)
        plt.close()
        print(f"  [PLOT] {out}")

    # 4. Packets per flow histogram
    if "bidirectional_packets" in df.columns and "label" in df.columns:
        fig, ax = plt.subplots(figsize=(10, 5))
        for lbl in sorted(df["label"].unique()):
            cls = LABEL_MAP.get(int(lbl), str(lbl))
            data = df[df["label"] == lbl]["bidirectional_packets"]
            data_clipped = data[data < data.quantile(0.99)]
            ax.hist(data_clipped, bins=50, alpha=0.5, label=f"[{int(lbl)}]{cls[:8]}")
        ax.set_title(f"Packets per Flow Distribution — {name}")
        ax.set_xlabel("Packets")
        ax.set_ylabel("Count")
        ax.legend(fontsize=8)
        plt.tight_layout()
        out = PLOT_DIR / f"{name.lower().replace(' ','_')}_packets.png"
        plt.savefig(out, dpi=150)
        plt.close()
        print(f"  [PLOT] {out}")

    # 5. Bytes per flow per class (log scale)
    if "bidirectional_bytes" in df.columns and "label" in df.columns:
        fig, ax = plt.subplots(figsize=(12, 5))
        means = df.groupby("label")["bidirectional_bytes"].median()
        labels = [f"[{int(i)}]{LABEL_MAP.get(int(i),'?')[:8]}" for i in means.index]
        ax.bar(labels, means.values, color=sns.color_palette("Set2", len(means)))
        ax.set_yscale("log")
        ax.set_title(f"Median Bytes per Flow per Class — {name}")
        ax.set_xlabel("Class")
        ax.set_ylabel("Bytes (log scale)")
        plt.xticks(rotation=30, ha="right")
        plt.tight_layout()
        out = PLOT_DIR / f"{name.lower().replace(' ','_')}_bytes.png"
        plt.savefig(out, dpi=150)
        plt.close()
        print(f"  [PLOT] {out}")

    print(f"  [PLOTS] All plots saved to: {PLOT_DIR}")


def validate_single_csv(csv_path: str, is_final: bool, make_plots_flag: bool):
    print(f"\n{'#'*70}")
    print(f"  Validating: {csv_path}")
    print(f"{'#'*70}")

    df = _load_csv(csv_path)
    if df.empty:
        print("[ERROR] Empty or unreadable CSV.")
        return

    name = Path(csv_path).stem

    report_basic(df, name)
    report_missing(df)
    report_duplicates(df)
    report_invalid(df)
    report_constant_features(df)
    report_flow_stats(df)
    report_protocol(df)
    report_interface(df)
    report_leakage_risk(df)

    if is_final:
        report_experiment_split(df)

    if make_plots_flag:
        _sep("Generating Plots")
        make_plots(df, name)


def main():
    parser = argparse.ArgumentParser(description="NIDS Dataset Validator")
    parser.add_argument("--csv", default=None,
                        help="Validate a specific CSV (default: validate all in processed/)")
    parser.add_argument("--final", action="store_true",
                        help="Treat input as the merged final dataset")
    parser.add_argument("--no-plots", action="store_true",
                        help="Skip plot generation")
    args = parser.parse_args()

    do_plots = not args.no_plots

    if args.csv:
        validate_single_csv(args.csv, args.final, do_plots)
    else:
        # Validate all processed CSVs
        csv_files = sorted(PROCESSED_DIR.glob("*.csv"))
        if not csv_files:
            print(f"No CSVs found in {PROCESSED_DIR}")
            print("Run nfstream_processor.py first to generate processed CSVs.")
            sys.exit(1)

        for csv_file in csv_files:
            validate_single_csv(str(csv_file), False, False)  # no per-class plots

        # Validate final merged dataset if it exists
        final_csv = FINAL_DIR / "nids_dataset.csv"
        if final_csv.exists():
            validate_single_csv(str(final_csv), True, do_plots)
        else:
            print(f"\n[INFO] Final merged dataset not found: {final_csv}")
            print("Run merge_dataset.py to create it.")

    _sep("Validation Complete")


if __name__ == "__main__":
    main()
