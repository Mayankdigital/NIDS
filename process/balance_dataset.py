#!/home/mayank/Desktop/DATACOLLECTION/venv/bin/python
"""
balance_dataset.py — Class-balance the NIDS training split
===========================================================
Reads:  nids_dataset/final/nids_dataset_ml.csv  (ML-ready, split column present)
Writes:
    nids_dataset/final/nids_dataset_balanced.csv   — balanced training set
    nids_dataset/final/nids_dataset_balanced_full.csv — balanced train + original val/test

Strategy:
    • Training split only is balanced (val/test remain untouched — realistic evaluation)
    • Minority classes (< TARGET_PER_CLASS):  SMOTE oversampling
    • Dominant classes (> TARGET_PER_CLASS):  RandomUnderSampler
    • Target: TARGET_PER_CLASS rows per class = 10,000

Requirements:
    pip install imbalanced-learn scikit-learn
"""
import sys
import logging
from pathlib import Path

import numpy as np
import pandas as pd

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [BALANCE] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("balance")

BASE_DIR       = Path(__file__).parent.parent / "nids_dataset" / "final"
ML_CSV         = BASE_DIR / "nids_dataset_ml.csv"
SPLITS_CSV     = Path(__file__).parent.parent / "nids_dataset" / "final" / "nids_dataset_splits.csv"
BALANCED_CSV   = BASE_DIR / "nids_dataset_balanced.csv"
BALANCED_FULL  = BASE_DIR / "nids_dataset_balanced_full.csv"

TARGET_PER_CLASS = 20_000
RANDOM_STATE     = 42

LABEL_MAP = {
    0: "benign", 1: "port_scan", 2: "dos",    3: "ddos",
    4: "brute_force", 5: "web_attack",
}


def check_imports():
    try:
        from imblearn.over_sampling import SMOTE
        from imblearn.under_sampling import RandomUnderSampler
        from imblearn.pipeline import Pipeline
        return SMOTE, RandomUnderSampler, Pipeline
    except ImportError:
        log.error("imbalanced-learn not installed. Run:\n"
                  "  pip install imbalanced-learn scikit-learn")
        sys.exit(1)


def print_distribution(y: pd.Series, label: str = ""):
    log.info("%sClass distribution:", f"[{label}] " if label else "")
    counts = y.value_counts().sort_index()
    total = len(y)
    for cls_id, cnt in counts.items():
        cls_name = LABEL_MAP.get(int(cls_id), f"class_{cls_id}")
        log.info("  %-16s (label=%d): %7d  (%.2f%%)",
                 cls_name, int(cls_id), cnt, cnt / total * 100)
    log.info("  Total: %d | Min: %d | Max: %d | Ratio: %.0fx",
             total, counts.min(), counts.max(),
             counts.max() / max(counts.min(), 1))


def balance_training_split(X_train: pd.DataFrame, y_train: pd.Series,
                            SMOTE, RandomUnderSampler, Pipeline) -> tuple:
    """
    Apply SMOTE then RandomUnderSampler to make all classes ≈ TARGET_PER_CLASS.

    SMOTE first brings all minority classes up (needs k_neighbors samples).
    RandomUnderSampler then caps all classes at TARGET_PER_CLASS.
    """
    log.info("── Before balancing ─────────────────────────────────────────")
    print_distribution(y_train, "TRAIN before")

    counts = y_train.value_counts()

    # SMOTE requires at least k_neighbors+1 samples.
    # For very small classes, reduce k_neighbors dynamically.
    min_samples = counts.min()
    k_neighbors = min(5, min_samples - 1)
    if k_neighbors < 1:
        log.warning(
            "Some classes have only %d sample(s). Using k_neighbors=1 for SMOTE.",
            min_samples
        )
        k_neighbors = 1

    # Oversampling targets: bring all classes below TARGET up to TARGET
    over_strategy = {
        int(cls): TARGET_PER_CLASS
        for cls, cnt in counts.items()
        if cnt < TARGET_PER_CLASS
    }

    # Undersampling targets: bring all classes above TARGET down to TARGET
    under_strategy = {
        int(cls): TARGET_PER_CLASS
        for cls, cnt in counts.items()
        if cnt > TARGET_PER_CLASS
    }

    log.info("Oversample targets  (SMOTE)  : %s", over_strategy)
    log.info("Undersample targets (Random) : %s", under_strategy)

    steps = []
    if over_strategy:
        steps.append(("smote", SMOTE(
            sampling_strategy=over_strategy,
            k_neighbors=k_neighbors,
            random_state=RANDOM_STATE,
        )))
    if under_strategy:
        steps.append(("under", RandomUnderSampler(
            sampling_strategy=under_strategy,
            random_state=RANDOM_STATE,
        )))

    if not steps:
        log.info("Dataset already balanced — no resampling needed.")
        return X_train, y_train

    pipe = Pipeline(steps=steps)

    log.info("Running resampling pipeline... (this may take a minute)")
    X_bal, y_bal = pipe.fit_resample(X_train, y_train)

    log.info("── After balancing ──────────────────────────────────────────")
    print_distribution(pd.Series(y_bal), "TRAIN after")

    return pd.DataFrame(X_bal, columns=X_train.columns), pd.Series(y_bal, name="label")


def main():
    SMOTE, RandomUnderSampler, Pipeline = check_imports()

    # ── Load ML-ready CSV ────────────────────────────────────────────────────
    if not ML_CSV.exists():
        log.error("ML CSV not found: %s\nRun process/merge_dataset.py first.", ML_CSV)
        sys.exit(1)

    log.info("Loading ML-ready dataset: %s", ML_CSV)
    df = pd.read_csv(ML_CSV, low_memory=False)
    log.info("Loaded: %d rows, %d cols", len(df), len(df.columns))

    if "split" not in df.columns:
        log.error("'split' column not found. Run process/merge_dataset.py first.")
        sys.exit(1)

    if "label" not in df.columns:
        log.error("'label' column not found.")
        sys.exit(1)

    # ── Separate splits ──────────────────────────────────────────────────────
    train_df = df[df["split"] == "train"].copy()
    val_df   = df[df["split"] == "val"].copy()
    test_df  = df[df["split"] == "test"].copy()

    log.info("Split sizes — Train: %d | Val: %d | Test: %d",
             len(train_df), len(val_df), len(test_df))

    # ── Prepare X/y for training split ───────────────────────────────────────
    meta_cols = ["split", "label"]
    feature_cols = [c for c in train_df.columns if c not in meta_cols]

    # Ensure all features are numeric
    X_train = train_df[feature_cols].copy()
    y_train = train_df["label"].copy()

    # Handle remaining non-numeric cols (convert or drop)
    non_numeric = X_train.select_dtypes(exclude=[np.number]).columns.tolist()
    if non_numeric:
        log.warning("Dropping remaining non-numeric columns before SMOTE: %s",
                    non_numeric)
        X_train = X_train.drop(columns=non_numeric)
        feature_cols = list(X_train.columns)

    # Fill any residual NaNs
    X_train = X_train.fillna(0.0)

    # ── Balance ──────────────────────────────────────────────────────────────
    X_bal, y_bal = balance_training_split(
        X_train, y_train, SMOTE, RandomUnderSampler, Pipeline
    )

    # ── Reconstruct balanced train DataFrame ─────────────────────────────────
    bal_train = X_bal.copy()
    bal_train["label"] = y_bal.values
    bal_train["split"] = "train"

    # ── Save balanced training set only ──────────────────────────────────────
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    bal_train.to_csv(BALANCED_CSV, index=False)
    log.info("Saved balanced training set: %s  (%d rows, %d cols)",
             BALANCED_CSV, len(bal_train), len(bal_train.columns))

    # ── Save balanced train + original val/test ───────────────────────────────
    # Keep only shared feature columns in val/test
    shared_cols = [c for c in bal_train.columns
                   if c in val_df.columns or c in ["label", "split"]]

    val_part  = val_df[[c for c in shared_cols if c in val_df.columns]].copy()
    test_part = test_df[[c for c in shared_cols if c in test_df.columns]].copy()

    # Fill missing feature cols with 0 for non-SMOTE-generated rows
    for col in bal_train.columns:
        if col not in val_part.columns:
            val_part[col] = 0.0
        if col not in test_part.columns:
            test_part[col] = 0.0

    full_df = pd.concat(
        [bal_train, val_part[bal_train.columns], test_part[bal_train.columns]],
        ignore_index=True
    )
    full_df.to_csv(BALANCED_FULL, index=False)
    log.info("Saved full balanced dataset (train+val+test): %s  (%d rows)",
             BALANCED_FULL, len(full_df))

    # ── Final summary ─────────────────────────────────────────────────────────
    print("\n=== Balancing Summary ===")
    print(f"  {'CLASS':<16} {'LABEL':<6} {'ORIG TRAIN':>12} {'BALANCED':>12}")
    print(f"  {'-'*50}")
    orig_counts = y_train.value_counts().sort_index()
    bal_counts  = y_bal.value_counts().sort_index()
    for lbl in sorted(set(orig_counts.index) | set(bal_counts.index)):
        cls_name = LABEL_MAP.get(int(lbl), f"class_{lbl}")
        orig = orig_counts.get(lbl, 0)
        bal  = bal_counts.get(lbl, 0)
        direction = "↑ SMOTE" if bal > orig else ("↓ under" if bal < orig else "=")
        print(f"  {cls_name:<16} {int(lbl):<6} {orig:>12,} {bal:>12,}  {direction}")
    print(f"  {'-'*50}")
    print(f"  {'TOTAL':<16} {'':6} {len(y_train):>12,} {len(y_bal):>12,}")

    print(f"\n✓ Balanced training set : {BALANCED_CSV}")
    print(f"✓ Full (train+val+test) : {BALANCED_FULL}")
    log.info("Done.")


if __name__ == "__main__":
    main()
