#!/home/mayank/Desktop/DATACOLLECTION/venv/bin/python
"""
train_eval.py — ML training and evaluation with experiment-level splitting
==========================================================================
Uses Random Forest and XGBoost as baselines.
Reports per-class Precision, Recall, F1, Macro-F1, Confusion Matrix.

Usage:
    python3 ml/train_eval.py \\
        --dataset nids_dataset/final/nids_dataset_splits.csv

    # Use only Random Forest (no XGBoost)
    python3 ml/train_eval.py --rf-only

    # Skip class balancing
    python3 ml/train_eval.py --no-balance

Design decisions:
  1. Experiment-level splits (pre-computed by merge_dataset.py) prevent leakage
  2. All leakage-risk columns are dropped before training
  3. Class imbalance addressed with class_weight='balanced' + SMOTE option
  4. Report Macro-F1, not accuracy alone
  5. Clearly document low-separability class pairs
"""
import argparse
import os
import sys
import warnings
from pathlib import Path

import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")

BASE_DIR  = Path(__file__).parent.parent / "nids_dataset"
FINAL_DIR = BASE_DIR / "final"
ML_OUT    = FINAL_DIR / "ml_results"

LABEL_MAP = {
    0: "BENIGN", 1: "PORT_SCAN", 2: "DOS", 3: "DDOS",
    4: "BRUTE_FORCE", 5: "NETWORK_RECON",
    6: "UDP_FLOOD", 7: "ICMP_FLOOD", 8: "WEB_ATTACK",
}

# Columns to ALWAYS drop before ML training
DROP_BEFORE_ML = [
    "src_ip", "dst_ip", "src_mac", "dst_mac",
    "src_port", "dst_port",
    "experiment_id", "class_name", "label", "split",
    "expiration_id", "id",
    "src_oui", "dst_oui",
    "application_name", "application_category_name",
    "application_is_guessed", "application_confidence",
    "requested_server_name", "client_fingerprint",
    "server_fingerprint", "user_agent", "content_type",
    "first_seen", "last_seen", "processed_at", "pcap_file",
    "bidirectional_first_seen_ms", "bidirectional_last_seen_ms",
    "src2dst_first_seen_ms", "dst2src_first_seen_ms",
]

# Known difficult pairs — document, don't hide
KNOWN_HARD_PAIRS = [
    ("PORT_SCAN",     "NETWORK_RECON",
     "Both use nmap; differ in rate and per-flow packet count."),
    ("DOS",           "UDP_FLOOD",
     "Both have high packet rate; protocol field (TCP vs UDP) is the main separator."),
    ("DOS",           "ICMP_FLOOD",
     "Both high rate; protocol (TCP=6 vs ICMP=1) distinguishes them."),
    ("BENIGN",        "BRUTE_FORCE",
     "Same HTTP port, similar flow sizes; timing regularity is the only signal."),
    ("BENIGN",        "WEB_ATTACK",
     "NFStream cannot see HTTP payload. Flow-level features are nearly identical."),
    ("WEB_ATTACK",    "BRUTE_FORCE",
     "Both HTTP on similar ports, similar flow patterns."),
]


def print_hard_pairs_warning():
    print("\n" + "="*70)
    print("  KNOWN DIFFICULT CLASS PAIRS (low expected separability)")
    print("="*70)
    for cls1, cls2, reason in KNOWN_HARD_PAIRS:
        print(f"  • {cls1} vs {cls2}")
        print(f"    → {reason}")
    print("="*70 + "\n")


def load_data(dataset_path: str):
    print(f"[ML] Loading: {dataset_path}")
    df = pd.read_csv(dataset_path, low_memory=False)
    print(f"[ML] Loaded {len(df):,} rows, {len(df.columns)} columns")

    if "split" not in df.columns:
        print("[ML] WARNING: 'split' column missing. Run merge_dataset.py first.")
        print("[ML] Falling back to random 70/15/15 split (NOT RECOMMENDED).")
        from sklearn.model_selection import train_test_split
        idx = df.index
        train_idx, temp_idx = train_test_split(idx, test_size=0.3, random_state=42,
                                               stratify=df["label"])
        val_idx, test_idx = train_test_split(temp_idx, test_size=0.5, random_state=42,
                                             stratify=df.loc[temp_idx, "label"])
        df["split"] = "train"
        df.loc[val_idx,  "split"] = "val"
        df.loc[test_idx, "split"] = "test"

    return df


def prepare_features(df: pd.DataFrame) -> tuple:
    """Drop non-feature columns and return (X_df, y, feature_names)."""
    y = df["label"].copy()

    drop_cols = [c for c in DROP_BEFORE_ML if c in df.columns]
    X = df.drop(columns=drop_cols)

    # Drop non-numeric
    non_numeric = X.select_dtypes(exclude=[np.number]).columns.tolist()
    if non_numeric:
        print(f"[ML] Dropping non-numeric columns: {non_numeric}")
        X = X.drop(columns=non_numeric)

    # Replace inf
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.fillna(0, inplace=True)

    # Drop constant features
    std = X.std()
    const_cols = std[std == 0].index.tolist()
    if const_cols:
        print(f"[ML] Dropping {len(const_cols)} constant features")
        X = X.drop(columns=const_cols)

    print(f"[ML] Feature matrix shape: {X.shape}")
    print(f"[ML] Features: {list(X.columns)[:10]} ...")
    return X, y, X.columns.tolist()


def print_class_dist(y_series, title: str):
    vc = y_series.value_counts().sort_index()
    print(f"\n  {title}:")
    for lbl, cnt in vc.items():
        print(f"    [{int(lbl)}] {LABEL_MAP.get(int(lbl),'?'):<16} {cnt:>8,}")


def train_and_evaluate(X_train, y_train, X_val, y_val, X_test, y_test,
                       feature_names: list, model_name: str, model,
                       use_smote: bool = False):
    from sklearn.metrics import (classification_report, confusion_matrix,
                                 f1_score, accuracy_score)

    print(f"\n{'='*60}")
    print(f"  Training: {model_name}")
    print(f"{'='*60}")

    # Optional SMOTE oversampling
    if use_smote:
        try:
            from imblearn.over_sampling import SMOTE
            min_samples = y_train.value_counts().min()
            k = min(5, min_samples - 1)
            if k >= 1:
                print(f"[ML] Applying SMOTE (k_neighbors={k})")
                sm = SMOTE(random_state=42, k_neighbors=k)
                X_train, y_train = sm.fit_resample(X_train, y_train)
                print(f"[ML] After SMOTE: {len(X_train):,} training samples")
        except ImportError:
            print("[ML] imblearn not installed. Skipping SMOTE.")

    # Train
    print(f"[ML] Fitting {model_name} ...")
    model.fit(X_train, y_train)

    # Feature importance
    if hasattr(model, "feature_importances_"):
        fi = pd.Series(model.feature_importances_, index=feature_names)
        top10 = fi.nlargest(10)
        print(f"\n  Top-10 feature importances ({model_name}):")
        for feat, imp in top10.items():
            bar = "▇" * int(imp * 100)
            print(f"    {feat:<50} {imp:.4f}  {bar}")

    # Evaluate on val set
    print(f"\n  --- Validation Set ---")
    y_val_pred = model.predict(X_val)
    _print_metrics(y_val, y_val_pred, "Validation")

    # Evaluate on test set
    print(f"\n  --- Test Set ---")
    y_test_pred = model.predict(X_test)
    _print_metrics(y_test, y_test_pred, "Test")

    # Confusion matrix
    cm = confusion_matrix(y_test, y_test_pred)
    _print_confusion_matrix(cm)

    # Save confusion matrix plot
    try:
        _save_confusion_matrix_plot(cm, model_name)
    except Exception as e:
        print(f"  [PLOT] Could not save confusion matrix: {e}")

    return model


def _print_metrics(y_true, y_pred, split_name: str):
    from sklearn.metrics import (f1_score, precision_score,
                                 recall_score, accuracy_score,
                                 classification_report)
    labels = sorted(set(y_true) | set(y_pred))
    target_names = [f"[{l}]{LABEL_MAP.get(l,'?')[:10]}" for l in labels]

    acc   = accuracy_score(y_true, y_pred)
    macro_f1 = f1_score(y_true, y_pred, average="macro", zero_division=0)
    wt_f1    = f1_score(y_true, y_pred, average="weighted", zero_division=0)

    print(f"  {split_name}  Accuracy={acc:.4f}  MacroF1={macro_f1:.4f}  WeightedF1={wt_f1:.4f}")
    print()
    print(classification_report(y_true, y_pred,
                                labels=labels,
                                target_names=target_names,
                                zero_division=0))

    # Per-class breakdown
    p_scores = precision_score(y_true, y_pred, labels=labels, average=None, zero_division=0)
    r_scores = recall_score(y_true, y_pred, labels=labels, average=None, zero_division=0)
    f_scores = f1_score(y_true, y_pred, labels=labels, average=None, zero_division=0)

    print(f"  {'CLASS':<16} {'PREC':>6} {'REC':>6} {'F1':>6} {'NOTE'}")
    print(f"  {'-'*55}")
    for lbl, p, r, f in zip(labels, p_scores, r_scores, f_scores):
        cls = LABEL_MAP.get(lbl, f"class_{lbl}")
        note = ""
        if f < 0.5:
            note = "← LOW F1 (possible overlap)"
        elif f < 0.7:
            note = "← MODERATE"
        print(f"  {cls:<16} {p:>6.3f} {r:>6.3f} {f:>6.3f}  {note}")

    print(f"\n  NOTE: Do not rely on accuracy alone. Use Macro-F1 ({macro_f1:.4f}).")


def _print_confusion_matrix(cm: np.ndarray):
    print("\n  Confusion Matrix (rows=actual, cols=predicted):")
    labels = list(range(cm.shape[0]))
    header = "       " + "  ".join(f"[{l}]" for l in labels)
    print(f"  {header}")
    for i, row in enumerate(cm):
        row_str = "  ".join(f"{v:4d}" for v in row)
        print(f"  [{i}]  {row_str}")


def _save_confusion_matrix_plot(cm: np.ndarray, model_name: str):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import seaborn as sns
    except ImportError:
        return

    ML_OUT.mkdir(parents=True, exist_ok=True)
    n = cm.shape[0]
    labels = [f"[{i}]\n{LABEL_MAP.get(i,'?')[:8]}" for i in range(n)]

    fig, ax = plt.subplots(figsize=(12, 10))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=labels, yticklabels=labels, ax=ax)
    ax.set_title(f"Confusion Matrix — {model_name}", fontsize=14)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    plt.tight_layout()

    out = ML_OUT / f"confusion_matrix_{model_name.lower().replace(' ','_')}.png"
    plt.savefig(out, dpi=150)
    plt.close()
    print(f"  [PLOT] Confusion matrix saved: {out}")


def main():
    parser = argparse.ArgumentParser(description="NIDS ML Training and Evaluation")
    parser.add_argument("--dataset",
                        default=str(FINAL_DIR / "nids_dataset_splits.csv"))
    parser.add_argument("--rf-only", action="store_true",
                        help="Train only Random Forest (skip XGBoost)")
    parser.add_argument("--no-balance", action="store_true",
                        help="Skip class_weight='balanced'")
    parser.add_argument("--smote", action="store_true",
                        help="Apply SMOTE oversampling (requires imbalanced-learn)")
    args = parser.parse_args()

    ML_OUT.mkdir(parents=True, exist_ok=True)
    print_hard_pairs_warning()

    # Load and split
    df = load_data(args.dataset)

    train_df = df[df["split"] == "train"]
    val_df   = df[df["split"] == "val"]
    test_df  = df[df["split"] == "test"]

    print_class_dist(train_df["label"], "Train")
    print_class_dist(val_df["label"],   "Val")
    print_class_dist(test_df["label"],  "Test")

    # Check for empty splits
    for name, split in [("Train", train_df), ("Val", val_df), ("Test", test_df)]:
        if split.empty:
            print(f"[ML] ERROR: {name} split is empty!")
            print("[ML] Run more experiments and re-run merge_dataset.py")
            sys.exit(1)

    # Prepare features
    X_train, y_train, feat_names = prepare_features(train_df)

    # Align val/test to same features
    X_val  = val_df[feat_names].replace([np.inf, -np.inf], np.nan).fillna(0)
    y_val  = val_df["label"]
    X_test = test_df[feat_names].replace([np.inf, -np.inf], np.nan).fillna(0)
    y_test = test_df["label"]

    # Scale features
    from sklearn.preprocessing import StandardScaler
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_val_s   = scaler.transform(X_val)
    X_test_s  = scaler.transform(X_test)

    cw = None if args.no_balance else "balanced"

    # ── Random Forest ─────────────────────────────────────────────────────────
    from sklearn.ensemble import RandomForestClassifier
    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        class_weight=cw,
        n_jobs=-1,
        random_state=42,
    )
    train_and_evaluate(X_train, y_train, X_val, y_val, X_test, y_test,
                       feat_names, "Random Forest", rf,
                       use_smote=args.smote)

    # ── XGBoost ───────────────────────────────────────────────────────────────
    if not args.rf_only:
        try:
            from xgboost import XGBClassifier
            # Map labels to 0-based for XGBoost
            unique_labels = sorted(y_train.unique())
            label_to_idx = {l: i for i, l in enumerate(unique_labels)}
            idx_to_label = {i: l for l, i in label_to_idx.items()}

            y_train_xgb = y_train.map(label_to_idx)
            y_val_xgb   = y_val.map(label_to_idx)
            y_test_xgb  = y_test.map(label_to_idx)

            xgb = XGBClassifier(
                n_estimators=300,
                max_depth=8,
                learning_rate=0.1,
                use_label_encoder=False,
                eval_metric="mlogloss",
                n_jobs=-1,
                random_state=42,
                verbosity=0,
            )
            xgb.fit(X_train_s, y_train_xgb,
                    eval_set=[(X_val_s, y_val_xgb)],
                    verbose=False)

            # Remap predictions back to original labels
            y_val_pred_xgb  = pd.Series(xgb.predict(X_val_s)).map(idx_to_label)
            y_test_pred_xgb = pd.Series(xgb.predict(X_test_s)).map(idx_to_label)

            print(f"\n{'='*60}")
            print("  Training: XGBoost")
            print(f"{'='*60}")
            print("\n  --- Validation Set ---")
            _print_metrics(y_val.values, y_val_pred_xgb.values, "Validation")
            print("\n  --- Test Set ---")
            _print_metrics(y_test.values, y_test_pred_xgb.values, "Test")
            cm_xgb = __import__("sklearn.metrics", fromlist=["confusion_matrix"]).confusion_matrix(
                y_test.values, y_test_pred_xgb.values)
            _print_confusion_matrix(cm_xgb)
            _save_confusion_matrix_plot(cm_xgb, "XGBoost")

        except ImportError:
            print("\n[ML] XGBoost not installed. Run: pip3 install xgboost")
            print("[ML] Skipping XGBoost evaluation.")

    print("\n" + "="*60)
    print("  Final Notes on Result Interpretation")
    print("="*60)
    print()
    print("  1. Macro-F1 is the primary metric for imbalanced multiclass NIDS.")
    print("  2. Do not over-interpret accuracy — a model can be 90%+ accurate")
    print("     by predicting BENIGN on an unbalanced dataset.")
    print("  3. Inspect the confusion matrix for systematic misclassifications.")
    print("  4. Classes with F1 < 0.5 likely have insufficient data OR")
    print("     inherently overlapping flow features with other classes.")
    print()
    print("  Known overlapping pairs in this single-laptop setup:")
    for cls1, cls2, reason in KNOWN_HARD_PAIRS:
        print(f"    • {cls1} ↔ {cls2}: {reason}")
    print()
    print("  If WEB_ATTACK or BRUTE_FORCE F1 is very low, this is EXPECTED.")
    print("  These classes require DPI or application-layer logs to separate.")
    print()
    print(f"  Results and plots saved to: {ML_OUT}")


if __name__ == "__main__":
    main()
