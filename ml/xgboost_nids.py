#!/home/mayank/Desktop/DATACOLLECTION/venv/bin/python
"""
xgboost_nids.py — XGBoost Multi-class NIDS Classifier
=======================================================
Full pipeline: load → preprocess → train → tune → evaluate → save

Usage:
    # Full run (recommended): use pre-balanced training set
    python3 ml/xgboost_nids.py

    # Use raw splits (no pre-balancing, uses scale_pos_weight internally)
    python3 ml/xgboost_nids.py --use-raw-splits

    # Skip hyperparameter tuning (fast mode)
    python3 ml/xgboost_nids.py --no-tune

    # Custom dataset path
    python3 ml/xgboost_nids.py --balanced nids_dataset/final/nids_dataset_balanced.csv \\
                                --full     nids_dataset/final/nids_dataset_balanced_full.csv

Outputs (all in nids_dataset/final/ml_results/xgboost/):
    model.json                  — Saved XGBoost model (load with XGBClassifier)
    scaler.joblib               — Fitted StandardScaler
    feature_names.txt           — Ordered feature list used for training
    label_map.json              — Label int → class name mapping
    metrics_val.json            — Full val metrics dict
    metrics_test.json           — Full test metrics dict
    classification_report.txt   — Human-readable per-class report
    confusion_matrix.png        — Annotated heatmap (test set)
    feature_importance.png      — Top-30 feature importances
    training_history.png        — Logloss learning curve (train vs val)
    hyperparameter_search.csv   — GridSearch results (if tuning enabled)
"""
import argparse
import json
import os
import sys
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")

# ─────────────────────────────────────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────────────────────────────────────
BASE_DIR      = Path(__file__).parent.parent / "nids_dataset" / "final"
BALANCED_CSV  = BASE_DIR / "nids_dataset_balanced.csv"
FULL_CSV      = BASE_DIR / "nids_dataset_balanced_full.csv"
ML_SPLITS_CSV = BASE_DIR / "nids_dataset_ml.csv"
OUT_DIR       = BASE_DIR / "ml_results" / "xgboost"

LABEL_MAP = {
    0: "BENIGN",      1: "PORT_SCAN",   2: "DOS",
    3: "DDOS",        4: "BRUTE_FORCE", 5: "WEB_ATTACK",
    # UDP_FLOOD, ICMP_FLOOD and NETWORK_RECON removed
}
CLASS_NAMES = [LABEL_MAP[i] for i in sorted(LABEL_MAP)]

# Columns to never use as ML features
DROP_COLS = [
    "label", "split", "id", "expiration_id",
    "src_ip", "dst_ip", "src_mac", "dst_mac", "src_oui", "dst_oui",
    "src_port", "dst_port", "protocol_name",
    "bidirectional_first_seen_ms", "bidirectional_last_seen_ms",
    "src2dst_first_seen_ms", "src2dst_last_seen_ms",
    "dst2src_first_seen_ms", "dst2src_last_seen_ms",
    "application_name", "application_category_name",
    "application_is_guessed", "application_confidence",
    "requested_server_name", "client_fingerprint",
    "server_fingerprint", "user_agent", "content_type",
    "experiment_id", "class_name", "pcap_file", "processed_at",
    "splt_direction", "splt_ps", "splt_piat_ms",   # raw string versions
    "ip_version", "vlan_id", "tunnel_id",           # zero-variance
]


# ─────────────────────────────────────────────────────────────────────────────
# Data loading
# ─────────────────────────────────────────────────────────────────────────────
def load_balanced(balanced_path: Path, full_path: Path):
    """
    Load pre-balanced training set + original val/test from the full file.
    """
    print(f"[DATA] Loading balanced training set: {balanced_path}")
    train_df = pd.read_csv(balanced_path, low_memory=False)
    print(f"[DATA] Training rows: {len(train_df):,} | Classes: {sorted(train_df['label'].unique())}")

    print(f"[DATA] Loading val/test from: {full_path}")
    full_df  = pd.read_csv(full_path, low_memory=False)
    val_df   = full_df[full_df["split"] == "val"].copy()
    test_df  = full_df[full_df["split"] == "test"].copy()
    print(f"[DATA] Val rows: {len(val_df):,} | Test rows: {len(test_df):,}")

    return train_df, val_df, test_df


def load_raw_splits(splits_path: Path):
    """Load from nids_dataset_ml.csv which has the 'split' column."""
    print(f"[DATA] Loading raw splits: {splits_path}")
    df      = pd.read_csv(splits_path, low_memory=False)
    train_df = df[df["split"] == "train"].copy()
    val_df   = df[df["split"] == "val"].copy()
    test_df  = df[df["split"] == "test"].copy()
    print(f"[DATA] Train: {len(train_df):,} | Val: {len(val_df):,} | Test: {len(test_df):,}")
    return train_df, val_df, test_df


def print_class_dist(y: pd.Series, name: str):
    vc = y.value_counts().sort_index()
    total = len(y)
    print(f"\n  [{name} class distribution]")
    print(f"  {'Class':<18} {'Label':>5} {'Count':>8} {'%':>7}")
    print(f"  {'-'*42}")
    for lbl, cnt in vc.items():
        cls = LABEL_MAP.get(int(lbl), f"cls_{lbl}")
        print(f"  {cls:<18} {int(lbl):>5} {cnt:>8,} {cnt/total*100:>6.2f}%")


# ─────────────────────────────────────────────────────────────────────────────
# Feature engineering
# ─────────────────────────────────────────────────────────────────────────────
def prepare_features(train_df, val_df, test_df):
    """
    Drop non-feature columns, drop constant/all-NaN features,
    align val/test to training feature set, apply StandardScaler.
    Returns: X_train, y_train, X_val, y_val, X_test, y_test, feature_names, scaler
    """
    from sklearn.preprocessing import StandardScaler

    def extract_X_y(df):
        y = df["label"].astype(int)
        drop = [c for c in DROP_COLS if c in df.columns]
        X = df.drop(columns=drop)
        # Drop remaining non-numeric
        non_num = X.select_dtypes(exclude=[np.number]).columns.tolist()
        if non_num:
            print(f"[FEAT] Dropping non-numeric: {non_num}")
            X = X.drop(columns=non_num)
        X = X.replace([np.inf, -np.inf], np.nan).fillna(0.0)
        return X, y

    X_train, y_train = extract_X_y(train_df)
    X_val,   y_val   = extract_X_y(val_df)
    X_test,  y_test  = extract_X_y(test_df)

    # Drop zero-variance features (measured on training set)
    std = X_train.std()
    const_cols = std[std == 0].index.tolist()
    if const_cols:
        print(f"[FEAT] Dropping {len(const_cols)} zero-variance features: {const_cols}")
        X_train = X_train.drop(columns=const_cols)

    # Align val/test to training features (add missing as 0, drop extras)
    feat_names = X_train.columns.tolist()
    for col in feat_names:
        if col not in X_val.columns:
            X_val[col] = 0.0
        if col not in X_test.columns:
            X_test[col] = 0.0
    X_val  = X_val[feat_names]
    X_test = X_test[feat_names]

    print(f"\n[FEAT] Final feature count: {len(feat_names)}")
    print(f"[FEAT] Train shape : {X_train.shape}")
    print(f"[FEAT] Val   shape : {X_val.shape}")
    print(f"[FEAT] Test  shape : {X_test.shape}")

    # Scale
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_val_s   = scaler.transform(X_val)
    X_test_s  = scaler.transform(X_test)

    return (X_train_s, y_train,
            X_val_s,   y_val,
            X_test_s,  y_test,
            feat_names, scaler)


# ─────────────────────────────────────────────────────────────────────────────
# XGBoost training
# ─────────────────────────────────────────────────────────────────────────────
def build_default_xgb(n_classes: int):
    """Return a well-configured XGBClassifier for multiclass NIDS."""
    from xgboost import XGBClassifier
    return XGBClassifier(
        objective="multi:softprob",
        num_class=n_classes,
        n_estimators=500,          # high, rely on early stopping
        max_depth=8,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        min_child_weight=5,
        gamma=0.1,
        reg_alpha=0.1,             # L1
        reg_lambda=1.0,            # L2
        eval_metric="mlogloss",
        use_label_encoder=False,
        n_jobs=-1,
        random_state=42,
        verbosity=0,
        tree_method="hist",        # fast histogram method
    )


def remap_labels(y_train, y_val, y_test):
    """Map original labels (0-8) to contiguous 0-based indices for XGBoost."""
    unique_labels = sorted(y_train.unique())
    l2i = {l: i for i, l in enumerate(unique_labels)}   # label → idx
    i2l = {i: l for l, i in l2i.items()}                # idx → label
    return (
        y_train.map(l2i).values,
        y_val.map(l2i).values,
        y_test.map(l2i).values,
        l2i, i2l, unique_labels,
    )


def tune_xgboost(X_train, y_train, X_val, y_val, n_classes: int):
    """
    Lightweight grid search over the most impactful hyperparameters.
    Evaluates on val set (NOT test — prevents leakage).
    """
    from xgboost import XGBClassifier
    from sklearn.metrics import f1_score
    import itertools

    print("\n[TUNE] Starting hyperparameter search (val-set macro-F1)...")

    param_grid = {
        "max_depth":        [6, 8, 10],
        "learning_rate":    [0.03, 0.05, 0.1],
        "subsample":        [0.8, 0.9],
        "colsample_bytree": [0.8, 0.9],
    }

    keys   = list(param_grid.keys())
    values = list(param_grid.values())
    combos = list(itertools.product(*values))
    print(f"[TUNE] Evaluating {len(combos)} configurations...")

    results = []
    best_f1  = -1
    best_cfg = {}

    for i, combo in enumerate(combos, 1):
        cfg = dict(zip(keys, combo))
        model = XGBClassifier(
            objective="multi:softprob",
            num_class=n_classes,
            n_estimators=300,
            eval_metric="mlogloss",
            use_label_encoder=False,
            n_jobs=-1,
            random_state=42,
            verbosity=0,
            tree_method="hist",
            **cfg,
        )
        model.fit(
            X_train, y_train,
            eval_set=[(X_val, y_val)],
            verbose=False,
        )
        preds = model.predict(X_val)
        macro_f1 = f1_score(y_val, preds, average="macro", zero_division=0)
        results.append({**cfg, "macro_f1": macro_f1, "n_estimators": 300})
        print(f"  [{i:>2}/{len(combos)}] {cfg}  →  macro_f1={macro_f1:.4f}")

        if macro_f1 > best_f1:
            best_f1  = macro_f1
            best_cfg = cfg

    results_df = pd.DataFrame(results).sort_values("macro_f1", ascending=False)
    results_df.to_csv(OUT_DIR / "hyperparameter_search.csv", index=False)
    print(f"\n[TUNE] Best config: {best_cfg}  (macro_f1={best_f1:.4f})")
    return best_cfg


def train_xgboost(X_train, y_train, X_val, y_val, n_classes: int, best_cfg: dict):
    """Train final XGBoost model with early stopping on val logloss."""
    from xgboost import XGBClassifier

    print("\n[TRAIN] Fitting final XGBoost model with early stopping...")
    model = XGBClassifier(
        objective="multi:softprob",
        num_class=n_classes,
        n_estimators=1000,
        eval_metric="mlogloss",
        use_label_encoder=False,
        n_jobs=-1,
        random_state=42,
        verbosity=0,
        tree_method="hist",
        early_stopping_rounds=30,
        **best_cfg,
    )
    model.fit(
        X_train, y_train,
        eval_set=[(X_train, y_train), (X_val, y_val)],
        verbose=50,
    )
    best_iter = model.best_iteration
    print(f"[TRAIN] Best iteration: {best_iter}  |  Best val logloss: {model.best_score:.4f}")
    return model


# ─────────────────────────────────────────────────────────────────────────────
# Per-class threshold optimization
# ─────────────────────────────────────────────────────────────────────────────
def optimize_thresholds(model, X_val, y_val_remapped, y_val_orig, i2l,
                        target_classes_orig=None):
    """
    Find per-class probability thresholds that maximize F1 on the val set.
    Only tunes thresholds for target_classes_orig (by original label int);
    all others remain at 0.5.
    Returns: dict {class_idx: threshold}
    """
    from sklearn.metrics import f1_score

    proba = model.predict_proba(X_val)         # shape (N, n_classes)
    n_classes = proba.shape[1]

    # Default: argmax (equivalent to threshold=0 on max prob)
    # Map original labels → remapped indices for val set
    unique_orig = sorted(set(y_val_orig))
    l2i = {l: i for i, l in enumerate(unique_orig)}  # orig → remapped

    if target_classes_orig is None:
        target_classes_orig = unique_orig

    best_thresholds = {}   # remapped_idx → threshold

    print("\n[THRESH] Optimizing per-class probability thresholds on val set...")
    for orig_label in target_classes_orig:
        if orig_label not in l2i:
            continue
        remapped_idx = l2i[orig_label]
        cls_name = LABEL_MAP.get(int(orig_label), f"cls_{orig_label}")

        best_f1 = -1
        best_thr = 0.5
        for thr in np.arange(0.05, 0.99, 0.01):
            # Predict: class c if proba[:,c] >= thr, else take argmax of remaining
            preds_remapped = np.argmax(proba, axis=1).copy()
            # Override: assign class only if its prob >= thr, else use second-best
            class_proba = proba[:, remapped_idx]
            # Rows where argmax gave this class but prob < thr → reassign
            override_mask = (preds_remapped == remapped_idx) & (class_proba < thr)
            if override_mask.any():
                # For those rows, pick the next-best class
                alt_proba = proba.copy()
                alt_proba[:, remapped_idx] = 0
                alt_preds = np.argmax(alt_proba, axis=1)
                preds_remapped[override_mask] = alt_preds[override_mask]

            preds_orig = np.array([i2l[i] for i in preds_remapped])
            f1 = f1_score(y_val_orig, preds_orig,
                          labels=[orig_label], average="macro", zero_division=0)
            if f1 > best_f1:
                best_f1 = f1
                best_thr = thr

        best_thresholds[remapped_idx] = best_thr
        print(f"  {cls_name:<16}  threshold={best_thr:.2f}  val_f1={best_f1:.4f}")

    return best_thresholds


def predict_with_thresholds(model, X, i2l, thresholds: dict):
    """
    Generate predictions applying per-class probability thresholds.
    For each row, if the argmax class has prob < threshold, use next-best class.
    """
    proba = model.predict_proba(X)
    preds_remapped = np.argmax(proba, axis=1).copy()

    for remapped_idx, thr in thresholds.items():
        class_proba = proba[:, remapped_idx]
        override_mask = (preds_remapped == remapped_idx) & (class_proba < thr)
        if override_mask.any():
            alt_proba = proba.copy()
            alt_proba[:, remapped_idx] = 0
            alt_preds = np.argmax(alt_proba, axis=1)
            preds_remapped[override_mask] = alt_preds[override_mask]

    return np.array([i2l[i] for i in preds_remapped])


# ─────────────────────────────────────────────────────────────────────────────
# Evaluation
# ─────────────────────────────────────────────────────────────────────────────
def evaluate(model, X, y_true_remapped, y_true_orig, i2l, split_name: str,
             thresholds: dict = None):
    """Predict and compute all metrics. Returns metrics dict."""
    from sklearn.metrics import (
        classification_report, confusion_matrix,
        f1_score, precision_score, recall_score, accuracy_score,
    )

    preds_idx = model.predict(X)
    if thresholds:
        preds     = predict_with_thresholds(model, X, i2l, thresholds)
    else:
        preds     = np.array([i2l[i] for i in preds_idx])

    labels_orig = sorted(set(y_true_orig) | set(preds))
    target_names = [f"{LABEL_MAP.get(l, f'cls_{l}')}" for l in labels_orig]

    acc      = accuracy_score(y_true_orig, preds)
    macro_f1 = f1_score(y_true_orig, preds, average="macro",    zero_division=0)
    wt_f1    = f1_score(y_true_orig, preds, average="weighted", zero_division=0)
    p_scores = precision_score(y_true_orig, preds, labels=labels_orig, average=None, zero_division=0)
    r_scores = recall_score(   y_true_orig, preds, labels=labels_orig, average=None, zero_division=0)
    f_scores = f1_score(       y_true_orig, preds, labels=labels_orig, average=None, zero_division=0)
    
    # Calculate MAE and Max Absolute Error (treating labels as ordinals/integers)
    from sklearn.metrics import mean_absolute_error, max_error
    mae = mean_absolute_error(y_true_orig, preds)
    mx_err = max_error(y_true_orig, preds)

    print(f"\n{'─'*65}")
    print(f"  {split_name} Results")
    print(f"{'─'*65}")
    print(f"  Accuracy   : {acc:.4f}")
    print(f"  Macro F1   : {macro_f1:.4f}   ← primary metric")
    print(f"  Weighted F1: {wt_f1:.4f}")
    print(f"  MAE        : {mae:.4f}")
    print(f"  Max Error  : {mx_err:.4f}")
    print()
    print(f"  {'CLASS':<16} {'PREC':>6} {'REC':>6} {'F1':>6}  NOTE")
    print(f"  {'-'*55}")
    for lbl, p, r, f in zip(labels_orig, p_scores, r_scores, f_scores):
        cls  = LABEL_MAP.get(int(lbl), f"cls_{lbl}")
        note = ""
        if f < 0.5:  note = "⚠ LOW"
        elif f < 0.8: note = "~ OK"
        else:         note = "✓ GOOD"
        print(f"  {cls:<16} {p:>6.3f} {r:>6.3f} {f:>6.3f}  {note}")

    report_str = classification_report(
        y_true_orig, preds,
        labels=labels_orig,
        target_names=target_names,
        zero_division=0,
    )
    cm = confusion_matrix(y_true_orig, preds, labels=labels_orig)

    metrics = {
        "accuracy":   float(acc),
        "macro_f1":   float(macro_f1),
        "weighted_f1": float(wt_f1),
        "mae": float(mae),
        "max_error": float(mx_err),
        "per_class": {
            LABEL_MAP.get(int(l), f"cls_{l}"): {
                "precision": float(p),
                "recall":    float(r),
                "f1":        float(f),
            }
            for l, p, r, f in zip(labels_orig, p_scores, r_scores, f_scores)
        },
        "classification_report": report_str,
        "confusion_matrix": cm.tolist(),
    }
    return metrics, preds, cm


# ─────────────────────────────────────────────────────────────────────────────
# Plots
# ─────────────────────────────────────────────────────────────────────────────
def plot_confusion_matrix(cm: np.ndarray, labels, out_path: Path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import seaborn as sns

    short = [LABEL_MAP.get(l, f"cls_{l}") for l in labels]
    fig, ax = plt.subplots(figsize=(13, 11))
    sns.heatmap(
        cm, annot=True, fmt="d", cmap="Blues",
        xticklabels=short, yticklabels=short,
        linewidths=0.5, linecolor="grey",
        ax=ax,
    )
    ax.set_title("XGBoost — Confusion Matrix (Test Set)", fontsize=15, pad=15)
    ax.set_xlabel("Predicted Class", fontsize=12)
    ax.set_ylabel("True Class",      fontsize=12)
    plt.xticks(rotation=35, ha="right", fontsize=9)
    plt.yticks(rotation=0,  fontsize=9)
    plt.tight_layout()
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[PLOT] Confusion matrix saved: {out_path}")


def plot_feature_importance(model, feature_names: list, out_path: Path, top_n: int = 30):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fi = pd.Series(model.feature_importances_, index=feature_names)
    top = fi.nlargest(top_n).sort_values()

    fig, ax = plt.subplots(figsize=(10, 12))
    colors = ["#2980b9" if "splt" not in f else "#e74c3c" for f in top.index]
    top.plot(kind="barh", ax=ax, color=colors, edgecolor="white")
    ax.set_title(f"XGBoost — Top {top_n} Feature Importances", fontsize=14, pad=12)
    ax.set_xlabel("Importance (F score)", fontsize=11)
    ax.tick_params(axis="y", labelsize=9)
    ax.grid(axis="x", alpha=0.3)

    # Legend
    from matplotlib.patches import Patch
    legend_els = [
        Patch(facecolor="#2980b9", label="Flow features"),
        Patch(facecolor="#e74c3c", label="SPLT features"),
    ]
    ax.legend(handles=legend_els, fontsize=9)

    plt.tight_layout()
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[PLOT] Feature importance saved: {out_path}")


def plot_training_history(model, out_path: Path):
    """Plot train vs val logloss learning curve."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    evals = model.evals_result()
    # Keys depend on eval_set order: 0=train, 1=val
    keys = list(evals.keys())
    if len(keys) < 2:
        return

    train_loss = evals[keys[0]]["mlogloss"]
    val_loss   = evals[keys[1]]["mlogloss"]
    epochs     = range(1, len(train_loss) + 1)

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.plot(epochs, train_loss, label="Train logloss",      color="#2980b9", linewidth=1.5)
    ax.plot(epochs, val_loss,   label="Validation logloss", color="#e74c3c", linewidth=1.5)

    best_iter = model.best_iteration
    ax.axvline(x=best_iter + 1, color="green", linestyle="--",
               label=f"Best iteration ({best_iter + 1})", linewidth=1.2)

    ax.set_title("XGBoost — Learning Curve (Log Loss)", fontsize=14)
    ax.set_xlabel("Boosting Round")
    ax.set_ylabel("Multiclass Log Loss")
    ax.legend()
    ax.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()
    print(f"[PLOT] Learning curve saved: {out_path}")


def plot_per_class_f1(metrics_val: dict, metrics_test: dict, out_path: Path):
    """Bar chart comparing val vs test F1 per class."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    classes = list(metrics_test["per_class"].keys())
    val_f1  = [metrics_val["per_class"][c]["f1"]  for c in classes]
    test_f1 = [metrics_test["per_class"][c]["f1"] for c in classes]

    x = np.arange(len(classes))
    width = 0.35

    fig, ax = plt.subplots(figsize=(14, 6))
    bars1 = ax.bar(x - width/2, val_f1,  width, label="Val F1",  color="#3498db", alpha=0.85)
    bars2 = ax.bar(x + width/2, test_f1, width, label="Test F1", color="#e74c3c", alpha=0.85)

    ax.set_xticks(x)
    ax.set_xticklabels(classes, rotation=30, ha="right", fontsize=10)
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("F1 Score")
    ax.set_title("XGBoost NIDS — Per-Class F1 (Val vs Test)", fontsize=14)
    ax.axhline(y=0.8, color="green",  linestyle="--", alpha=0.5, label="F1 = 0.80")
    ax.axhline(y=0.5, color="orange", linestyle="--", alpha=0.5, label="F1 = 0.50")
    ax.legend(fontsize=10)
    ax.grid(axis="y", alpha=0.3)

    # Annotate bars
    for bar in bars1:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2, h + 0.01, f"{h:.2f}",
                ha="center", va="bottom", fontsize=7.5)
    for bar in bars2:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2, h + 0.01, f"{h:.2f}",
                ha="center", va="bottom", fontsize=7.5)

    plt.tight_layout()
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[PLOT] Per-class F1 chart saved: {out_path}")


# ─────────────────────────────────────────────────────────────────────────────
# Save artefacts
# ─────────────────────────────────────────────────────────────────────────────
def save_artifacts(model, scaler, feature_names, l2i, i2l,
                   metrics_val, metrics_test, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)

    # Model
    model_path = out_dir / "model.json"
    model.save_model(str(model_path))
    print(f"[SAVE] Model saved: {model_path}")

    # Scaler
    scaler_path = out_dir / "scaler.joblib"
    joblib.dump(scaler, scaler_path)
    print(f"[SAVE] Scaler saved: {scaler_path}")

    # Feature names
    feat_path = out_dir / "feature_names.txt"
    feat_path.write_text("\n".join(feature_names))
    print(f"[SAVE] Feature names saved: {feat_path}")

    # Label map
    lmap_path = out_dir / "label_map.json"
    lmap_path.write_text(json.dumps({str(k): v for k, v in LABEL_MAP.items()}, indent=2))
    print(f"[SAVE] Label map saved: {lmap_path}")

    # Metrics JSON
    (out_dir / "metrics_val.json").write_text(
        json.dumps({k: v for k, v in metrics_val.items()
                    if k != "classification_report" and k != "confusion_matrix"}, indent=2)
    )
    (out_dir / "metrics_test.json").write_text(
        json.dumps({k: v for k, v in metrics_test.items()
                    if k != "classification_report" and k != "confusion_matrix"}, indent=2)
    )

    # Human-readable report
    report_path = out_dir / "classification_report.txt"
    report_path.write_text(
        "=== VALIDATION ===\n" + metrics_val["classification_report"] +
        "\n\n=== TEST ===\n"   + metrics_test["classification_report"]
    )
    print(f"[SAVE] Classification report saved: {report_path}")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="XGBoost NIDS Classifier")
    parser.add_argument("--balanced",       default=str(BALANCED_CSV),
                        help="Balanced training CSV")
    parser.add_argument("--full",           default=str(FULL_CSV),
                        help="Full CSV with val/test splits")
    parser.add_argument("--use-raw-splits", action="store_true",
                        help="Use raw splits instead of balanced set")
    parser.add_argument("--no-tune",        action="store_true",
                        help="Skip hyperparameter grid search")
    args = parser.parse_args()

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    print("\n" + "=" * 65)
    print("  XGBoost NIDS Classifier — Network Intrusion Detection")
    print("=" * 65)

    # ── Load data ────────────────────────────────────────────────────────────
    if args.use_raw_splits:
        train_df, val_df, test_df = load_raw_splits(Path(args.full))
    else:
        if not Path(args.balanced).exists():
            print(f"[ERR] Balanced CSV not found: {args.balanced}")
            print("[ERR] Run: python3 process/balance_dataset.py")
            sys.exit(1)
        train_df, val_df, test_df = load_balanced(
            Path(args.balanced), Path(args.full)
        )

    print_class_dist(train_df["label"], "Train")
    print_class_dist(val_df["label"],   "Val")
    print_class_dist(test_df["label"],  "Test")

    # ── Prepare features ─────────────────────────────────────────────────────
    print("\n[FEAT] Preparing features...")
    (X_train, y_train,
     X_val,   y_val,
     X_test,  y_test,
     feat_names, scaler) = prepare_features(train_df, val_df, test_df)

    # ── Remap labels to 0-based for XGBoost ──────────────────────────────────
    y_train_r, y_val_r, y_test_r, l2i, i2l, unique_labels = remap_labels(
        y_train, y_val, y_test
    )
    n_classes = len(unique_labels)
    print(f"\n[LABEL] {n_classes} classes: {[LABEL_MAP.get(l, l) for l in unique_labels]}")

    # ── Hyperparameter tuning ─────────────────────────────────────────────────
    if args.no_tune:
        print("\n[TUNE] Skipping grid search (--no-tune). Using defaults.")
        best_cfg = {
            "max_depth": 8, "learning_rate": 0.05,
            "subsample": 0.8, "colsample_bytree": 0.8,
        }
    else:
        best_cfg = tune_xgboost(X_train, y_train_r, X_val, y_val_r, n_classes)

    # ── Train final model with early stopping ─────────────────────────────────
    model = train_xgboost(X_train, y_train_r, X_val, y_val_r, n_classes, best_cfg)

    # ── Evaluate ──────────────────────────────────────────────────────────────
    print("\n[EVAL] Evaluating on Validation set (default thresholds)...")
    metrics_val, _, _ = evaluate(
        model, X_val, y_val_r, y_val.values, i2l, "Validation"
    )

    # ── Threshold optimization on val set (only for weak classes) ─────────────
    # Find which classes have F1 < 0.95 and tune their thresholds
    weak_classes = [
        orig_lbl for orig_lbl in sorted(set(y_val.values))
        if metrics_val["per_class"].get(
            LABEL_MAP.get(int(orig_lbl), f"cls_{orig_lbl}"), {}).get("f1", 1.0) < 0.95
    ]
    thresholds = {}
    if weak_classes:
        print(f"\n[THRESH] Weak classes (F1<0.95): "
              f"{[LABEL_MAP.get(int(c)) for c in weak_classes]}")
        thresholds = optimize_thresholds(
            model, X_val, y_val_r, y_val.values, i2l,
            target_classes_orig=weak_classes
        )
        # Save thresholds
        import json as _json
        (OUT_DIR / "class_thresholds.json").write_text(
            _json.dumps({str(k): float(v) for k, v in thresholds.items()}, indent=2)
        )
        print("\n[EVAL] Re-evaluating Validation with optimized thresholds...")
        metrics_val, _, _ = evaluate(
            model, X_val, y_val_r, y_val.values, i2l, "Validation (tuned)",
            thresholds=thresholds
        )

    print("\n[EVAL] Evaluating on Test set...")
    metrics_test, preds_test, cm_test = evaluate(
        model, X_test, y_test_r, y_test.values, i2l, "Test",
        thresholds=thresholds
    )

    # ── Save artefacts ────────────────────────────────────────────────────────
    print("\n[SAVE] Saving artefacts...")
    save_artifacts(model, scaler, feat_names, l2i, i2l,
                   metrics_val, metrics_test, OUT_DIR)

    # ── Plots ─────────────────────────────────────────────────────────────────
    print("\n[PLOT] Generating plots...")
    try:
        plot_confusion_matrix(
            cm_test,
            labels=sorted(set(y_test.values)),
            out_path=OUT_DIR / "confusion_matrix.png",
        )
        plot_feature_importance(
            model, feat_names,
            out_path=OUT_DIR / "feature_importance.png",
        )
        plot_training_history(
            model,
            out_path=OUT_DIR / "training_history.png",
        )
        plot_per_class_f1(
            metrics_val, metrics_test,
            out_path=OUT_DIR / "per_class_f1.png",
        )
    except Exception as e:
        print(f"[PLOT] Error generating plots: {e}")

    # ── Final summary ─────────────────────────────────────────────────────────
    print("\n" + "=" * 65)
    print("  FINAL RESULTS — XGBoost NIDS Classifier")
    print("=" * 65)
    print(f"  Val  Accuracy  : {metrics_val['accuracy']:.4f}")
    print(f"  Val  Macro F1  : {metrics_val['macro_f1']:.4f}")
    print(f"  Test Accuracy  : {metrics_test['accuracy']:.4f}")
    print(f"  Test Macro F1  : {metrics_test['macro_f1']:.4f}  ← primary metric")
    print(f"\n  Best XGBoost config: {best_cfg}")
    print(f"  Best iteration: {model.best_iteration}")
    print(f"  Feature count : {len(feat_names)}")
    print(f"\n  Output directory: {OUT_DIR}")
    print(f"    ├── model.json")
    print(f"    ├── scaler.joblib")
    print(f"    ├── feature_names.txt")
    print(f"    ├── label_map.json")
    print(f"    ├── metrics_val.json / metrics_test.json")
    print(f"    ├── classification_report.txt")
    print(f"    ├── confusion_matrix.png")
    print(f"    ├── feature_importance.png")
    print(f"    ├── training_history.png")
    print(f"    ├── per_class_f1.png")
    print(f"    └── hyperparameter_search.csv  (if tuning ran)")
    print("=" * 65)

    # Inference example
    print("""
  ─── How to load and use this model ─────────────────────────────────
  from xgboost import XGBClassifier
  import joblib, json, numpy as np, pandas as pd

  model  = XGBClassifier(); model.load_model("ml_results/xgboost/model.json")
  scaler = joblib.load("ml_results/xgboost/scaler.joblib")
  feats  = open("ml_results/xgboost/feature_names.txt").read().splitlines()
  lmap   = json.load(open("ml_results/xgboost/label_map.json"))

  X_new = pd.DataFrame([your_flow_dict])[feats].fillna(0)
  X_scaled = scaler.transform(X_new)
  pred_idx = model.predict(X_scaled)[0]
  print("Predicted class:", lmap[str(pred_idx)])
  ─────────────────────────────────────────────────────────────────────
""")


if __name__ == "__main__":
    main()
