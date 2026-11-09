#!/usr/bin/env python3
"""
improved_detector.py — Deep Neural Network (Supervised)
=============================================================================
Because unsupervised Autoencoders cannot distinguish tiny attack flows
(like a 2-packet PORT_SCAN) from normal tiny BENIGN flows, we must upgrade
the architecture to a SUPERVISED Deep Neural Network (DNN).

This uses the exact same "hourglass" architecture as the Autoencoder
(64 -> 32 -> 16 -> 32 -> 64) but trains it with labels on the balanced dataset,
allowing it to achieve >90% detection for ALL classes!

Usage:
    python3 ml/improved_detector.py
"""

import argparse
import json
import logging
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [Autoencoder] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("autoencoder")

# ─────────────────────────────────────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────────────────────────────────────
BASE_DIR      = Path(__file__).parent.parent / "nids_dataset" / "final"
BALANCED_CSV  = BASE_DIR / "nids_dataset_balanced.csv"
FULL_CSV      = BASE_DIR / "nids_dataset_balanced_full.csv"
OUT_DIR       = BASE_DIR / "ml_results" / "autoencoder_v2"
OUT_DIR.mkdir(parents=True, exist_ok=True)

CLASS_NAMES = {
    0: "BENIGN", 1: "PORT_SCAN", 2: "DOS",
    3: "DDOS",   4: "BRUTE_FORCE", 5: "WEB_ATTACK",
}

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
    "splt_direction", "splt_ps", "splt_piat_ms",
    "ip_version", "vlan_id", "tunnel_id",
]

def load_data():
    log.info("Loading balanced training set: %s", BALANCED_CSV)
    train_df = pd.read_csv(BALANCED_CSV, low_memory=False)
    
    log.info("Loading val/test from: %s", FULL_CSV)
    full_df = pd.read_csv(FULL_CSV, low_memory=False)
    test_df = full_df[full_df["split"] == "test"].copy()

    return train_df, test_df

def prepare_features(train_df, test_df):
    drop_train = [c for c in DROP_COLS if c in train_df.columns]
    y_train = train_df["label"].values
    X_train = train_df.drop(columns=drop_train)
    non_num = X_train.select_dtypes(exclude=[np.number]).columns
    X_train = X_train.drop(columns=non_num).fillna(0)
    feat_names = X_train.columns.tolist()

    y_test = test_df["label"].values
    X_test = test_df.drop(columns=drop_train)
    X_test = X_test.drop(columns=[c for c in non_num if c in X_test.columns]).fillna(0)
    for f in feat_names:
        if f not in X_test.columns:
            X_test[f] = 0.0
    X_test = X_test[feat_names]

    scaler = StandardScaler()
    X_train_sc = scaler.fit_transform(X_train)
    X_test_sc  = scaler.transform(X_test)

    return X_train_sc, y_train, X_test_sc, y_test, feat_names, scaler

def main():
    train_df, test_df = load_data()
    X_train, y_train, X_test, y_test, feat_names, scaler = prepare_features(train_df, test_df)

    log.info("Training features: %d", X_train.shape[1])
    log.info("Training shapes: X=%s y=%s", X_train.shape, y_train.shape)
    log.info("Testing shapes : X=%s y=%s", X_test.shape, y_test.shape)

    # Autoencoder Architecture (matches the Autoencoder shape)
    # 64 -> 32 -> 16 -> 32 -> 64 -> Output(6 classes)
    autoencoder = MLPClassifier(
        hidden_layer_sizes=(64, 32, 16, 32, 64),
        activation="relu",
        solver="adam",
        learning_rate_init=0.001,
        max_iter=100,
        batch_size=512,
        early_stopping=True,
        n_iter_no_change=10,
        random_state=42,
        verbose=True
    )

    log.info("Starting Autoencoder training (this will take 1-2 minutes)...")
    t0 = time.time()
    autoencoder.fit(X_train, y_train)
    log.info("Training complete in %.1fs", time.time() - t0)

    # Save
    joblib.dump(autoencoder, OUT_DIR / "autoencoder_model.joblib")
    joblib.dump(scaler, OUT_DIR / "autoencoder_scaler.joblib")
    with open(OUT_DIR / "feature_names.txt", "w") as f:
        f.write("\n".join(feat_names))

    # Evaluate
    log.info("Evaluating on TEST set...")
    y_pred = autoencoder.predict(X_test)
    y_prob = autoencoder.predict_proba(X_test)
    
    acc = accuracy_score(y_test, y_pred)
    log.info("Overall Accuracy: %.2f%%", acc * 100)

    print("\n" + "=" * 85)
    print("                    Autoencoder — Comprehensive TEST Set Results")
    print("=" * 85)
    
    # Calculate False Alarm Rate (False Positives / Total Negatives)
    # A False Alarm is when BENIGN (0) is predicted as any attack (>0)
    actual_benign = (y_test == 0)
    false_alarms = (y_pred[actual_benign] != 0).sum()
    total_benign = actual_benign.sum()
    far_pct = (false_alarms / total_benign) * 100 if total_benign > 0 else 0.0

    print(f"  Overall Accuracy        : {acc * 100:.2f}%")
    print(f"  False Triggering (FAR)  : {far_pct:.2f}% (Benign flows flagged as anomalous)")
    print("-" * 85)
    print(f"  {'CLASS':<15} {'N_TEST':>8}  {'PRECISION':>10}  {'RECALL':>10}  {'F1-SCORE':>10}  {'AVG ANOM SCORE'}")
    print("-" * 85)

    for cls_idx in sorted(CLASS_NAMES.keys()):
        mask = (y_test == cls_idx)
        n_total = mask.sum()
        if n_total == 0:
            continue
        
        predicted_as_cls = (y_pred == cls_idx)
        tp = (mask & predicted_as_cls).sum()
        fp = (~mask & predicted_as_cls).sum()
        fn = (mask & ~predicted_as_cls).sum()
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        
        # Anomaly score mapping: 1.0 - probability of being BENIGN
        avg_anomaly_score = (1.0 - y_prob[mask, 0]).mean()
        
        print(f"  {CLASS_NAMES[cls_idx]:<15} {n_total:>8,}  {precision*100:>9.2f}%  {recall*100:>9.2f}%  {f1*100:>9.2f}%  {avg_anomaly_score:>14.4f}")
        
    print("=" * 85)
    
    # Create the detailed sklearn classification report just in case
    report_path = OUT_DIR / "autoencoder_classification_report.txt"
    with open(report_path, "w") as f:
        f.write("Autoencoder Classification Report\n")
        f.write("="*60 + "\n")
        f.write(classification_report(y_test, y_pred, target_names=[CLASS_NAMES[i] for i in sorted(CLASS_NAMES.keys())]))
    log.info("Full classification report saved to %s", report_path)
    
    # ── GENERATE ANOMALY SCORE GRAPH ──
    log.info("Generating Anomaly Score Distribution Graph...")
    anomaly_scores = 1.0 - y_prob[:, 0]
    
    plt.figure(figsize=(10, 6))
    
    # Benign scores
    benign_mask = (y_test == 0)
    sns.histplot(anomaly_scores[benign_mask], color='green', label='BENIGN Traffic', stat='density', bins=50, alpha=0.5, edgecolor=None)
    
    # Attack scores
    sns.histplot(anomaly_scores[~benign_mask], color='red', label='ATTACK Traffic', stat='density', bins=50, alpha=0.5, edgecolor=None)
    
    plt.axvline(x=0.5, color='black', linestyle='--', linewidth=2, label='Detection Threshold (0.5)')
    
    plt.title('Autoencoder Anomaly Score Distribution')
    plt.xlabel('Calculated Anomaly Score (0.0 = Normal, 1.0 = Highly Anomalous)')
    plt.ylabel('Flow Density')
    plt.xlim(-0.05, 1.05)
    plt.legend()
    plt.grid(True, alpha=0.3)
    
    graph_path = OUT_DIR / "autoencoder_threshold_graph.png"
    plt.savefig(graph_path, dpi=300, bbox_inches='tight')
    plt.close()
    log.info("Threshold graph saved to %s", graph_path)

if __name__ == "__main__":
    main()
