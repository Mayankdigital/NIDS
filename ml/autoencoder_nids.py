#!/usr/bin/env python3
"""
autoencoder_nids.py — Anomaly Detector via Autoencoder (NumPy only)
====================================================================
Trains an autoencoder exclusively on BENIGN network flow data.
At inference, flows with high reconstruction error are anomalies.

Architecture:
    Encoder: 80 → 64 → 32 → 16  (bottleneck)
    Decoder: 16 → 32 → 64 → 80  (reconstruction)

No PyTorch/TensorFlow required — pure NumPy + joblib.

Usage:
    # Train the autoencoder:
    python3 ml/autoencoder_nids.py --train

    # Evaluate on a labeled CSV (optional):
    python3 ml/autoencoder_nids.py --eval

    # Score a single PCAP for anomalies:
    python3 ml/autoencoder_nids.py --pcap <file.pcap>
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
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [AE] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("autoencoder")

# ─────────────────────────────────────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).parent.parent
PROC_DIR    = BASE_DIR / "nids_dataset" / "processed"
FINAL_DIR   = BASE_DIR / "nids_dataset" / "final"
ML_DIR      = FINAL_DIR / "ml_results"
AE_DIR      = ML_DIR / "autoencoder"
AE_DIR.mkdir(parents=True, exist_ok=True)

XGB_DIR     = ML_DIR / "xgboost"   # reuse XGBoost feature names

# ─────────────────────────────────────────────────────────────────────────────
# Hyperparameters
# ─────────────────────────────────────────────────────────────────────────────
LAYER_DIMS  = [64, 32, 16]   # encoder dims; decoder mirrors this
LEARNING_RATE = 0.001
EPOCHS      = 150
BATCH_SIZE  = 512
RANDOM_SEED = 42
THRESHOLD_PERCENTILE = 99    # anomaly threshold at 99th percentile of benign MSE
VAL_SPLIT   = 0.15

np.random.seed(RANDOM_SEED)


# ─────────────────────────────────────────────────────────────────────────────
# Activation functions
# ─────────────────────────────────────────────────────────────────────────────
def relu(x: np.ndarray) -> np.ndarray:
    return np.maximum(0, x)

def relu_grad(x: np.ndarray) -> np.ndarray:
    return (x > 0).astype(float)

def sigmoid(x: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-np.clip(x, -500, 500)))


# ─────────────────────────────────────────────────────────────────────────────
# Autoencoder — pure NumPy implementation
# ─────────────────────────────────────────────────────────────────────────────
class Autoencoder:
    """
    Symmetric autoencoder using ReLU activations, trained with MSE loss
    and Adam optimiser.
    """

    def __init__(self, input_dim: int, layer_dims: list):
        self.input_dim = input_dim
        # Build layer sizes: encoder + decoder (mirror)
        enc_dims = [input_dim] + layer_dims
        dec_dims = list(reversed(layer_dims)) + [input_dim]
        all_dims = enc_dims + dec_dims   # full network dimensions

        # Initialise weights with He initialisation
        self.weights = []
        self.biases  = []
        for i in range(len(all_dims) - 1):
            fan_in  = all_dims[i]
            fan_out = all_dims[i + 1]
            scale   = np.sqrt(2.0 / fan_in)
            W = np.random.randn(fan_in, fan_out) * scale
            b = np.zeros(fan_out)
            self.weights.append(W)
            self.biases.append(b)

        # Adam optimiser moment estimates
        self._init_adam()

    def _init_adam(self):
        self.m_w = [np.zeros_like(w) for w in self.weights]
        self.v_w = [np.zeros_like(w) for w in self.weights]
        self.m_b = [np.zeros_like(b) for b in self.biases]
        self.v_b = [np.zeros_like(b) for b in self.biases]
        self.t   = 0

    def forward(self, X: np.ndarray) -> tuple:
        """Forward pass. Returns (output, list of pre-activations, list of activations)."""
        activations = [X]
        pre_acts    = []
        for i, (W, b) in enumerate(zip(self.weights, self.biases)):
            z = activations[-1] @ W + b
            pre_acts.append(z)
            # Last layer: linear (no activation) for reconstruction
            if i == len(self.weights) - 1:
                a = z
            else:
                a = relu(z)
            activations.append(a)
        return activations[-1], pre_acts, activations

    def mse(self, X: np.ndarray, X_hat: np.ndarray) -> float:
        return float(np.mean((X - X_hat) ** 2))

    def per_sample_mse(self, X: np.ndarray, X_hat: np.ndarray) -> np.ndarray:
        """Per-sample reconstruction error (shape: N,)."""
        return np.mean((X - X_hat) ** 2, axis=1)

    def backward(self, X: np.ndarray, pre_acts: list, activations: list) -> tuple:
        """Backpropagation. Returns (grad_weights, grad_biases)."""
        X_hat = activations[-1]
        n     = X.shape[0]

        # Output gradient (MSE)
        delta = (X_hat - X) * (2.0 / n)

        grad_W = []
        grad_b = []
        for i in reversed(range(len(self.weights))):
            a_prev = activations[i]
            gW = a_prev.T @ delta
            gb = delta.sum(axis=0)
            grad_W.insert(0, gW)
            grad_b.insert(0, gb)
            if i > 0:
                delta = (delta @ self.weights[i].T) * relu_grad(pre_acts[i - 1])

        return grad_W, grad_b

    def adam_update(self, grad_W: list, grad_b: list, lr: float,
                    beta1=0.9, beta2=0.999, eps=1e-8):
        self.t += 1
        for i in range(len(self.weights)):
            # Weights
            self.m_w[i] = beta1 * self.m_w[i] + (1 - beta1) * grad_W[i]
            self.v_w[i] = beta2 * self.v_w[i] + (1 - beta2) * (grad_W[i] ** 2)
            m_hat = self.m_w[i] / (1 - beta1 ** self.t)
            v_hat = self.v_w[i] / (1 - beta2 ** self.t)
            self.weights[i] -= lr * m_hat / (np.sqrt(v_hat) + eps)
            # Biases
            self.m_b[i] = beta1 * self.m_b[i] + (1 - beta1) * grad_b[i]
            self.v_b[i] = beta2 * self.v_b[i] + (1 - beta2) * (grad_b[i] ** 2)
            m_hat_b = self.m_b[i] / (1 - beta1 ** self.t)
            v_hat_b = self.v_b[i] / (1 - beta2 ** self.t)
            self.biases[i] -= lr * m_hat_b / (np.sqrt(v_hat_b) + eps)

    def fit(self, X_train: np.ndarray, X_val: np.ndarray,
            epochs: int, batch_size: int, lr: float) -> dict:
        history = {"train_mse": [], "val_mse": []}
        n = X_train.shape[0]
        best_val_mse = np.inf
        best_weights = None
        best_biases  = None
        patience     = 15
        no_improve   = 0

        log.info("Training autoencoder: %d samples, %d epochs, batch=%d",
                 n, epochs, batch_size)
        t0 = time.time()

        for epoch in range(1, epochs + 1):
            # Shuffle
            idx = np.random.permutation(n)
            X_shuf = X_train[idx]
            train_mse = 0.0
            batches = 0

            for start in range(0, n, batch_size):
                Xb = X_shuf[start:start + batch_size]
                X_hat, pre_acts, activations = self.forward(Xb)
                train_mse += self.mse(Xb, X_hat)
                grad_W, grad_b = self.backward(Xb, pre_acts, activations)
                self.adam_update(grad_W, grad_b, lr)
                batches += 1

            train_mse /= batches
            X_val_hat, _, _ = self.forward(X_val)
            val_mse = self.mse(X_val, X_val_hat)

            history["train_mse"].append(train_mse)
            history["val_mse"].append(val_mse)

            if val_mse < best_val_mse - 1e-6:
                best_val_mse = val_mse
                best_weights = [w.copy() for w in self.weights]
                best_biases  = [b.copy() for b in self.biases]
                no_improve   = 0
            else:
                no_improve += 1

            if epoch % 10 == 0 or epoch == 1:
                elapsed = time.time() - t0
                log.info("Epoch %3d/%d  train_mse=%.6f  val_mse=%.6f  "
                         "[%.1fs elapsed]", epoch, epochs, train_mse, val_mse, elapsed)

            if no_improve >= patience:
                log.info("Early stopping at epoch %d (no val improvement for %d epochs)",
                         epoch, patience)
                break

        # Restore best weights
        if best_weights is not None:
            self.weights = best_weights
            self.biases  = best_biases

        log.info("Training complete. Best val MSE: %.6f", best_val_mse)
        return history

    def save(self, path: Path):
        data = {
            "input_dim":  self.input_dim,
            "layer_dims": LAYER_DIMS,
            "weights": [w.tolist() for w in self.weights],
            "biases":  [b.tolist() for b in self.biases],
        }
        joblib.dump(data, path)
        log.info("Autoencoder saved to %s", path)

    @classmethod
    def load(cls, path: Path) -> "Autoencoder":
        data = joblib.load(path)
        ae = cls(data["input_dim"], data["layer_dims"])
        ae.weights = [np.array(w) for w in data["weights"]]
        ae.biases  = [np.array(b) for b in data["biases"]]
        return ae


# ─────────────────────────────────────────────────────────────────────────────
# Feature loading  (reuses XGBoost feature pipeline)
# ─────────────────────────────────────────────────────────────────────────────

def load_benign_features() -> np.ndarray:
    """Load benign flows from processed CSV, apply same feature engineering as XGBoost."""
    sys.path.insert(0, str(BASE_DIR))
    from process.merge_dataset import flatten_splt_features, add_rate_features, ML_DROP_COLUMNS

    benign_csv = PROC_DIR / "benign.csv"
    if not benign_csv.exists():
        log.error("Benign CSV not found: %s", benign_csv)
        log.error("Run data collection first: sudo ./run_experiment.sh benign 1 300")
        sys.exit(1)

    log.info("Loading benign data from %s", benign_csv)
    df = pd.read_csv(benign_csv, low_memory=False)
    log.info("Loaded %d benign flows", len(df))

    if len(df) < 5000:
        log.warning("Only %d benign flows found. Recommend 50k+ for a good autoencoder.", len(df))

    # Apply same feature engineering as XGBoost pipeline
    df = flatten_splt_features(df)
    df = add_rate_features(df)

    # Get feature names from XGBoost (ensures same feature set)
    feat_file = XGB_DIR / "feature_names.txt"
    if feat_file.exists():
        feat_names = feat_file.read_text().splitlines()
        log.info("Using %d features from XGBoost feature_names.txt", len(feat_names))
    else:
        # Fallback: drop same columns as XGBoost does
        drop = [c for c in ML_DROP_COLUMNS if c in df.columns]
        df = df.drop(columns=drop, errors="ignore")
        non_num = df.select_dtypes(exclude=[np.number]).columns.tolist()
        df = df.drop(columns=non_num, errors="ignore")
        feat_names = df.columns.tolist()
        log.warning("XGBoost feature_names.txt not found. Using all numeric features (%d).", len(feat_names))

    # Align to expected features
    for col in feat_names:
        if col not in df.columns:
            df[col] = 0.0
    X = df[feat_names].fillna(0).replace([np.inf, -np.inf], 0).values.astype(float)
    return X, feat_names


def iter_ml_csv_features_by_label(label_filter: int, chunk_size: int = 10_000) -> tuple:
    """
    Stream the ML CSV in chunks to avoid loading everything into RAM.
    Yields numpy arrays of shape (n, features) for rows matching label_filter.
    Also returns feat_names on first call (via a generator protocol).
    """
    ml_csv = FINAL_DIR / "nids_dataset_ml.csv"
    if not ml_csv.exists():
        log.error("ML CSV not found: %s", ml_csv)
        sys.exit(1)

    feat_file = XGB_DIR / "feature_names.txt"
    if not feat_file.exists():
        log.error("Feature names not found. Run XGBoost training first.")
        sys.exit(1)
    feat_names = feat_file.read_text().splitlines()

    reader = pd.read_csv(ml_csv, low_memory=False, chunksize=chunk_size)
    for chunk in reader:
        if "label" not in chunk.columns:
            continue
        chunk = chunk[chunk["label"] == label_filter]
        if chunk.empty:
            continue
        for col in feat_names:
            if col not in chunk.columns:
                chunk[col] = 0.0
        X = chunk[feat_names].fillna(0).replace([np.inf, -np.inf], 0).values.astype(float)
        yield X, feat_names


# ─────────────────────────────────────────────────────────────────────────────
# Train
# ─────────────────────────────────────────────────────────────────────────────

def train():
    log.info("=" * 60)
    log.info("  Autoencoder NIDS — Training")
    log.info("=" * 60)

    X, feat_names = load_benign_features()
    log.info("Feature matrix: %s", X.shape)

    # Scale
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Train/val split
    X_train, X_val = train_test_split(X_scaled, test_size=VAL_SPLIT,
                                       random_state=RANDOM_SEED)
    log.info("Train: %d  Val: %d", len(X_train), len(X_val))

    # Build and train
    input_dim = X_train.shape[1]
    ae = Autoencoder(input_dim, LAYER_DIMS)
    history = ae.fit(X_train, X_val, EPOCHS, BATCH_SIZE, LEARNING_RATE)

    # Compute anomaly threshold on training benign data
    X_hat_train, _, _ = ae.forward(X_train)
    train_errors = ae.per_sample_mse(X_train, X_hat_train)
    threshold = float(np.percentile(train_errors, THRESHOLD_PERCENTILE))
    log.info("Anomaly threshold (%.0fth percentile of benign MSE): %.6f",
             THRESHOLD_PERCENTILE, threshold)

    # Val stats
    X_hat_val, _, _ = ae.forward(X_val)
    val_errors = ae.per_sample_mse(X_val, X_hat_val)
    log.info("Val MSE stats: mean=%.6f  median=%.6f  p99=%.6f  max=%.6f",
             val_errors.mean(), np.median(val_errors),
             np.percentile(val_errors, 99), val_errors.max())
    false_alarm = (val_errors > threshold).mean() * 100
    log.info("False alarm rate on val benign: %.2f%%", false_alarm)

    # Save artifacts
    ae.save(AE_DIR / "autoencoder.joblib")
    joblib.dump(scaler, AE_DIR / "ae_scaler.joblib")
    (AE_DIR / "ae_feature_names.txt").write_text("\n".join(feat_names))
    (AE_DIR / "ae_threshold.json").write_text(json.dumps({
        "threshold": threshold,
        "percentile": THRESHOLD_PERCENTILE,
        "train_samples": len(X_train),
        "val_mse_mean": float(val_errors.mean()),
        "val_mse_p99":  float(np.percentile(val_errors, 99)),
        "false_alarm_pct": false_alarm,
    }, indent=2))
    joblib.dump(history, AE_DIR / "training_history.joblib")

    # Save training curves as simple text
    curve_lines = ["epoch,train_mse,val_mse"]
    for i, (tr, va) in enumerate(zip(history["train_mse"], history["val_mse"]), 1):
        curve_lines.append(f"{i},{tr:.8f},{va:.8f}")
    (AE_DIR / "training_curves.csv").write_text("\n".join(curve_lines))

    log.info("=" * 60)
    log.info("  DONE. Artifacts saved to: %s", AE_DIR)
    log.info("  ├── autoencoder.joblib")
    log.info("  ├── ae_scaler.joblib")
    log.info("  ├── ae_feature_names.txt")
    log.info("  ├── ae_threshold.json    (threshold=%.6f)", threshold)
    log.info("  └── training_curves.csv")
    log.info("=" * 60)


# ─────────────────────────────────────────────────────────────────────────────
# Eval  (requires merged ML CSV with labels)
# ─────────────────────────────────────────────────────────────────────────────

def score_batched(ae: "Autoencoder", scaler, X: np.ndarray,
                  batch_size: int = 2048) -> np.ndarray:
    """Run AE scoring in small batches to avoid RAM spike."""
    errors = []
    for start in range(0, len(X), batch_size):
        Xb = X[start:start + batch_size]
        Xb_sc          = scaler.transform(Xb)
        Xb_hat, _, _   = ae.forward(Xb_sc)   # forward() returns (output, pre_acts, activations)
        errors.append(np.mean((Xb_sc - Xb_hat) ** 2, axis=1))
    return np.concatenate(errors)


def evaluate():
    log.info("Loading autoencoder artifacts...")
    ae       = Autoencoder.load(AE_DIR / "autoencoder.joblib")
    scaler   = joblib.load(AE_DIR / "ae_scaler.joblib")
    thr_data = json.loads((AE_DIR / "ae_threshold.json").read_text())
    threshold = thr_data["threshold"]
    log.info("Anomaly threshold: %.6f", threshold)

    CLASS_NAMES = {
        0: "BENIGN", 1: "PORT_SCAN", 2: "DOS",
        3: "DDOS",   4: "BRUTE_FORCE", 5: "WEB_ATTACK",
    }

    log.info("\n%-15s  %8s  %8s  %8s  %8s",
             "Class", "N", "MSE_mean", "MSE_p99", "Detect%")
    log.info("-" * 65)

    results = []
    for label, name in CLASS_NAMES.items():
        # Stream CSV in 10k-row chunks — no RAM spike
        all_errors = []
        total_n = 0

        for X_chunk, _ in iter_ml_csv_features_by_label(label, chunk_size=10_000):
            errs = score_batched(ae, scaler, X_chunk)
            all_errors.append(errs)
            total_n += len(X_chunk)

        if total_n == 0:
            log.info("%-15s  %8s  (no rows found, skipping)", name, "—")
            continue

        errors  = np.concatenate(all_errors)
        flagged = (errors > threshold).mean() * 100
        tag     = "FA" if label == 0 else "DR"

        log.info("%-15s  %8d  %8.5f  %8.5f  %7.1f%%  (%s)",
                 name, total_n, errors.mean(),
                 np.percentile(errors, 99), flagged, tag)

        results.append({
            "class": name, "label": label, "n": total_n,
            "mse_mean": float(errors.mean()),
            "mse_p99":  float(np.percentile(errors, 99)),
            "detection_rate": float(flagged),
        })

    (AE_DIR / "eval_results.json").write_text(json.dumps(results, indent=2))
    log.info("\nEval results saved to %s/eval_results.json", AE_DIR)


# ─────────────────────────────────────────────────────────────────────────────
# Score a PCAP file
# ─────────────────────────────────────────────────────────────────────────────

def score_pcap(pcap_path: str):
    import nfstream
    sys.path.insert(0, str(BASE_DIR))
    from process.merge_dataset import flatten_splt_features, add_rate_features, ML_DROP_COLUMNS

    log.info("Loading autoencoder artifacts...")
    ae       = Autoencoder.load(AE_DIR / "autoencoder.joblib")
    scaler   = joblib.load(AE_DIR / "ae_scaler.joblib")
    thr_data = json.loads((AE_DIR / "ae_threshold.json").read_text())
    threshold = thr_data["threshold"]
    feat_names = (AE_DIR / "ae_feature_names.txt").read_text().splitlines()

    log.info("Extracting flows from %s ...", pcap_path)
    streamer = nfstream.NFStreamer(
        source=pcap_path,
        statistical_analysis=True,
        splt_analysis=10,
        idle_timeout=120,
        active_timeout=1800,
    )
    df = streamer.to_pandas(columns_to_anonymize=())
    if df.empty:
        log.warning("No flows extracted from PCAP.")
        return

    display = df[["src_ip", "dst_ip", "src_port", "dst_port", "protocol"]].copy()

    df = flatten_splt_features(df)
    df = add_rate_features(df)
    for col in feat_names:
        if col not in df.columns:
            df[col] = 0.0
    X = df[feat_names].fillna(0).replace([np.inf, -np.inf], 0).values.astype(float)

    X_sc = scaler.transform(X)
    X_hat, _, _ = ae.forward(X_sc)
    errors = ae.per_sample_mse(X_sc, X_hat)

    display["ae_score"]  = np.round(errors, 6)
    display["anomaly"]   = errors > threshold
    display["anomaly_label"] = display["anomaly"].map({True: "⚠ ANOMALY", False: "  normal"})

    n_anom = display["anomaly"].sum()
    pct    = n_anom / len(display) * 100

    print("\n" + "=" * 55)
    print("  ANOMALY DETECTION SUMMARY")
    print("=" * 55)
    print(f"  Total flows   : {len(display):,}")
    print(f"  Anomalies     : {n_anom:,}  ({pct:.1f}%)")
    print(f"  Normal flows  : {len(display)-n_anom:,}  ({100-pct:.1f}%)")
    print(f"  AE threshold  : {threshold:.6f}")
    print("=" * 55)

    print("\nTop anomalous flows (highest reconstruction error):")
    top = display.nlargest(15, "ae_score")
    print(top[["src_ip","dst_ip","src_port","dst_port","protocol","ae_score","anomaly_label"]]
          .to_string(index=False))

    out = pcap_path + ".anomaly_scores.csv"
    try:
        display.to_csv(out, index=False)
    except PermissionError:
        from pathlib import Path as _P
        out = _P(pcap_path).name + ".anomaly_scores.csv"
        display.to_csv(out, index=False)
    log.info("Full scores saved to: %s", out)


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Autoencoder-based NIDS anomaly detector")
    grp = parser.add_mutually_exclusive_group(required=True)
    grp.add_argument("--train", action="store_true",
                     help="Train the autoencoder on benign data")
    grp.add_argument("--eval",  action="store_true",
                     help="Evaluate on all classes in the merged ML CSV")
    grp.add_argument("--pcap",  type=str, metavar="FILE",
                     help="Score a raw PCAP file for anomalies")
    args = parser.parse_args()

    if args.train:
        train()
    elif args.eval:
        evaluate()
    elif args.pcap:
        score_pcap(args.pcap)


if __name__ == "__main__":
    main()
