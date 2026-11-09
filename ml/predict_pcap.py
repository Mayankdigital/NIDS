#!/usr/bin/env python3
"""
predict_pcap.py — Unified NIDS Decision Engine (XGBoost + Autoencoder)
=======================================================================
Combines both models into a single, clear verdict per flow:

  VERDICT LEVELS (in order of severity):
  ────────────────────────────────────────────────────────────────
  ✅ CONFIRMED ATTACK   XGBoost confident (≥80%) → known attack class
  🚨 ZERO-DAY ANOMALY   XGBoost said BENIGN, but AE score ≫ threshold
  ⚠  SUSPECTED ATTACK   XGBoost 50–80% confident, AE also alarmed
  🔍 REVIEW NEEDED      XGBoost unsure, AE did NOT alarm (low confidence)
  🔔 SUSPICIOUS         AE slightly above threshold, XGBoost = BENIGN
  ✓  BENIGN             Both models agree: normal traffic

Usage:
    python3 ml/predict_pcap.py <pcap_file>            # full analysis
    python3 ml/predict_pcap.py <pcap_file> --mode xgb # XGBoost only
    python3 ml/predict_pcap.py <pcap_file> --mode ae  # AE only
    python3 ml/predict_pcap.py <pcap_file> --mode both --verbose  # per-flow table
"""
import argparse
import sys
import os
import json
from pathlib import Path
from collections import Counter

try:
    import nfstream
    import joblib
    import numpy as np
    import pandas as pd
    from xgboost import XGBClassifier
except ImportError:
    print("[ERROR] Missing dependencies. Run: pip install nfstream xgboost joblib pandas")
    sys.exit(1)

BASE_DIR = Path("/home/mayank/Desktop/DATACOLLECTION")
ML_DIR   = BASE_DIR / "nids_dataset" / "final" / "ml_results" / "xgboost"
AE_DIR   = BASE_DIR / "nids_dataset" / "final" / "ml_results" / "autoencoder"

sys.path.insert(0, str(BASE_DIR))
try:
    from process.merge_dataset import flatten_splt_features, add_rate_features, ML_DROP_COLUMNS
except ImportError:
    print("[ERROR] Could not import feature engineering from process/merge_dataset.py")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────────
# Decision thresholds
# ─────────────────────────────────────────────────────────────────────────────
XGB_HIGH_CONF   = 0.80   # ≥80% → confirmed attack
XGB_LOW_CONF    = 0.50   # 50–80% → suspected attack (needs AE confirmation)
AE_ZERO_DAY_MUL = 3.0   # AE score > threshold × 3 → zero-day (strong anomaly)

# Verdict labels and display strings
VERDICT_CONFIRMED  = "CONFIRMED"   # XGBoost high confidence known attack
VERDICT_ZERO_DAY   = "ZERO-DAY"   # AE caught it, XGBoost missed
VERDICT_SUSPECTED  = "SUSPECTED"  # XGBoost medium conf + AE alarmed
VERDICT_REVIEW     = "REVIEW"     # XGBoost medium conf but AE ok
VERDICT_SUSPICIOUS = "SUSPICIOUS" # AE slightly above threshold, XGB=BENIGN
VERDICT_BENIGN     = "BENIGN"     # all clear

VERDICT_ICONS = {
    VERDICT_CONFIRMED:  "✅ CONFIRMED ATTACK",
    VERDICT_ZERO_DAY:   "🚨 ZERO-DAY ANOMALY",
    VERDICT_SUSPECTED:  "⚠  SUSPECTED ATTACK",
    VERDICT_REVIEW:     "🔍 REVIEW NEEDED   ",
    VERDICT_SUSPICIOUS: "🔔 SUSPICIOUS      ",
    VERDICT_BENIGN:     "✓  BENIGN          ",
}

SEVERITY = {
    VERDICT_CONFIRMED:  5,
    VERDICT_ZERO_DAY:   4,
    VERDICT_SUSPECTED:  3,
    VERDICT_REVIEW:     2,
    VERDICT_SUSPICIOUS: 1,
    VERDICT_BENIGN:     0,
}


# ─────────────────────────────────────────────────────────────────────────────
# Inline AE (no extra import needed)
# ─────────────────────────────────────────────────────────────────────────────
def _relu(x): return np.maximum(0, x)

class _AE:
    def __init__(self, data):
        self.weights = [np.array(w) for w in data["weights"]]
        self.biases  = [np.array(b) for b in data["biases"]]
    def forward(self, X):
        a = X
        for i, (W, b) in enumerate(zip(self.weights, self.biases)):
            z = a @ W + b
            a = z if i == len(self.weights) - 1 else _relu(z)
        return a
    def score_batched(self, X, batch=2048):
        out = []
        for s in range(0, len(X), batch):
            Xb = X[s:s+batch]
            out.append(np.mean((Xb - self.forward(Xb))**2, axis=1))
        return np.concatenate(out)


# ─────────────────────────────────────────────────────────────────────────────
# Feature extraction
# ─────────────────────────────────────────────────────────────────────────────
def extract_features(pcap_path: str, feat_names: list):
    print(f"\n[PROCESS] Running NFStream on {pcap_path}...")
    streamer = nfstream.NFStreamer(
        source=pcap_path,
        decode_tunnels=True,
        statistical_analysis=True,
        splt_analysis=10,
        n_dissections=20,
        idle_timeout=120,
        active_timeout=1800,
    )
    df = streamer.to_pandas(columns_to_anonymize=())
    if df.empty:
        print("[WARNING] No flows extracted.")
        sys.exit(0)
    print(f"[PROCESS] Extracted {len(df):,} flows.")

    display = df[["src_ip","dst_ip","src_port","dst_port","protocol"]].copy()

    print("[PROCESS] Applying feature engineering...")
    df = flatten_splt_features(df)
    df = add_rate_features(df)
    df = df.drop(columns=[c for c in ML_DROP_COLUMNS if c in df.columns], errors="ignore")
    for col in feat_names:
        if col not in df.columns:
            df[col] = 0.0

    X = df[feat_names].fillna(0).replace([np.inf,-np.inf], 0).values.astype(float)
    return X, display


# ─────────────────────────────────────────────────────────────────────────────
# Unified decision engine
# ─────────────────────────────────────────────────────────────────────────────
def decide(xgb_label: str, xgb_conf: float,
           ae_score: float, ae_threshold: float) -> tuple:
    """
    Returns (verdict_key, detail_str)

    Rules (evaluated in priority order):
    1. XGBoost is confident (≥80%) → CONFIRMED ATTACK with class name
    2. XGBoost says BENIGN + AE score ≫ threshold → ZERO-DAY ANOMALY
    3. XGBoost is 50–80% + AE alarmed → SUSPECTED ATTACK
    4. XGBoost is 50–80% + AE ok → REVIEW NEEDED
    5. AE slightly above threshold, XGBoost=BENIGN → SUSPICIOUS
    6. Everything ok → BENIGN
    """
    is_attack    = xgb_label != "BENIGN"
    ae_alarmed   = ae_score > ae_threshold
    ae_strong    = ae_score > ae_threshold * AE_ZERO_DAY_MUL

    if is_attack and xgb_conf >= XGB_HIGH_CONF:
        return VERDICT_CONFIRMED, xgb_label

    if not is_attack and ae_strong:
        return VERDICT_ZERO_DAY, f"AE={ae_score:.3f}"

    if is_attack and xgb_conf >= XGB_LOW_CONF and ae_alarmed:
        return VERDICT_SUSPECTED, f"{xgb_label} ({xgb_conf*100:.0f}%)"

    if is_attack and xgb_conf >= XGB_LOW_CONF and not ae_alarmed:
        return VERDICT_REVIEW, f"{xgb_label} ({xgb_conf*100:.0f}%, AE ok)"

    if not is_attack and ae_alarmed:
        return VERDICT_SUSPICIOUS, f"AE={ae_score:.3f}"

    return VERDICT_BENIGN, ""


# ─────────────────────────────────────────────────────────────────────────────
# Print final combined report
# ─────────────────────────────────────────────────────────────────────────────
def print_combined_report(display_df: pd.DataFrame, verdicts: list,
                           details: list, ae_threshold: float):
    """Print the single unified summary that replaces the two separate tables."""
    total    = len(verdicts)
    vc       = Counter(verdicts)

    print("\n" + "═"*62)
    print("  NIDS UNIFIED VERDICT SUMMARY")
    print("═"*62)

    # ── Verdict breakdown ──
    for key in [VERDICT_CONFIRMED, VERDICT_ZERO_DAY, VERDICT_SUSPECTED,
                VERDICT_REVIEW, VERDICT_SUSPICIOUS, VERDICT_BENIGN]:
        count = vc.get(key, 0)
        if count == 0:
            continue
        pct   = count / total * 100
        icon  = VERDICT_ICONS[key]
        print(f"  {icon}  {count:>8,} flows  ({pct:5.1f}%)")

    # ── For confirmed attacks, show breakdown by class ──
    confirmed_idx = [i for i,v in enumerate(verdicts) if v == VERDICT_CONFIRMED]
    if confirmed_idx:
        print(f"\n  ── Confirmed attack breakdown ──")
        class_counts = Counter(details[i] for i in confirmed_idx)
        for cls, cnt in class_counts.most_common():
            pct = cnt / total * 100
            print(f"     {cls:<16} {cnt:>8,} flows  ({pct:5.1f}%)")

    # ── For zero-day, show AE score stats ──
    zd_idx = [i for i,v in enumerate(verdicts) if v == VERDICT_ZERO_DAY]
    if zd_idx:
        zd_scores = display_df.iloc[zd_idx]["ae_score"].values
        print(f"\n  ── Zero-day anomaly AE scores ──")
        print(f"     Mean : {zd_scores.mean():.4f}   "
              f"Max : {zd_scores.max():.4f}   "
              f"Threshold : {ae_threshold:.6f}")
        print(f"     These flows are {zd_scores.mean()/ae_threshold:.0f}× above the normal threshold")

    # ── Mixed attack warning ──
    if len(class_counts if confirmed_idx else {}) > 1:
        print(f"\n  ⚠ Multiple attack types detected in the same capture.")
        print(f"    This is common in long captures with mixed traffic.")
        top_cls = class_counts.most_common(1)[0][0]
        print(f"    Primary threat → {top_cls} "
              f"({class_counts[top_cls]/len(confirmed_idx)*100:.0f}% of confirmed attacks)")

    print("═"*62)

    # ── Overall alert level ──
    max_sev = max(SEVERITY.get(v, 0) for v in verdicts)
    alerts = {
        5: "🔴 CRITICAL  — Known attack confirmed. Investigate immediately.",
        4: "🔴 HIGH      — Unknown attack pattern detected (zero-day). Block source.",
        3: "🟠 MEDIUM    — Suspected attack with moderate confidence. Review logs.",
        2: "🟡 LOW       — Uncertain classification. Manual review recommended.",
        1: "🔵 INFO      — Slight anomaly detected. Monitor this source.",
        0: "🟢 CLEAR     — No threats detected. Traffic appears normal.",
    }
    print(f"\n  ALERT LEVEL: {alerts.get(max_sev, 'UNKNOWN')}")
    print("═"*62)

    # ── Plain English Analysis ──────────────────────────────────────
    print("\n  📋 ANALYSIS:")
    print("  " + "─"*58)

    n_confirmed  = vc.get(VERDICT_CONFIRMED,  0)
    n_zeroday    = vc.get(VERDICT_ZERO_DAY,   0)
    n_suspected  = vc.get(VERDICT_SUSPECTED,  0)
    n_suspicious = vc.get(VERDICT_SUSPICIOUS, 0)
    n_benign     = vc.get(VERDICT_BENIGN,     0)

    # What XGBoost found
    if n_confirmed > 0:
        top_cls = Counter(details[i] for i in
                  [i for i,v in enumerate(verdicts) if v==VERDICT_CONFIRMED]
                  ).most_common(1)[0][0]
        avg_conf = float(np.mean([display_df.iloc[i]["xgb_confidence"]
                          for i,v in enumerate(verdicts)
                          if v == VERDICT_CONFIRMED]))
        print(f"  XGBoost identified {n_confirmed:,} flows as a known attack")
        print(f"  ({top_cls}) with {avg_conf*100:.0f}% average confidence.")
    elif n_suspected > 0:
        print(f"  XGBoost flagged {n_suspected:,} flows as a possible attack")
        print(f"  but with low confidence (50–80%).")
    else:
        xgb_benign_conf = float(np.mean([display_df.iloc[i]["xgb_confidence"]
                                  for i,v in enumerate(verdicts)
                                  if v in (VERDICT_BENIGN, VERDICT_ZERO_DAY,
                                           VERDICT_SUSPICIOUS)]))
        print(f"  XGBoost classified most traffic as BENIGN")
        print(f"  with {xgb_benign_conf*100:.0f}% average confidence — it did not")
        print(f"  recognise this as any known attack type.")

    # What the AE found
    if n_zeroday > 0:
        zd_scores = display_df.iloc[
            [i for i,v in enumerate(verdicts) if v==VERDICT_ZERO_DAY]
        ]["ae_score"].values
        mult = zd_scores.mean() / ae_threshold
        print(f"\n  The Autoencoder flagged {n_zeroday:,} flows as ZERO-DAY")
        print(f"  anomalies. Their reconstruction error ({zd_scores.mean():.1f})")
        print(f"  is {mult:,.0f}× above the normal benign threshold ({ae_threshold:.4f}).")
        print(f"  This means the traffic pattern is completely unlike")
        print(f"  anything seen during normal (benign) training.")

    if n_suspected > 0 and n_confirmed == 0:
        print(f"\n  {n_suspected} flows were suspected but not confirmed.")
        print(f"  Both models raised some concern — recommend manual review.")

    if n_suspicious > 0 and n_zeroday == 0:
        print(f"\n  {n_suspicious} flows looked slightly unusual to the AE")
        print(f"  but XGBoost considered them benign. Low priority.")

    # Conclusion
    print(f"\n  CONCLUSION:")
    if n_zeroday > 0 and n_confirmed == 0:
        print(f"  → This is a ZERO-DAY / UNKNOWN attack.")
        print(f"  → XGBoost alone would have MISSED this completely.")
        print(f"  → The Autoencoder layer caught it.")
        print(f"  → Recommend: block source IP, capture for forensic analysis.")
    elif n_zeroday > 0 and n_confirmed > 0:
        print(f"  → MIXED: known attack ({top_cls}) + unknown anomalies.")
        print(f"  → Treat the unknown portion as potential zero-day.")
        print(f"  → Recommend: block source, escalate to security team.")
    elif n_confirmed > 0:
        print(f"  → Known attack ({top_cls}) confirmed by XGBoost.")
        print(f"  → Autoencoder also alarmed — both models agree.")
        print(f"  → Recommend: block source IP immediately.")
    elif n_suspected > 0:
        print(f"  → Possible attack but models are not fully confident.")
        print(f"  → Recommend: review traffic logs manually.")
    else:
        print(f"  → Traffic appears normal. No action required.")

    print("  " + "─"*58)
    print("═"*62)



# ─────────────────────────────────────────────────────────────────────────────
# XGBoost runner
# ─────────────────────────────────────────────────────────────────────────────
def run_xgb(X_raw: np.ndarray) -> tuple:
    print("\n[XGB] Loading XGBoost model...")
    try:
        model     = XGBClassifier()
        model.load_model(ML_DIR / "model.json")
        scaler    = joblib.load(ML_DIR / "scaler.joblib")
        label_map = json.loads((ML_DIR / "label_map.json").read_text())
        thr_path  = ML_DIR / "class_thresholds.json"
        thresholds = {}
        if thr_path.exists():
            thresholds = {int(k): float(v) for k,v in
                          json.loads(thr_path.read_text()).items()}
    except Exception as e:
        print(f"[ERROR] Failed to load XGBoost: {e}")
        return None, None, None

    X_sc  = scaler.transform(X_raw)
    proba = model.predict_proba(X_sc)

    preds = np.argmax(proba, axis=1).copy()
    confs = proba[np.arange(len(preds)), preds]

    # Apply tuned thresholds
    for idx, thr in thresholds.items():
        mask = (preds == idx) & (confs < thr)
        if mask.any():
            alt = proba.copy(); alt[:, idx] = 0
            preds[mask] = np.argmax(alt, axis=1)[mask]
        confs = proba[np.arange(len(preds)), preds]

    labels = [label_map.get(str(i), f"Class_{i}") for i in preds]
    return labels, confs, label_map


# ─────────────────────────────────────────────────────────────────────────────
# Autoencoder runner
# ─────────────────────────────────────────────────────────────────────────────
def run_ae(X_raw: np.ndarray) -> tuple:
    print("[AE]  Loading Autoencoder model...")
    if not (AE_DIR / "autoencoder.joblib").exists():
        print("[AE]  Not trained yet. Run: python3 ml/autoencoder_nids.py --train")
        return None, None

    ae_data   = joblib.load(AE_DIR / "autoencoder.joblib")
    ae        = _AE(ae_data)
    ae_scaler = joblib.load(AE_DIR / "ae_scaler.joblib")
    threshold = json.loads((AE_DIR / "ae_threshold.json").read_text())["threshold"]

    X_sc   = ae_scaler.transform(X_raw)
    scores = ae.score_batched(X_sc)
    return scores, threshold


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="NIDS Unified Decision Engine")
    parser.add_argument("pcap",    help="Path to PCAP file")
    parser.add_argument("--mode",  choices=["xgb","ae","both"], default="both")
    parser.add_argument("--verbose", action="store_true",
                        help="Print per-flow verdict table")
    args = parser.parse_args()

    if not os.path.exists(args.pcap):
        print(f"[ERROR] PCAP not found: {args.pcap}")
        sys.exit(1)

    feat_names = (ML_DIR / "feature_names.txt").read_text().splitlines()
    X_raw, display_df = extract_features(args.pcap, feat_names)

    xgb_labels  = None
    xgb_confs   = None
    ae_scores   = None
    ae_threshold = None

    if args.mode in ("xgb", "both"):
        xgb_labels, xgb_confs, _ = run_xgb(X_raw)

    if args.mode in ("ae", "both"):
        ae_scores, ae_threshold = run_ae(X_raw)

    # ── XGBoost-only mode ──
    if args.mode == "xgb":
        if xgb_labels is None: sys.exit(1)
        vc = Counter(xgb_labels)
        print("\n" + "="*52)
        print("  XGBoost — CLASSIFICATION SUMMARY")
        print("="*52)
        for lbl, cnt in vc.most_common():
            print(f"  {lbl:<16}: {cnt:>8,} flows  ({cnt/len(xgb_labels)*100:5.1f}%)")
        print("="*52)
        display_df["prediction"] = xgb_labels
        display_df["confidence"] = np.round(xgb_confs, 3)
        _save(display_df, args.pcap, ".predictions_xgb.csv")
        return

    # ── AE-only mode ──
    if args.mode == "ae":
        if ae_scores is None: sys.exit(1)
        n_anom = (ae_scores > ae_threshold).sum()
        print("\n" + "="*52)
        print("  Autoencoder — ANOMALY DETECTION")
        print("="*52)
        print(f"  Threshold  : {ae_threshold:.6f}")
        print(f"  ⚠ Anomalies: {n_anom:,}  ({n_anom/len(ae_scores)*100:.1f}%)")
        print(f"  ✓ Normal   : {len(ae_scores)-n_anom:,}  "
              f"({(len(ae_scores)-n_anom)/len(ae_scores)*100:.1f}%)")
        print(f"  AE Score   : mean={ae_scores.mean():.4f}  max={ae_scores.max():.4f}")
        print("="*52)
        display_df["ae_score"]   = np.round(ae_scores, 5)
        display_df["ae_anomaly"] = (ae_scores > ae_threshold).astype(int)
        _save(display_df, args.pcap, ".predictions_ae.csv")
        return

    # ── Both models: unified decision engine ──
    if xgb_labels is None or ae_scores is None:
        print("[ERROR] Both models required. Check artifacts exist.")
        sys.exit(1)

    print("\n[DECIDE] Applying unified decision logic...")
    verdicts = []
    details  = []
    for lbl, conf, score in zip(xgb_labels, xgb_confs, ae_scores):
        v, d = decide(lbl, conf, score, ae_threshold)
        verdicts.append(v)
        details.append(d)

    # Build output columns
    display_df["xgb_prediction"] = xgb_labels
    display_df["xgb_confidence"] = np.round(xgb_confs, 3)
    display_df["ae_score"]       = np.round(ae_scores, 4)
    display_df["verdict"]        = [VERDICT_ICONS[v].strip() for v in verdicts]
    display_df["detail"]         = details

    # Print unified report
    print_combined_report(display_df, verdicts, details, ae_threshold)

    # Per-flow table (only if --verbose or small file)
    if args.verbose or len(display_df) <= 50:
        print(f"\nPer-flow verdicts:")
        cols = ["src_ip","dst_ip","src_port","dst_port",
                "protocol","xgb_prediction","xgb_confidence","ae_score","verdict"]
        print(display_df[cols].head(30).to_string(index=False))
    else:
        # Always show most alarming flows
        severe = display_df[
            display_df["verdict"].str.contains("ZERO-DAY|CONFIRMED|SUSPECTED")
        ].head(10)
        if not severe.empty:
            print(f"\nTop {len(severe)} most severe flows:")
            cols = ["src_ip","dst_ip","src_port","dst_port",
                    "protocol","xgb_prediction","xgb_confidence","ae_score","verdict"]
            print(severe[cols].to_string(index=False))

    _save(display_df, args.pcap, ".predictions_unified.csv")


def _save(df, pcap_path, suffix):
    out = pcap_path + suffix
    try:
        df.to_csv(out, index=False)
        print(f"\n[SAVE] Results saved → {out}")
    except PermissionError:
        out = Path(pcap_path).name + suffix
        df.to_csv(out, index=False)
        print(f"\n[SAVE] (permission denied) Saved → {out}")


if __name__ == "__main__":
    main()
