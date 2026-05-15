#!/usr/bin/env python3
"""
Patient IDS — Isolation Forest Trainer
========================================
Reads the patient vitals CSV produced by patient_mqtt_subscriber.py,
engineers features, trains an Isolation Forest on normal traffic, and
saves everything the IDS inference script needs:

    patient_ids_model.pkl   ← trained IsolationForest
    patient_ids_scaler.pkl  ← fitted StandardScaler
    patient_ids_meta.json   ← feature list + training stats + threshold

Usage:
    python train_isolation_forest.py
    python train_isolation_forest.py --csv my_data.csv --out-dir ./models
    python train_isolation_forest.py --contamination 0.03 --estimators 200

Requirements:
    pip install pandas scikit-learn joblib
"""

import argparse
import json
import logging
import sys
from pathlib import Path
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# ─────────────────────────────────────────────
#  CONFIGURATION  ← defaults, override via CLI
# ─────────────────────────────────────────────
DEFAULTS = {
    # Input CSV (supports glob patterns, e.g. patient_data_*.csv)
    "csv_path": r"C:\patient_data\csv\patient_data_2026-05-10.csv",

    # Where to save model artefacts
    "output_dir": r"C:\Users\Hospital OS\Desktop\IDS FILES\Models",

    # IsolationForest hyper-parameters
    # contamination: expected fraction of outliers in training data (0.0–0.5)
    # Set to "auto" to let sklearn decide, or a float like 0.01
    "contamination": 0.01,
    "n_estimators": 150,       # number of trees (100–300 typical)
    "max_samples": "auto",     # "auto" = min(256, n_samples)
    "max_features": 1.0,       # fraction of features per tree
    "random_state": 42,
    "n_jobs": -1,              # use all CPU cores

    # Minimum rows required before training
    "min_rows": 100,
}

# ── Categorical encodings (must stay consistent across train & infer) ──────────
WARD_ORDER = ["ICU", "Cardiology", "Neurology", "Orthopedics", "General"]
ECG_ORDER  = ["Normal Sinus", "Sinus Bradycardia", "Sinus Tachycardia", "AFib"]
CON_ORDER  = ["Alert", "Drowsy", "Confused", "Unconscious"]
GENDER_MAP = {"Male": 0, "Female": 1}

# ── Features used for training (must stay consistent with IDS inference) ───────
NUMERIC_FEATURES = [
    "age",
    "bp_systolic_mmhg",
    "bp_diastolic_mmhg",
    "heart_rate_bpm",
    "spo2_percent",
    "respiratory_rate_bpm",
    "temperature_celsius",
    "blood_glucose_mgdl",
    "pain_scale",
    # engineered ↓
    "pulse_pressure",          # systolic - diastolic (cardiac load indicator)
    "mean_arterial_pressure",  # diastolic + pulse_pressure/3
    "shock_index",             # heart_rate / systolic (>1.0 = shock risk)
    "bmi_proxy",               # age-adjusted proxy when height/weight absent
]

ORDINAL_FEATURES = [
    "ward_encoded",
    "ecg_encoded",
    "consciousness_encoded",
    "gender_encoded",
]

ALL_FEATURES = NUMERIC_FEATURES + ORDINAL_FEATURES

# ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


# ══════════════════════════════════════════════
#  1. DATA LOADING
# ══════════════════════════════════════════════
def load_csv(pattern: str) -> pd.DataFrame:
    """Load one file or a glob of daily CSV files into one DataFrame."""
    paths = sorted(Path(".").glob(pattern)) if "*" in pattern else [Path(pattern)]

    if not paths:
        # Try as a literal path
        p = Path(pattern)
        if p.exists():
            paths = [p]
        else:
            log.error(f"No CSV files found matching: {pattern}")
            sys.exit(1)

    frames = []
    for p in paths:
        log.info(f"Reading: {p}  ({p.stat().st_size / 1024:.1f} KB)")
        try:
            frames.append(pd.read_csv(p, parse_dates=["received_at", "published_at"]))
        except Exception as e:
            log.warning(f"Skipping {p}: {e}")

    if not frames:
        log.error("No valid CSV data loaded.")
        sys.exit(1)

    df = pd.concat(frames, ignore_index=True)
    log.info(f"Loaded {len(df):,} rows from {len(frames)} file(s)")
    return df


# ══════════════════════════════════════════════
#  2. CLEANING
# ══════════════════════════════════════════════
def clean(df: pd.DataFrame) -> pd.DataFrame:
    log.info("── Cleaning ──────────────────────────────")
    before = len(df)

    # Drop completely empty rows
    df = df.dropna(how="all")

    # Coerce numeric columns (bad values → NaN)
    numeric_cols = [
        "age", "bp_systolic_mmhg", "bp_diastolic_mmhg", "heart_rate_bpm",
        "spo2_percent", "respiratory_rate_bpm", "temperature_celsius",
        "blood_glucose_mgdl", "pain_scale",
    ]
    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    # Hard physiological bounds — values outside these are sensor errors
    bounds = {
        "age":                   (0,   120),
        "bp_systolic_mmhg":      (50,  260),
        "bp_diastolic_mmhg":     (30,  160),
        "heart_rate_bpm":        (20,  250),
        "spo2_percent":          (50,  100),
        "respiratory_rate_bpm":  (4,   60),
        "temperature_celsius":   (33,  43),
        "blood_glucose_mgdl":    (20,  600),
        "pain_scale":            (0,   10),
    }
    for col, (lo, hi) in bounds.items():
        if col in df.columns:
            mask = df[col].between(lo, hi, inclusive="both") | df[col].isna()
            n_bad = (~mask).sum()
            if n_bad:
                log.warning(f"  {col}: {n_bad} out-of-bounds values set to NaN")
            df.loc[~mask, col] = np.nan

    # Drop rows still missing core vitals
    core = ["bp_systolic_mmhg", "bp_diastolic_mmhg", "heart_rate_bpm", "spo2_percent"]
    df = df.dropna(subset=core)

    # Fill remaining numeric NaNs with per-patient median, then global median
    for col in numeric_cols:
        if col in df.columns and df[col].isna().any():
            df[col] = df.groupby("patient_id")[col].transform(
                lambda s: s.fillna(s.median())
            )
            df[col] = df[col].fillna(df[col].median())

    # Remove duplicate readings (same patient, same published_at)
    df = df.drop_duplicates(subset=["patient_id", "published_at"])

    log.info(f"  Rows: {before:,} → {len(df):,} after cleaning")
    return df


# ══════════════════════════════════════════════
#  3. FEATURE ENGINEERING
# ══════════════════════════════════════════════
def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    log.info("── Feature Engineering ───────────────────")

    # Derived cardiovascular features
    df["pulse_pressure"]         = df["bp_systolic_mmhg"] - df["bp_diastolic_mmhg"]
    df["mean_arterial_pressure"] = df["bp_diastolic_mmhg"] + df["pulse_pressure"] / 3
    df["shock_index"]            = df["heart_rate_bpm"] / df["bp_systolic_mmhg"].replace(0, np.nan)

    # Age-adjusted BMI proxy (no height/weight available)
    df["bmi_proxy"] = np.log1p(df["age"]) * (df["blood_glucose_mgdl"] / 100)

    # Ordinal encoding — consistent order crucial for inference parity
    df["ward_encoded"]          = pd.Categorical(df["ward"],         categories=WARD_ORDER).codes.astype(float)
    df["ecg_encoded"]           = pd.Categorical(df["ecg_rhythm"],   categories=ECG_ORDER).codes.astype(float)
    df["consciousness_encoded"] = pd.Categorical(df["consciousness"], categories=CON_ORDER).codes.astype(float)
    df["gender_encoded"]        = df["gender"].map(GENDER_MAP).astype(float)

    # Replace -1 (unseen category) with NaN, then fill with mode
    for col in ORDINAL_FEATURES:
        df[col] = df[col].replace(-1, np.nan)
        df[col] = df[col].fillna(df[col].mode()[0])

    log.info(f"  Engineered features: {ALL_FEATURES}")
    return df


# ══════════════════════════════════════════════
#  4. TRAINING
# ══════════════════════════════════════════════
def train(df: pd.DataFrame, cfg: dict):
    log.info("── Training ──────────────────────────────")

    X = df[ALL_FEATURES].copy()

    # Final NaN check
    n_null = X.isnull().sum().sum()
    if n_null:
        log.warning(f"  {n_null} NaN values remain — filling with column median")
        X = X.fillna(X.median())

    log.info(f"  Training matrix: {X.shape[0]:,} rows × {X.shape[1]} features")

    # Scale features (IsolationForest doesn't strictly need it, but
    # it helps with anomaly score interpretability and future extensibility)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Train Isolation Forest
    log.info(
        f"  IsolationForest | n_estimators={cfg['n_estimators']} | "
        f"contamination={cfg['contamination']} | random_state={cfg['random_state']}"
    )
    model = IsolationForest(
        n_estimators=cfg["n_estimators"],
        max_samples=cfg["max_samples"],
        max_features=cfg["max_features"],
        contamination=cfg["contamination"],
        random_state=cfg["random_state"],
        n_jobs=cfg["n_jobs"],
    )
    model.fit(X_scaled)

    # Score the training data to compute a decision threshold
    scores = model.decision_function(X_scaled)   # higher = more normal
    predictions = model.predict(X_scaled)         # +1 = normal, -1 = anomaly

    n_anomalies = (predictions == -1).sum()
    n_normal    = (predictions ==  1).sum()
    pct_anomaly = n_anomalies / len(predictions) * 100

    log.info(f"  Training results: {n_normal:,} normal | {n_anomalies:,} flagged ({pct_anomaly:.2f}%)")

    # Save a percentile-based threshold for the IDS script to use
    # (5th percentile of training scores = conservative boundary)
    threshold = float(np.percentile(scores, 5))
    log.info(f"  Decision threshold (5th pct): {threshold:.6f}")

    return model, scaler, scores, threshold


# ══════════════════════════════════════════════
#  5. SAVE ARTEFACTS
# ══════════════════════════════════════════════
def save_artefacts(model, scaler, scores, threshold, cfg: dict):
    out = Path(cfg["output_dir"])
    out.mkdir(parents=True, exist_ok=True)

    model_path  = out / "patient_ids_model.pkl"
    scaler_path = out / "patient_ids_scaler.pkl"
    meta_path   = out / "patient_ids_meta.json"

    joblib.dump(model,  model_path,  compress=3)
    joblib.dump(scaler, scaler_path, compress=3)
    log.info(f"  Model  saved → {model_path}")
    log.info(f"  Scaler saved → {scaler_path}")

    meta = {
        "trained_at":           datetime.utcnow().isoformat() + "Z",
        "n_training_samples":   int(len(scores)),
        "features":             ALL_FEATURES,
        "numeric_features":     NUMERIC_FEATURES,
        "ordinal_features":     ORDINAL_FEATURES,
        "ward_order":           WARD_ORDER,
        "ecg_order":            ECG_ORDER,
        "consciousness_order":  CON_ORDER,
        "gender_map":           GENDER_MAP,
        "decision_threshold":   threshold,
        "score_stats": {
            "mean":  float(np.mean(scores)),
            "std":   float(np.std(scores)),
            "min":   float(np.min(scores)),
            "p5":    float(np.percentile(scores, 5)),
            "p25":   float(np.percentile(scores, 25)),
            "p50":   float(np.percentile(scores, 50)),
            "p75":   float(np.percentile(scores, 75)),
            "max":   float(np.max(scores)),
        },
        "hyperparameters": {
            "n_estimators":  cfg["n_estimators"],
            "contamination": str(cfg["contamination"]),
            "max_samples":   str(cfg["max_samples"]),
            "max_features":  cfg["max_features"],
            "random_state":  cfg["random_state"],
        },
        "model_path":  str(model_path),
        "scaler_path": str(scaler_path),
    }

    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)
    log.info(f"  Meta   saved → {meta_path}")

    return model_path, scaler_path, meta_path


# ══════════════════════════════════════════════
#  6. TRAINING REPORT
# ══════════════════════════════════════════════
def print_report(df: pd.DataFrame, scores: np.ndarray, threshold: float):
    print("\n" + "═" * 60)
    print("  TRAINING REPORT")
    print("═" * 60)
    print(f"  Patients in dataset  : {df['patient_id'].nunique()}")
    print(f"  Total readings       : {len(df):,}")
    print(f"  Date range           : {df['published_at'].min()} → {df['published_at'].max()}")
    print(f"  Features trained on  : {len(ALL_FEATURES)}")
    print()
    print("  Anomaly Score Distribution (higher = more normal):")
    print(f"    Min   : {np.min(scores):>10.6f}")
    print(f"    P5    : {np.percentile(scores,  5):>10.6f}  ← decision threshold")
    print(f"    P25   : {np.percentile(scores, 25):>10.6f}")
    print(f"    Median: {np.percentile(scores, 50):>10.6f}")
    print(f"    P75   : {np.percentile(scores, 75):>10.6f}")
    print(f"    Max   : {np.max(scores):>10.6f}")
    print()
    flagged = (scores < threshold).sum()
    print(f"  Flagged as anomalous : {flagged:,} / {len(scores):,} ({flagged/len(scores)*100:.2f}%)")
    print("═" * 60 + "\n")


# ══════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════
def parse_args():
    p = argparse.ArgumentParser(description="Train IsolationForest on patient vitals CSV")
    p.add_argument("--csv",           default=DEFAULTS["csv_path"],      help="Path or glob to CSV file(s)")
    p.add_argument("--out-dir",       default=DEFAULTS["output_dir"],    help="Directory to save model artefacts")
    p.add_argument("--contamination", default=DEFAULTS["contamination"], help="Expected outlier fraction (float or 'auto')")
    p.add_argument("--estimators",    default=DEFAULTS["n_estimators"],  type=int, help="Number of trees")
    p.add_argument("--min-rows",      default=DEFAULTS["min_rows"],      type=int, help="Minimum rows required to train")
    return p.parse_args()


# ══════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════
def main():
    args = parse_args()

    cfg = {
        **DEFAULTS,
        "csv_path":      args.csv,
        "output_dir":    args.out_dir,
        "contamination": float(args.contamination) if args.contamination != "auto" else "auto",
        "n_estimators":  args.estimators,
    }

    log.info("=== Isolation Forest Trainer — Patient IDS ===")
    log.info(f"  CSV source  : {cfg['csv_path']}")
    log.info(f"  Output dir  : {cfg['output_dir']}")

    # ── Load ──
    df = load_csv(cfg["csv_path"])

    if len(df) < cfg["min_rows"]:
        log.error(f"Only {len(df)} rows — need at least {cfg['min_rows']} to train reliably. Collect more data.")
        sys.exit(1)

    # ── Clean ──
    df = clean(df)

    # ── Feature engineering ──
    df = engineer_features(df)

    # ── Train ──
    model, scaler, scores, threshold = train(df, cfg)

    # ── Save ──
    log.info("── Saving Artefacts ──────────────────────")
    model_path, scaler_path, meta_path = save_artefacts(model, scaler, scores, threshold, cfg)

    # ── Report ──
    print_report(df, scores, threshold)

    log.info("Done! Load the model in your IDS script like this:")
    log.info("")
    log.info("    import joblib, json")
    log.info(f"    model  = joblib.load(r'{model_path}')")
    log.info(f"    scaler = joblib.load(r'{scaler_path}')")
    log.info(f"    meta   = json.load(open(r'{meta_path}'))")
    log.info("    X_scaled = scaler.transform(new_data[meta['features']])")
    log.info("    predictions = model.predict(X_scaled)  # +1=normal, -1=anomaly")
    log.info("    scores      = model.decision_function(X_scaled)")
    log.info("")


if __name__ == "__main__":
    main()
