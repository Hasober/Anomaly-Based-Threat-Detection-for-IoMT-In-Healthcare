#!/usr/bin/env python3
"""
Patient IDS — Real-Time MQTT Intrusion Detection System
=========================================================
Loads the pre-trained Isolation Forest model and scaler produced by
train_isolation_forest.py, subscribes to the MQTT broker, and for every
incoming patient vitals message:

  1. Parses & engineers features (identical pipeline to training)
  2. Scales the feature vector with the saved StandardScaler
  3. Computes an anomaly score via IsolationForest.decision_function()
  4. Classifies the alert level  → LOW / MEDIUM / HIGH
  5. Identifies the attack type  → Data Exfiltration / Brute Force /
                                   Unauthorized Access / Unrelated Payload /
                                   Vital Sign Spoofing / Replay Attack / CLEAN
  6. Logs CPU usage for the scan cycle
  7. Writes every event to a structured JSON-lines alert log

Run this on the Windows VM alongside the MQTT broker.

Requirements:
    pip install paho-mqtt joblib scikit-learn numpy psutil
"""

import json
import logging
import os
import signal
import sys
import time
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import psutil
import paho.mqtt.client as mqtt

# ─────────────────────────────────────────────
#  CONFIGURATION  ← edit these values
# ─────────────────────────────────────────────
CONFIG = {
    # MQTT broker
    "broker_host":   "192.168.190.130",       # Windows VM IP / localhost
    "broker_port":   1883,
    "topic":         "hospital/patients/#", # same wildcard as subscriber
    "client_id":     "patient-ids-engine",
    "mqtt_username": "",
    "mqtt_password": "",
    "keepalive":     60,

    # Model artefacts (produced by train_isolation_forest.py)
    "model_path":  r"C:\Users\Hospital OS\Desktop\IDS FILES\Models\patient_ids_model.pkl",
    "scaler_path": r"C:\Users\Hospital OS\Desktop\IDS FILES\Models\patient_ids_scaler.pkl",
    "meta_path":   r"C:\Users\Hospital OS\Desktop\IDS FILES\Models\patient_ids_meta.json",

    # Alert log (JSON-lines format, one event per line)
    "alert_log":   r"C:\patient_data\ids_alerts.jsonl",

    # Console log level: DEBUG / INFO / WARNING
    "log_level": "INFO",

    # ── Alert thresholds (anomaly score; higher = more normal) ──────────────
    # Scores are centred around 0; typical normal range is [-0.1, +0.5]
    # These can be tuned after reviewing score_stats in patient_ids_meta.json
    "threshold_low":    -0.05,   # below this            → LOW alert
    "threshold_medium": -0.15,   # below this            → MEDIUM alert
    "threshold_high":   -0.30,   # below this            → HIGH alert
    # anything above threshold_low                       → CLEAN

    # ── CPU warning ─────────────────────────────────────────────────────────
    "cpu_warn_pct": 80.0,   # log a warning if CPU usage exceeds this
}
# ─────────────────────────────────────────────

# ── Encoding maps — MUST match train_isolation_forest.py ─────────────────────
WARD_ORDER = ["ICU", "Cardiology", "Neurology", "Orthopedics", "General"]
ECG_ORDER  = ["Normal Sinus", "Sinus Bradycardia", "Sinus Tachycardia", "AFib"]
CON_ORDER  = ["Alert", "Drowsy", "Confused", "Unconscious"]
GENDER_MAP = {"Male": 0, "Female": 1}

NUMERIC_FEATURES = [
    "age", "bp_systolic_mmhg", "bp_diastolic_mmhg", "heart_rate_bpm",
    "spo2_percent", "respiratory_rate_bpm", "temperature_celsius",
    "blood_glucose_mgdl", "pain_scale",
    "pulse_pressure", "mean_arterial_pressure", "shock_index", "bmi_proxy",
]
ORDINAL_FEATURES = [
    "ward_encoded", "ecg_encoded", "consciousness_encoded", "gender_encoded",
]
ALL_FEATURES = NUMERIC_FEATURES + ORDINAL_FEATURES

# ── Physiological bounds (same as cleaner in training) ───────────────────────
BOUNDS = {
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

# ─────────────────────────────────────────────
logging.basicConfig(
    level=CONFIG["log_level"],
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 1 — LOAD MODEL ARTEFACTS
# ══════════════════════════════════════════════════════════════════════════════
def load_artefacts(cfg: dict) -> tuple:
    """Load model, scaler, and meta from disk. Exit on failure."""
    for key in ("model_path", "scaler_path", "meta_path"):
        if not Path(cfg[key]).exists():
            log.error(f"Artefact not found: {cfg[key]}")
            log.error("Run train_isolation_forest.py first.")
            sys.exit(1)

    model  = joblib.load(cfg["model_path"])
    scaler = joblib.load(cfg["scaler_path"])
    with open(cfg["meta_path"]) as f:
        meta = json.load(f)

    log.info(f"Model  loaded ← {cfg['model_path']}")
    log.info(f"Scaler loaded ← {cfg['scaler_path']}")
    log.info(f"Meta   loaded ← trained at {meta.get('trained_at', 'unknown')}")
    log.info(f"Features ({len(meta['features'])}): {meta['features']}")
    log.info(
        f"Score stats from training: "
        f"min={meta['score_stats']['min']:.4f}  "
        f"p50={meta['score_stats']['p50']:.4f}  "
        f"max={meta['score_stats']['max']:.4f}"
    )
    return model, scaler, meta


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 2 — FEATURE ENGINEERING (must mirror training pipeline exactly)
# ══════════════════════════════════════════════════════════════════════════════
def _safe_float(val, default=0.0):
    try:
        v = float(val)
        return v if np.isfinite(v) else default
    except (TypeError, ValueError):
        return default


def engineer_features(payload: dict) -> dict | None:
    """
    Parse a raw MQTT JSON payload and return a flat feature dict ready for
    model inference.  Returns None if core vitals are missing or invalid.
    """
    vitals = payload.get("vitals", {})
    bp     = vitals.get("blood_pressure", {})

    raw = {
        "age":                   _safe_float(payload.get("age")),
        "bp_systolic_mmhg":      _safe_float(bp.get("systolic_mmhg")),
        "bp_diastolic_mmhg":     _safe_float(bp.get("diastolic_mmhg")),
        "heart_rate_bpm":        _safe_float(vitals.get("heart_rate_bpm")),
        "spo2_percent":          _safe_float(vitals.get("spo2_percent")),
        "respiratory_rate_bpm":  _safe_float(vitals.get("respiratory_rate_bpm")),
        "temperature_celsius":   _safe_float(vitals.get("temperature_celsius")),
        "blood_glucose_mgdl":    _safe_float(vitals.get("blood_glucose_mgdl")),
        "pain_scale":            _safe_float(vitals.get("pain_scale")),
        "ward":                  payload.get("ward", "General"),
        "ecg_rhythm":            vitals.get("ecg_rhythm", "Normal Sinus"),
        "consciousness":         vitals.get("consciousness", "Alert"),
        "gender":                payload.get("gender", "Male"),
    }

    # Validate core vitals against physiological bounds
    core = ["bp_systolic_mmhg", "bp_diastolic_mmhg", "heart_rate_bpm", "spo2_percent"]
    for col in core:
        lo, hi = BOUNDS[col]
        if not (lo <= raw[col] <= hi):
            log.debug(f"Core vital {col}={raw[col]} out of bounds [{lo},{hi}] — skipping payload")
            return None

    # Apply bounds to non-core (clamp rather than reject)
    for col, (lo, hi) in BOUNDS.items():
        if col in raw:
            raw[col] = max(lo, min(hi, raw[col]))

    # Derived cardiovascular features
    pulse_pressure = raw["bp_systolic_mmhg"] - raw["bp_diastolic_mmhg"]
    map_val        = raw["bp_diastolic_mmhg"] + pulse_pressure / 3
    shock_index    = raw["heart_rate_bpm"] / raw["bp_systolic_mmhg"] if raw["bp_systolic_mmhg"] else 0.0
    bmi_proxy      = np.log1p(raw["age"]) * (raw["blood_glucose_mgdl"] / 100)

    # Ordinal encoding
    ward_enc = WARD_ORDER.index(raw["ward"]) if raw["ward"] in WARD_ORDER else 4
    ecg_enc  = ECG_ORDER.index(raw["ecg_rhythm"]) if raw["ecg_rhythm"] in ECG_ORDER else 0
    con_enc  = CON_ORDER.index(raw["consciousness"]) if raw["consciousness"] in CON_ORDER else 0
    gen_enc  = GENDER_MAP.get(raw["gender"], 0)

    return {
        # raw numeric
        "age":                   raw["age"],
        "bp_systolic_mmhg":      raw["bp_systolic_mmhg"],
        "bp_diastolic_mmhg":     raw["bp_diastolic_mmhg"],
        "heart_rate_bpm":        raw["heart_rate_bpm"],
        "spo2_percent":          raw["spo2_percent"],
        "respiratory_rate_bpm":  raw["respiratory_rate_bpm"],
        "temperature_celsius":   raw["temperature_celsius"],
        "blood_glucose_mgdl":    raw["blood_glucose_mgdl"],
        "pain_scale":            raw["pain_scale"],
        # engineered
        "pulse_pressure":         pulse_pressure,
        "mean_arterial_pressure": map_val,
        "shock_index":            shock_index,
        "bmi_proxy":              bmi_proxy,
        # ordinal
        "ward_encoded":           float(ward_enc),
        "ecg_encoded":            float(ecg_enc),
        "consciousness_encoded":  float(con_enc),
        "gender_encoded":         float(gen_enc),
    }


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 3 — ALERT CLASSIFICATION
# ══════════════════════════════════════════════════════════════════════════════
def classify_alert(score: float, cfg: dict) -> str:
    """
    Map an anomaly score to an alert level.

    Isolation Forest decision_function() returns:
      positive values  → normal (further from boundary)
      negative values  → anomalous (inside the isolation boundary)

    Thresholds (configurable in CONFIG):
      score > threshold_low    → CLEAN
      threshold_medium < score ≤ threshold_low  → LOW
      threshold_high   < score ≤ threshold_medium → MEDIUM
      score ≤ threshold_high   → HIGH
    """
    if score > cfg["threshold_low"]:
        return "CLEAN"
    elif score > cfg["threshold_medium"]:
        return "LOW"
    elif score > cfg["threshold_high"]:
        return "MEDIUM"
    else:
        return "HIGH"


def classify_attack(score: float, features: dict, payload: dict, alert_level: str) -> dict:
    """
    Heuristic attack-type classifier.

    Examines the anomaly score AND the raw feature values to infer the most
    likely threat vector.  Returns a dict with 'type' and 'reason'.

    Attack taxonomy for medical IoT / MQTT IDS:
      CLEAN              — within normal baseline, no threat
      DATA_EXFILTRATION  — abnormal payload structure / unexpected field combinations
      BRUTE_FORCE        — rapid sequential messages from same patient ID
      UNAUTHORIZED_ACCESS — topic mismatch or unknown patient fields
      VITAL_SIGN_SPOOFING — physiologically impossible combinations that still parse
      REPLAY_ATTACK      — duplicate timestamps with slightly different values
      UNRELATED_PAYLOAD  — non-patient JSON or missing expected fields
    """
    if alert_level == "CLEAN":
        return {"type": "NONE", "reason": "Score within normal baseline"}

    vitals      = payload.get("vitals", {})
    patient_id  = payload.get("patient_id", "")
    bp_sys      = features.get("bp_systolic_mmhg", 120)
    bp_dia      = features.get("bp_diastolic_mmhg", 80)
    hr          = features.get("heart_rate_bpm", 75)
    spo2        = features.get("spo2_percent", 98)
    temp        = features.get("temperature_celsius", 37)
    rr          = features.get("respiratory_rate_bpm", 16)
    glucose     = features.get("blood_glucose_mgdl", 100)
    shock_idx   = features.get("shock_index", 0.6)
    pulse_pr    = features.get("pulse_pressure", 40)

    reasons = []

    # ── Rule 1: UNRELATED_PAYLOAD ─────────────────────────────────────────────
    # Payload is missing structural fields expected from the publisher
    expected_keys = {"patient_id", "vitals", "timestamp", "ward"}
    missing = expected_keys - set(payload.keys())
    if missing:
        return {
            "type":   "UNRELATED_PAYLOAD",
            "reason": f"Missing expected fields: {sorted(missing)}. "
                      "Possibly a rogue publisher or wrong topic."
        }

    # ── Rule 2: VITAL_SIGN_SPOOFING ───────────────────────────────────────────
    # Physiologically impossible combinations that slip past individual bounds
    spoofing_flags = []

    if bp_sys <= bp_dia:
        spoofing_flags.append(f"systolic ({bp_sys}) ≤ diastolic ({bp_dia})")
    if pulse_pr > 100:
        spoofing_flags.append(f"pulse pressure {pulse_pr:.0f} mmHg (dangerously wide)")
    if shock_idx > 1.5:
        spoofing_flags.append(f"shock index {shock_idx:.2f} (extreme — HR/SBP ratio)")
    if spo2 < 85 and hr < 40:
        spoofing_flags.append(f"SpO2={spo2}% AND HR={hr} bpm simultaneously")
    if temp > 41 and rr < 8:
        spoofing_flags.append(f"hyperthermic ({temp}°C) but bradypnoea ({rr} bpm)")
    if glucose > 400 and spo2 > 99:
        spoofing_flags.append(f"extreme glucose ({glucose}) with perfect SpO2 ({spo2}%)")

    if spoofing_flags:
        return {
            "type":   "VITAL_SIGN_SPOOFING",
            "reason": "Physiologically inconsistent vital combination: " + "; ".join(spoofing_flags)
        }

    # ── Rule 3: DATA_EXFILTRATION ─────────────────────────────────────────────
    # Unexpected extra fields stuffed into the payload (side-channel exfil attempt)
    expected_vitals_keys = {
        "blood_pressure", "heart_rate_bpm", "spo2_percent", "respiratory_rate_bpm",
        "temperature_celsius", "blood_glucose_mgdl", "ecg_rhythm", "pain_scale", "consciousness"
    }
    unexpected_vitals = set(vitals.keys()) - expected_vitals_keys
    unexpected_root   = set(payload.keys()) - {
        "timestamp", "patient_id", "name", "age", "gender", "ward", "bed", "vitals"
    }

    if unexpected_vitals or unexpected_root:
        extra = list(unexpected_vitals) + list(unexpected_root)
        return {
            "type":   "DATA_EXFILTRATION",
            "reason": f"Unexpected fields detected in payload: {extra}. "
                      "Possible side-channel data injection or exfiltration attempt."
        }

    # ── Rule 4: UNAUTHORIZED_ACCESS ───────────────────────────────────────────
    # patient_id format mismatch (should be P001–P020 from publisher)
    import re
    if not re.match(r"^P\d{3}$", str(patient_id)):
        return {
            "type":   "UNAUTHORIZED_ACCESS",
            "reason": f"Patient ID '{patient_id}' does not match expected format P001–P020. "
                      "Possible rogue device publishing to the broker."
        }

    # ── Rule 5: BRUTE_FORCE ───────────────────────────────────────────────────
    # Very high anomaly (score far below HIGH threshold) with otherwise valid structure
    # Interpreted as a flood / brute-force probe of the broker
    if score < CONFIG["threshold_high"] - 0.15:
        return {
            "type":   "BRUTE_FORCE",
            "reason": f"Anomaly score {score:.4f} is significantly below HIGH threshold "
                      f"({CONFIG['threshold_high']}). Possible message flood / broker probe."
        }

    # ── Rule 6: REPLAY_ATTACK ─────────────────────────────────────────────────
    # Score is anomalous but features look individually plausible — typical of
    # replayed old readings with micro-mutations to evade duplicate detection
    if alert_level in ("MEDIUM", "HIGH"):
        reasons.append(
            f"Score {score:.4f} indicates anomalous pattern. "
            "All individual vitals within bounds but overall feature vector deviates "
            "from learned normal distribution — consistent with a replay or mutation attack."
        )
        return {
            "type":   "REPLAY_ATTACK",
            "reason": " ".join(reasons)
        }

    # ── Fallback ──────────────────────────────────────────────────────────────
    return {
        "type":   "UNRELATED_PAYLOAD",
        "reason": f"Score {score:.4f} is anomalous but attack type could not be "
                  "precisely determined. Flagging for manual review."
    }


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 4 — CPU MONITOR
# ══════════════════════════════════════════════════════════════════════════════
def get_cpu_stats() -> dict:
    """Return current CPU usage metrics."""
    per_core   = psutil.cpu_percent(interval=None, percpu=True)
    cpu_avg    = sum(per_core) / len(per_core)
    cpu_freq   = psutil.cpu_freq()
    mem        = psutil.virtual_memory()
    return {
        "cpu_avg_pct":      round(cpu_avg, 2),
        "cpu_per_core_pct": [round(c, 1) for c in per_core],
        "cpu_freq_mhz":     round(cpu_freq.current, 1) if cpu_freq else None,
        "mem_used_pct":     round(mem.percent, 2),
        "mem_used_mb":      round(mem.used / 1024 / 1024, 1),
    }


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 5 — ALERT LOGGER
# ══════════════════════════════════════════════════════════════════════════════
class AlertLogger:
    """Writes JSON-lines alert events to disk and to the console."""

    LEVEL_COLOUR = {
        "CLEAN":  "\033[92m",   # green
        "LOW":    "\033[93m",   # yellow
        "MEDIUM": "\033[95m",   # magenta
        "HIGH":   "\033[91m",   # red
    }
    RESET = "\033[0m"

    ATTACK_ICON = {
        "NONE":               "✅",
        "DATA_EXFILTRATION":  "📤",
        "BRUTE_FORCE":        "💥",
        "UNAUTHORIZED_ACCESS":"🚫",
        "VITAL_SIGN_SPOOFING":"🎭",
        "REPLAY_ATTACK":      "🔁",
        "UNRELATED_PAYLOAD":  "❓",
    }

    def __init__(self, log_path: str):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._total    = 0
        self._anomalies = 0
        log.info(f"Alert log → {self.log_path}")

    def write(self, event: dict):
        self._total += 1
        if event["alert_level"] != "CLEAN":
            self._anomalies += 1

        # JSON-lines append
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")

        # Console output
        level  = event["alert_level"]
        colour = self.ALERT_COLOUR(level)
        icon   = self.ATTACK_ICON.get(event["attack"]["type"], "❓")
        cpu    = event["cpu"]["cpu_avg_pct"]

        console_line = (
            f"{colour}[{level:6s}]{self.RESET} "
            f"{icon} {event['attack']['type']:22s} | "
            f"Patient {event['patient_id']:5s} | "
            f"Score {event['anomaly_score']:+.4f} | "
            f"CPU {cpu:5.1f}% | "
            f"{event['attack']['reason'][:80]}"
        )

        if level == "HIGH":
            log.warning(console_line)
        elif level in ("MEDIUM", "LOW"):
            log.info(console_line)
        else:
            log.debug(console_line)

    def ALERT_COLOUR(self, level: str) -> str:
        return self.LEVEL_COLOUR.get(level, "")

    def summary(self):
        pct = (self._anomalies / self._total * 100) if self._total else 0
        log.info(
            f"Session summary: {self._total} messages processed | "
            f"{self._anomalies} anomalies ({pct:.2f}%)"
        )


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 6 — INFERENCE ENGINE
# ══════════════════════════════════════════════════════════════════════════════
class IDSEngine:
    """Wraps model + scaler and performs inference on a single payload dict."""

    def __init__(self, model, scaler, meta: dict, cfg: dict):
        self.model  = model
        self.scaler = scaler
        self.meta   = meta
        self.cfg    = cfg

    def infer(self, topic: str, payload: dict) -> dict | None:
        """
        Full inference pipeline for one MQTT message.
        Returns an event dict, or None if the payload cannot be processed.
        """
        scan_start = time.perf_counter()

        # ── Step 1: Feature engineering ───────────────────────────────────────
        features = engineer_features(payload)
        if features is None:
            log.debug(f"[{topic}] Payload skipped — invalid core vitals")
            return None

        # ── Step 2: Build feature vector in training order ────────────────────
        try:
            X_raw = np.array([[features[f] for f in ALL_FEATURES]], dtype=float)
        except KeyError as e:
            log.warning(f"[{topic}] Missing feature {e} — skipping")
            return None

        # ── Step 3: Scale ──────────────────────────────────────────────────────
        X_scaled = self.scaler.transform(X_raw)

        # ── Step 4: Score & predict ────────────────────────────────────────────
        score      = float(self.model.decision_function(X_scaled)[0])
        prediction = int(self.model.predict(X_scaled)[0])   # +1 or -1

        # ── Step 5: Classify alert level ──────────────────────────────────────
        alert_level = classify_alert(score, self.cfg)

        # ── Step 6: Identify attack type ──────────────────────────────────────
        attack = classify_attack(score, features, payload, alert_level)

        # ── Step 7: CPU stats ──────────────────────────────────────────────────
        cpu_stats  = get_cpu_stats()
        scan_ms    = round((time.perf_counter() - scan_start) * 1000, 3)

        if cpu_stats["cpu_avg_pct"] >= self.cfg["cpu_warn_pct"]:
            log.warning(f"⚠ High CPU usage: {cpu_stats['cpu_avg_pct']}% during scan")

        # ── Step 8: Assemble event ─────────────────────────────────────────────
        event = {
            "event_time":    datetime.utcnow().isoformat() + "Z",
            "mqtt_topic":    topic,
            "patient_id":    payload.get("patient_id", "UNKNOWN"),
            "patient_name":  payload.get("name", ""),
            "ward":          payload.get("ward", ""),
            "bed":           payload.get("bed", ""),
            "anomaly_score": round(score, 6),
            "if_prediction": prediction,
            "alert_level":   alert_level,
            "attack":        attack,
            "features": {
                k: round(v, 4) if isinstance(v, float) else v
                for k, v in features.items()
                if k in ALL_FEATURES
            },
            "cpu":          cpu_stats,
            "scan_ms":      scan_ms,
        }
        return event


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 7 — MQTT CALLBACKS
# ══════════════════════════════════════════════════════════════════════════════
def make_callbacks(engine: IDSEngine, alert_logger: AlertLogger):

    def on_connect(client, userdata, flags, rc):
        rc_msgs = {
            0: "Connected ✓",
            1: "Bad protocol version",
            2: "Invalid client ID",
            3: "Broker unavailable",
            4: "Bad credentials",
            5: "Not authorised",
        }
        msg = rc_msgs.get(rc, f"rc={rc}")
        if rc == 0:
            client.subscribe(CONFIG["topic"], qos=1)
            log.info(f"MQTT {msg} — subscribed to '{CONFIG['topic']}'")
        else:
            log.error(f"MQTT connection refused: {msg}")

    def on_disconnect(client, userdata, rc):
        if rc != 0:
            log.warning("MQTT unexpected disconnect — auto-reconnect in progress…")

    def on_message(client, userdata, msg):
        try:
            payload = json.loads(msg.payload.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            log.warning(f"[{msg.topic}] Malformed JSON: {e}")
            # Still log as an unrelated payload event
            alert_logger.write({
                "event_time":    datetime.utcnow().isoformat() + "Z",
                "mqtt_topic":    msg.topic,
                "patient_id":    "UNKNOWN",
                "patient_name":  "",
                "ward":          "",
                "bed":           "",
                "anomaly_score": None,
                "if_prediction": None,
                "alert_level":   "HIGH",
                "attack": {
                    "type":   "UNRELATED_PAYLOAD",
                    "reason": f"JSON decode error: {e}. Raw: {msg.payload[:120]}"
                },
                "features":  {},
                "cpu":       get_cpu_stats(),
                "scan_ms":   0,
            })
            return

        event = engine.infer(msg.topic, payload)
        if event:
            alert_logger.write(event)

    return on_connect, on_disconnect, on_message


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════
def main():
    log.info("╔══════════════════════════════════════════════════╗")
    log.info("║  Patient IDS — Isolation Forest Inference Engine ║")
    log.info("╚══════════════════════════════════════════════════╝")

    # ── Load model ────────────────────────────────────────────────────────────
    model, scaler, meta = load_artefacts(CONFIG)

    # ── Initialise engine and logger ──────────────────────────────────────────
    engine       = IDSEngine(model, scaler, meta, CONFIG)
    alert_logger = AlertLogger(CONFIG["alert_log"])

    # ── Build MQTT client ─────────────────────────────────────────────────────
    client = mqtt.Client(client_id=CONFIG["client_id"])
    if CONFIG["mqtt_username"]:
        client.username_pw_set(CONFIG["mqtt_username"], CONFIG["mqtt_password"])

    on_connect, on_disconnect, on_message = make_callbacks(engine, alert_logger)
    client.on_connect    = on_connect
    client.on_disconnect = on_disconnect
    client.on_message    = on_message

    # ── Graceful shutdown ─────────────────────────────────────────────────────
    def shutdown(sig, frame):
        log.info("Shutdown signal received…")
        client.loop_stop()
        client.disconnect()
        alert_logger.summary()
        log.info(f"Alert log saved to: {CONFIG['alert_log']}")
        sys.exit(0)

    signal.signal(signal.SIGINT,  shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # ── Warm up CPU percent baseline (psutil needs one call before monitoring) ─
    psutil.cpu_percent(interval=None)

    # ── Connect and run ───────────────────────────────────────────────────────
    log.info(f"Connecting to MQTT broker {CONFIG['broker_host']}:{CONFIG['broker_port']} …")
    client.connect(CONFIG["broker_host"], CONFIG["broker_port"], keepalive=CONFIG["keepalive"])

    log.info("IDS engine running — press Ctrl+C to stop\n")
    client.loop_forever()


if __name__ == "__main__":
    main()
