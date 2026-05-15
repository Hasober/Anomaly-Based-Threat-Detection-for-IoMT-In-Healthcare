#!/usr/bin/env python3
"""
Patient IDS — Graphical User Interface
========================================
A sleek, dark-themed GUI wrapping the Isolation Forest IDS engine.

Features:
  • Start / Stop IDS with one click
  • Live alert table with colour-coded severity rows
  • Per-attack-type counters and a running total
  • Source IP tracking — flags repeated offenders
  • CPU & RAM live gauges (sidebar)
  • Export logs as  JSON  |  CSV  |  XML  |  PDF
  • Settings panel — edit broker / model paths without restarting
  • Packages to a single Windows EXE via PyInstaller

Requirements (install once):
    pip install customtkinter pillow paho-mqtt joblib scikit-learn
                numpy pandas psutil reportlab pyinstaller

Build EXE (run in project folder after installing):
    pyinstaller --noconsole --onefile --name "PatientIDS" ids_gui.py

Author: generated for Hospital OS IDS project
"""

# ── Standard library ──────────────────────────────────────────────────────────
import csv
import json
import logging
import os
import queue
import re
import socket
import threading
import time
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox
import tkinter as tk
import tkinter.ttk as ttk

# ── Third-party ───────────────────────────────────────────────────────────────
try:
    import customtkinter as ctk
    CTK_AVAILABLE = True
except ImportError:
    CTK_AVAILABLE = False

try:
    import paho.mqtt.client as mqtt
    MQTT_AVAILABLE = True
except ImportError:
    MQTT_AVAILABLE = False

try:
    import joblib
    import numpy as np
    import pandas as pd
    from sklearn.ensemble import IsolationForest
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        SimpleDocTemplate, Table, TableStyle, Paragraph,
        Spacer, HRFlowable,
    )
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

# ─────────────────────────────────────────────────────────────────────────────
#  COLOUR PALETTE  (dark theme — works with both customtkinter & plain tkinter)
# ─────────────────────────────────────────────────────────────────────────────
PAL = {
    "bg":           "#0d1117",
    "surface":      "#161b22",
    "surface2":     "#21262d",
    "border":       "#30363d",
    "text":         "#e6edf3",
    "text_dim":     "#8b949e",
    "accent":       "#58a6ff",
    "accent_dim":   "#1f6feb",
    "green":        "#3fb950",
    "yellow":       "#d29922",
    "orange":       "#e3b341",
    "red":          "#f85149",
    "purple":       "#bc8cff",
    "clean_bg":     "#0d2b1a",
    "low_bg":       "#2b2100",
    "medium_bg":    "#2b1600",
    "high_bg":      "#2b0d0d",
    "btn_start":    "#238636",
    "btn_stop":     "#da3633",
    "btn_export":   "#1f6feb",
    "btn_hover":    "#388bfd",
}

SEVERITY_COLOURS = {
    "CLEAN":  {"fg": PAL["green"],  "bg": PAL["clean_bg"],  "tag": "clean"},
    "LOW":    {"fg": PAL["yellow"], "bg": PAL["low_bg"],    "tag": "low"},
    "MEDIUM": {"fg": PAL["orange"], "bg": PAL["medium_bg"], "tag": "medium"},
    "HIGH":   {"fg": PAL["red"],    "bg": PAL["high_bg"],   "tag": "high"},
}

ATTACK_ICONS = {
    "NONE":                "✅",
    "VITAL_SIGN_SPOOFING": "🎭",
    "DATA_EXFILTRATION":   "📤",
    "UNAUTHORIZED_ACCESS": "🚫",
    "BRUTE_FORCE":         "💥",
    "REPLAY_ATTACK":       "🔁",
    "UNRELATED_PAYLOAD":   "❓",
}

# ─────────────────────────────────────────────────────────────────────────────
#  DEFAULT CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
DEFAULT_CONFIG = {
    "broker_host":      "192.168.1.100",
    "broker_port":      1883,
    "topic":            "hospital/patients/#",
    "client_id":        "patient-ids-gui",
    "mqtt_username":    "",
    "mqtt_password":    "",
    "keepalive":        60,
    "model_path":       r"C:\patient_data\models\patient_ids_model.pkl",
    "scaler_path":      r"C:\patient_data\models\patient_ids_scaler.pkl",
    "meta_path":        r"C:\patient_data\models\patient_ids_meta.json",
    "alert_log":        r"C:\patient_data\ids_alerts.jsonl",
    "threshold_low":    -0.05,
    "threshold_medium": -0.15,
    "threshold_high":   -0.30,
    "cpu_warn_pct":     80.0,
}

# ─────────────────────────────────────────────────────────────────────────────
#  IDS ENGINE  (identical logic to patient_ids.py — self-contained here)
# ─────────────────────────────────────────────────────────────────────────────
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

BOUNDS = {
    "age":                  (0,   120),
    "bp_systolic_mmhg":     (50,  260),
    "bp_diastolic_mmhg":    (30,  160),
    "heart_rate_bpm":       (20,  250),
    "spo2_percent":         (50,  100),
    "respiratory_rate_bpm": (4,   60),
    "temperature_celsius":  (33,  43),
    "blood_glucose_mgdl":   (20,  600),
    "pain_scale":           (0,   10),
}

ATTACK_DESCRIPTIONS = {
    "NONE":                "Normal reading — no threat detected.",
    "VITAL_SIGN_SPOOFING": "Vital signs contain physiologically impossible values. A device may be sending fabricated data.",
    "DATA_EXFILTRATION":   "Payload contains unexpected hidden fields. Sensitive data may be leaking through this channel.",
    "UNAUTHORIZED_ACCESS": "Message received from an unrecognised device or patient ID. A rogue publisher may be active.",
    "BRUTE_FORCE":         "Abnormally high message volume detected. The broker may be under a flood or brute-force attack.",
    "REPLAY_ATTACK":       "This reading matches a previously captured message pattern. Possible replay attack in progress.",
    "UNRELATED_PAYLOAD":   "Received a message that does not look like patient data. A foreign device is publishing here.",
}


def _safe_float(val, default=0.0):
    try:
        v = float(val)
        return v if (v == v) else default   # NaN check
    except (TypeError, ValueError):
        return default


def engineer_features(payload: dict):
    vitals = payload.get("vitals", {})
    bp     = vitals.get("blood_pressure", {})

    raw = {
        "age":                  _safe_float(payload.get("age")),
        "bp_systolic_mmhg":     _safe_float(bp.get("systolic_mmhg")),
        "bp_diastolic_mmhg":    _safe_float(bp.get("diastolic_mmhg")),
        "heart_rate_bpm":       _safe_float(vitals.get("heart_rate_bpm")),
        "spo2_percent":         _safe_float(vitals.get("spo2_percent")),
        "respiratory_rate_bpm": _safe_float(vitals.get("respiratory_rate_bpm")),
        "temperature_celsius":  _safe_float(vitals.get("temperature_celsius")),
        "blood_glucose_mgdl":   _safe_float(vitals.get("blood_glucose_mgdl")),
        "pain_scale":           _safe_float(vitals.get("pain_scale")),
        "ward":                 payload.get("ward", "General"),
        "ecg_rhythm":           vitals.get("ecg_rhythm", "Normal Sinus"),
        "consciousness":        vitals.get("consciousness", "Alert"),
        "gender":               payload.get("gender", "Male"),
    }

    core = ["bp_systolic_mmhg", "bp_diastolic_mmhg", "heart_rate_bpm", "spo2_percent"]
    for col in core:
        lo, hi = BOUNDS[col]
        if not (lo <= raw[col] <= hi):
            return None

    for col, (lo, hi) in BOUNDS.items():
        if col in raw:
            raw[col] = max(lo, min(hi, raw[col]))

    pp    = raw["bp_systolic_mmhg"] - raw["bp_diastolic_mmhg"]
    map_v = raw["bp_diastolic_mmhg"] + pp / 3
    si    = raw["heart_rate_bpm"] / raw["bp_systolic_mmhg"] if raw["bp_systolic_mmhg"] else 0.0
    bmi   = np.log1p(raw["age"]) * (raw["blood_glucose_mgdl"] / 100) if ML_AVAILABLE else 0.0

    return {
        **{k: raw[k] for k in NUMERIC_FEATURES[:9]},
        "pulse_pressure":          pp,
        "mean_arterial_pressure":  map_v,
        "shock_index":             si,
        "bmi_proxy":               bmi,
        "ward_encoded":            float(WARD_ORDER.index(raw["ward"]) if raw["ward"] in WARD_ORDER else 4),
        "ecg_encoded":             float(ECG_ORDER.index(raw["ecg_rhythm"]) if raw["ecg_rhythm"] in ECG_ORDER else 0),
        "consciousness_encoded":   float(CON_ORDER.index(raw["consciousness"]) if raw["consciousness"] in CON_ORDER else 0),
        "gender_encoded":          float(GENDER_MAP.get(raw["gender"], 0)),
    }


def classify_alert(score: float, cfg: dict) -> str:
    if score > cfg["threshold_low"]:
        return "CLEAN"
    elif score > cfg["threshold_medium"]:
        return "LOW"
    elif score > cfg["threshold_high"]:
        return "MEDIUM"
    return "HIGH"


def classify_attack(score, features, payload, alert_level, cfg) -> dict:
    if alert_level == "CLEAN":
        return {"type": "NONE", "reason": "Score within normal baseline"}

    vitals     = payload.get("vitals", {})
    patient_id = payload.get("patient_id", "")

    expected_keys = {"patient_id", "vitals", "timestamp", "ward"}
    if expected_keys - set(payload.keys()):
        return {"type": "UNRELATED_PAYLOAD",
                "reason": f"Missing fields: {sorted(expected_keys - set(payload.keys()))}"}

    bp_sys  = features.get("bp_systolic_mmhg", 120)
    bp_dia  = features.get("bp_diastolic_mmhg", 80)
    hr      = features.get("heart_rate_bpm", 75)
    spo2    = features.get("spo2_percent", 98)
    temp    = features.get("temperature_celsius", 37)
    rr      = features.get("respiratory_rate_bpm", 16)
    glucose = features.get("blood_glucose_mgdl", 100)
    si      = features.get("shock_index", 0.6)
    pp      = features.get("pulse_pressure", 40)

    spoof = []
    if bp_sys <= bp_dia:                spoof.append(f"systolic({bp_sys}) ≤ diastolic({bp_dia})")
    if pp > 100:                        spoof.append(f"pulse pressure {pp:.0f} mmHg")
    if si > 1.5:                        spoof.append(f"shock index {si:.2f}")
    if spo2 < 85 and hr < 40:          spoof.append(f"SpO2={spo2}% with HR={hr}bpm")
    if temp > 41 and rr < 8:           spoof.append(f"temp={temp}°C with RR={rr}")
    if glucose > 400 and spo2 > 99:    spoof.append(f"glucose={glucose} with SpO2={spo2}%")
    if spoof:
        return {"type": "VITAL_SIGN_SPOOFING", "reason": "; ".join(spoof)}

    expected_vitals = {
        "blood_pressure","heart_rate_bpm","spo2_percent","respiratory_rate_bpm",
        "temperature_celsius","blood_glucose_mgdl","ecg_rhythm","pain_scale","consciousness"
    }
    extra = list(set(vitals.keys()) - expected_vitals) + \
            list(set(payload.keys()) - {"timestamp","patient_id","name","age","gender","ward","bed","vitals"})
    if extra:
        return {"type": "DATA_EXFILTRATION", "reason": f"Unexpected fields: {extra}"}

    if not re.match(r"^P\d{3}$", str(patient_id)):
        return {"type": "UNAUTHORIZED_ACCESS", "reason": f"Invalid patient ID '{patient_id}'"}

    if score < cfg["threshold_high"] - 0.15:
        return {"type": "BRUTE_FORCE", "reason": f"Score {score:.4f} far below HIGH threshold"}

    return {"type": "REPLAY_ATTACK",
            "reason": f"Score {score:.4f} anomalous but vitals individually plausible"}




# ─────────────────────────────────────────────────────────────────────────────
#  RULE-BASED DETECTION ENGINE
#  Runs BEFORE the Isolation Forest model.
#  Catches threats the model cannot learn (content-based, not statistical).
#  Returns a verdict dict  or  None (meaning "let the model decide").
# ─────────────────────────────────────────────────────────────────────────────

# ── Signature databases ───────────────────────────────────────────────────────

# Path traversal patterns
PATH_TRAVERSAL = re.compile(
    r'(\.\.|%2e%2e|%252e|%c0%ae|\.\./)|(etc/passwd|etc/shadow|'
    r'windows/system32|win\.ini|boot\.ini|proc/self)',
    re.IGNORECASE
)

# SQL injection patterns
SQL_INJECTION = re.compile(
    r"('\s*(or|and)\s*[\'\"\d])|"
    r"(--\s*$)|(;\s*drop\s+table)|(union\s+select)|"
    r"(insert\s+into)|(exec\s*\()|(xp_cmdshell)|(benchmark\s*\()",
    re.IGNORECASE
)

# Shell / command injection patterns
CMD_INJECTION = re.compile(
    r"(&&|\|\||`;|`\$|\$\(|\bexec\b|\beval\b|"
    r"\bcurl\b|\bwget\b|\bnc\b|\bnmap\b|"
    r"powershell|cmd\.exe|/bin/sh|/bin/bash)",
    re.IGNORECASE
)

# XSS patterns
XSS_PATTERNS = re.compile(
    r"(<script|javascript:|on\w+=|alert\(|document\.cookie|"
    r"<iframe|<img\s+src\s*=\s*[\"\']?javascript)",
    re.IGNORECASE
)

# Known malicious / reserved identifiers
RESERVED_IDS = {
    "admin", "root", "administrator", "system", "guest",
    "null", "undefined", "test", "debug", "superuser",
    "sa", "oracle", "postgres", "mysql", "unknown",
}

# Suspicious field names that should never appear in medical IoT
MALICIOUS_FIELD_NAMES = re.compile(
    r"(password|passwd|secret|token|api_key|auth|credential|"
    r"private_key|ssh_key|db_conn|database|connection_string|"
    r"cmd|exec|shell|command|script|eval|payload|beacon|c2|"
    r"exfil|backdoor|malware|exploit|inject|bypass|override|"
    r"ssn|social_security|insurance_id|credit_card|cvv|pin)",
    re.IGNORECASE
)

# IP address formats to check (rogue MQTT publisher IPs)
PRIVATE_RANGES = re.compile(
    r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)"
)

# Valid patient ID format — strictly P001 through P020
VALID_PATIENT_RE = re.compile(r"^P0(0[1-9]|1[0-9]|20)$")  # P001–P020 only

# Known legitimate ward / ECG values
VALID_WARDS = {"ICU", "Cardiology", "Neurology", "Orthopedics", "General"}
VALID_ECG   = {"Normal Sinus", "Sinus Bradycardia", "Sinus Tachycardia", "AFib"}
VALID_CONSCIOUSNESS = {"Alert", "Drowsy", "Confused", "Unconscious"}
VALID_GENDERS = {"Male", "Female"}


def _scan_string(value: str) -> str | None:
    """Scan a single string value for attack signatures. Returns match or None."""
    s = str(value)
    if PATH_TRAVERSAL.search(s): return f"path traversal: {s[:60]}"
    if SQL_INJECTION.search(s):  return f"SQL injection: {s[:60]}"
    if CMD_INJECTION.search(s):  return f"command injection: {s[:60]}"
    if XSS_PATTERNS.search(s):   return f"XSS attempt: {s[:60]}"
    return None


def _scan_keys(d: dict, prefix: str = "") -> str | None:
    """Recursively scan all field NAMES in a dict for malicious names."""
    for k in d.keys():
        full_key = f"{prefix}.{k}" if prefix else k
        if MALICIOUS_FIELD_NAMES.search(str(k)):
            return f"suspicious field name '{full_key}'"
        if isinstance(d[k], dict):
            result = _scan_keys(d[k], full_key)
            if result:
                return result
    return None


def _scan_values(d: dict, depth: int = 0) -> str | None:
    """Recursively scan all string VALUES in a dict for attack signatures."""
    if depth > 4:
        return None
    for k, v in d.items():
        if isinstance(v, str):
            hit = _scan_string(v)
            if hit:
                return f"field '{k}': {hit}"
        elif isinstance(v, dict):
            hit = _scan_values(v, depth + 1)
            if hit:
                return hit
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, str):
                    hit = _scan_string(item)
                    if hit:
                        return f"field '{k}[]': {hit}"
    return None


class RuleEngine:
    """
    Deterministic signature-based detection layer.
    Evaluates every payload against hard rules BEFORE the Isolation Forest.

    Rule priority (first match wins):
      1.  Structural integrity   — missing required fields
      2.  Patient ID validation  — format, reserved words, injection attempts
      3.  Field name scanning    — malicious / unexpected field names
      4.  Value scanning         — injection signatures in all string values
      5.  Topic integrity        — topic path matches patient ID
      6.  Ward / enum validation — values outside known-good sets
      7.  Payload size           — abnormally large payloads
      8.  Brute-force rate       — per-IP and per-patient message rate tracking
    """

    # Required top-level fields every legitimate payload must have
    REQUIRED_FIELDS = {"patient_id", "vitals", "timestamp", "ward"}
    REQUIRED_VITALS = {
        "blood_pressure", "heart_rate_bpm", "spo2_percent",
        "respiratory_rate_bpm", "temperature_celsius",
        "blood_glucose_mgdl", "ecg_rhythm", "pain_scale", "consciousness"
    }
    ALLOWED_ROOT_FIELDS = {
        "timestamp","patient_id","name","age","gender","ward","bed","vitals","_source_ip"
    }
    ALLOWED_VITAL_FIELDS = REQUIRED_VITALS | {"blood_pressure"}

    # Rate limiting: flag if same IP sends > N messages in T seconds
    RATE_LIMIT_COUNT   = 15
    RATE_LIMIT_WINDOW  = 3.0   # seconds

    def __init__(self):
        # {ip: [timestamp, ...]}
        self._ip_timestamps     = defaultdict(list)
        # {patient_id: [timestamp, ...]}
        self._patient_timestamps = defaultdict(list)
        self._lock = threading.Lock()

    def check(self, payload: dict, topic: str, source_ip: str) -> dict | None:
        """
        Run all rules. Returns a verdict dict  {"alert_level", "attack"}
        if a rule fires, or None if the payload should proceed to the model.
        """
        now = time.time()

        # ── Rule 1: Structural integrity ─────────────────────────────────────
        missing = self.REQUIRED_FIELDS - set(payload.keys())
        if missing:
            return self._verdict("HIGH", "UNRELATED_PAYLOAD",
                f"Missing required fields: {sorted(missing)}")

        vitals = payload.get("vitals", {})
        if not isinstance(vitals, dict):
            return self._verdict("HIGH", "UNRELATED_PAYLOAD",
                "Field \'vitals\' is not a JSON object")

        # ── Rule 2: Patient ID validation ─────────────────────────────────────
        pid = str(payload.get("patient_id", ""))

        # Scan for injection signatures first (catches ../../etc/passwd, SQL, etc.)
        hit = _scan_string(pid)
        if hit:
            return self._verdict("HIGH", "UNAUTHORIZED_ACCESS",
                f"Attack signature in patient_id — {hit}")

        # Check for reserved system identifiers
        if pid.lower() in RESERVED_IDS:
            return self._verdict("HIGH", "UNAUTHORIZED_ACCESS",
                f"Reserved/system identifier used as patient_id: '{pid}'")

        # Strict format check: must be P001–P020
        if not VALID_PATIENT_RE.match(pid):
            return self._verdict("HIGH", "UNAUTHORIZED_ACCESS",
                f"Patient ID '{pid}' does not match valid format P001–P020")

        # Topic / ID consistency check
        if pid not in topic:
            return self._verdict("MEDIUM", "UNAUTHORIZED_ACCESS",
                f"Topic '{topic}' does not match patient_id '{pid}' — possible spoofing")

        # ── Rule 3: Field name scanning ───────────────────────────────────────
        hit = _scan_keys(payload)
        if hit:
            return self._verdict("HIGH", "DATA_EXFILTRATION",
                f"Malicious field name detected: {hit}")

        # Unexpected root-level fields
        extra_root = set(payload.keys()) - self.ALLOWED_ROOT_FIELDS
        if extra_root:
            return self._verdict("HIGH", "DATA_EXFILTRATION",
                f"Unexpected root fields (possible data injection): {sorted(extra_root)}")

        # Unexpected vitals fields
        extra_vitals = set(vitals.keys()) - self.ALLOWED_VITAL_FIELDS
        if extra_vitals:
            return self._verdict("HIGH", "DATA_EXFILTRATION",
                f"Unexpected vitals fields (possible hidden payload): {sorted(extra_vitals)}")

        # ── Rule 4: Value injection scanning ─────────────────────────────────
        hit = _scan_values(payload)
        if hit:
            # Determine most likely attack type from the hit description
            atype = "UNAUTHORIZED_ACCESS"
            if "injection" in hit or "traversal" in hit or "XSS" in hit:
                atype = "UNAUTHORIZED_ACCESS"
            if "field" in hit and ("secret" in hit or "password" in hit or "key" in hit):
                atype = "DATA_EXFILTRATION"
            return self._verdict("HIGH", atype,
                f"Attack signature found in payload value — {hit}")

        # ── Rule 5: Enum / domain validation ─────────────────────────────────
        ward = payload.get("ward", "")
        if ward and ward not in VALID_WARDS:
            return self._verdict("MEDIUM", "UNAUTHORIZED_ACCESS",
                f"Unknown ward value '{ward}' — not in recognised set {VALID_WARDS}")

        ecg = vitals.get("ecg_rhythm", "")
        if ecg and ecg not in VALID_ECG:
            return self._verdict("LOW", "VITAL_SIGN_SPOOFING",
                f"Unknown ECG rhythm '{ecg}' — not in recognised set")

        con = vitals.get("consciousness", "")
        if con and con not in VALID_CONSCIOUSNESS:
            return self._verdict("LOW", "VITAL_SIGN_SPOOFING",
                f"Unknown consciousness value '{con}' — not in recognised set")

        gender = payload.get("gender", "")
        if gender and gender not in VALID_GENDERS:
            return self._verdict("LOW", "UNAUTHORIZED_ACCESS",
                f"Unexpected gender value '{gender}'")

        # ── Rule 6: Payload size anomaly ──────────────────────────────────────
        raw_size = len(json.dumps(payload))
        if raw_size > 4096:
            return self._verdict("MEDIUM", "DATA_EXFILTRATION",
                f"Payload size {raw_size} bytes far exceeds normal (~400 bytes) — "
                "possible data stuffing or exfiltration attempt")

        # ── Rule 7: Rate limiting (brute-force / flood detection) ─────────────
        with self._lock:
            # IP-level rate check
            ip_ts = self._ip_timestamps[source_ip]
            ip_ts.append(now)
            self._ip_timestamps[source_ip] = [
                t for t in ip_ts if now - t <= self.RATE_LIMIT_WINDOW]
            if len(self._ip_timestamps[source_ip]) > self.RATE_LIMIT_COUNT:
                return self._verdict("HIGH", "BRUTE_FORCE",
                    f"IP {source_ip} sent {len(self._ip_timestamps[source_ip])} messages "
                    f"in {self.RATE_LIMIT_WINDOW}s (limit: {self.RATE_LIMIT_COUNT})")

            # Per-patient rate check (protect against targeted patient floods)
            pt_ts = self._patient_timestamps[pid]
            pt_ts.append(now)
            self._patient_timestamps[pid] = [
                t for t in pt_ts if now - t <= self.RATE_LIMIT_WINDOW]
            if len(self._patient_timestamps[pid]) > self.RATE_LIMIT_COUNT:
                return self._verdict("HIGH", "BRUTE_FORCE",
                    f"Patient {pid} received {len(self._patient_timestamps[pid])} messages "
                    f"in {self.RATE_LIMIT_WINDOW}s — targeted flood attack")

        # ── All rules passed — let the model decide ───────────────────────────
        return None

    @staticmethod
    def _verdict(alert_level: str, attack_type: str, reason: str) -> dict:
        return {
            "alert_level": alert_level,
            "attack": {
                "type":   attack_type,
                "reason": reason,
                "source": "RULE_ENGINE",   # marks that model was bypassed
            }
        }

# ─────────────────────────────────────────────────────────────────────────────
#  EXPORT HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def export_json(events: list, path: str):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(events, f, indent=2, default=str)


def export_csv(events: list, path: str):
    if not events:
        return
    cols = ["event_time", "patient_id", "patient_name", "ward", "bed",
            "alert_level", "attack_type", "attack_reason",
            "anomaly_score", "source_ip",
            "cpu_avg_pct", "mem_used_pct", "scan_ms"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for e in events:
            row = {
                "event_time":    e.get("event_time", ""),
                "patient_id":    e.get("patient_id", ""),
                "patient_name":  e.get("patient_name", ""),
                "ward":          e.get("ward", ""),
                "bed":           e.get("bed", ""),
                "alert_level":   e.get("alert_level", ""),
                "attack_type":   e.get("attack", {}).get("type", ""),
                "attack_reason": e.get("attack", {}).get("reason", ""),
                "anomaly_score": e.get("anomaly_score", ""),
                "source_ip":     e.get("source_ip", ""),
                "cpu_avg_pct":   e.get("cpu", {}).get("cpu_avg_pct", ""),
                "mem_used_pct":  e.get("cpu", {}).get("mem_used_pct", ""),
                "scan_ms":       e.get("scan_ms", ""),
            }
            w.writerow(row)


def export_xml(events: list, path: str):
    root = ET.Element("IDSAlertLog", generated=datetime.now(timezone.utc).isoformat())
    for e in events:
        ev = ET.SubElement(root, "Event")
        for key in ["event_time", "patient_id", "patient_name", "ward", "bed",
                    "alert_level", "anomaly_score", "source_ip", "scan_ms"]:
            child = ET.SubElement(ev, key)
            child.text = str(e.get(key, ""))
        atk = ET.SubElement(ev, "Attack")
        atk.set("type", e.get("attack", {}).get("type", ""))
        atk.text = e.get("attack", {}).get("reason", "")
        cpu_el = ET.SubElement(ev, "CPU")
        cpu_el.set("avg_pct", str(e.get("cpu", {}).get("cpu_avg_pct", "")))
        cpu_el.set("mem_pct", str(e.get("cpu", {}).get("mem_used_pct", "")))
    tree = ET.ElementTree(root)
    ET.indent(tree, space="  ")
    tree.write(path, encoding="utf-8", xml_declaration=True)


def export_pdf(events: list, path: str):
    if not REPORTLAB_AVAILABLE:
        raise ImportError("reportlab not installed — run: pip install reportlab")

    doc = SimpleDocTemplate(path, pagesize=A4,
                            leftMargin=1.5*cm, rightMargin=1.5*cm,
                            topMargin=2*cm,    bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    story  = []

    # Title
    title_style = ParagraphStyle("Title", parent=styles["Title"],
                                 textColor=colors.HexColor("#1f3864"),
                                 fontSize=18, spaceAfter=6)
    sub_style   = ParagraphStyle("Sub", parent=styles["Normal"],
                                 textColor=colors.HexColor("#666666"),
                                 fontSize=9,  spaceAfter=12)

    story.append(Paragraph("Patient IDS — Alert Log Export", title_style))
    story.append(Paragraph(
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}   |   "
        f"Total events: {len(events)}", sub_style))
    story.append(HRFlowable(width="100%", thickness=1,
                             color=colors.HexColor("#cccccc"), spaceAfter=12))

    # Summary counts
    counts = defaultdict(int)
    for e in events:
        counts[e.get("alert_level", "UNKNOWN")] += 1

    summary_data = [["Severity", "Count"]]
    colour_map = {"HIGH": "#f85149", "MEDIUM": "#e3b341",
                  "LOW": "#d29922", "CLEAN": "#3fb950"}
    for level in ["HIGH", "MEDIUM", "LOW", "CLEAN"]:
        summary_data.append([level, str(counts.get(level, 0))])

    sum_table = Table(summary_data, colWidths=[5*cm, 3*cm])
    sum_style = TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0), colors.HexColor("#1f3864")),
        ("TEXTCOLOR",   (0, 0), (-1, 0), colors.white),
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 9),
        ("ALIGN",       (0, 0), (-1, -1), "CENTER"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.HexColor("#f5f5f5"), colors.white]),
        ("GRID",        (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("TOPPADDING",  (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",(0,0), (-1, -1), 4),
    ])
    sum_table.setStyle(sum_style)
    story.append(sum_table)
    story.append(Spacer(1, 0.5*cm))

    # Events table
    headers = ["Time", "Patient", "Ward", "Severity", "Attack Type", "Source IP", "Score"]
    table_data = [headers]

    sev_colours = {
        "HIGH":   colors.HexColor("#ffd7d5"),
        "MEDIUM": colors.HexColor("#fff3cd"),
        "LOW":    colors.HexColor("#fff9c4"),
        "CLEAN":  colors.HexColor("#d4edda"),
    }

    row_styles = []
    for i, e in enumerate(events, start=1):
        level = e.get("alert_level", "")
        ts    = e.get("event_time", "")[:19].replace("T", " ")
        row   = [
            ts,
            f"{e.get('patient_id','')} {e.get('patient_name','')}",
            e.get("ward", ""),
            level,
            e.get("attack", {}).get("type", ""),
            e.get("source_ip", "N/A"),
            str(e.get("anomaly_score", "")),
        ]
        table_data.append(row)
        bg = sev_colours.get(level, colors.white)
        row_styles.append(("BACKGROUND", (0, i), (-1, i), bg))

    col_widths = [3*cm, 4*cm, 2.5*cm, 2*cm, 4*cm, 2.5*cm, 2*cm]
    ev_table = Table(table_data, colWidths=col_widths, repeatRows=1)
    base_style = TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0), colors.HexColor("#1f3864")),
        ("TEXTCOLOR",    (0, 0), (-1, 0), colors.white),
        ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, -1), 7),
        ("ALIGN",        (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ("GRID",         (0, 0), (-1, -1), 0.3, colors.HexColor("#cccccc")),
        ("TOPPADDING",   (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 3),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, colors.HexColor("#f9f9f9")]),
    ])
    for rs in row_styles:
        base_style.add(*rs)
    ev_table.setStyle(base_style)
    story.append(ev_table)

    doc.build(story)


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN GUI APPLICATION
# ─────────────────────────────────────────────────────────────────────────────
class IDSApp(tk.Tk):
    """
    Main application window.  Uses plain tkinter + ttk so it works without
    customtkinter installed, but applies a full dark theme manually.
    """

    def __init__(self):
        super().__init__()

        self.title("Patient IDS  —  Isolation Forest Intrusion Detection")
        self.geometry("1400x860")
        self.minsize(1100, 700)
        self.configure(bg=PAL["bg"])
        self._set_dark_ttk_theme()

        # ── State ─────────────────────────────────────────────────────────────
        self.config      = dict(DEFAULT_CONFIG)
        self.events      = []          # all events accumulated this session
        self.event_queue = queue.Queue()
        self.ids_running = False
        self.mqtt_client = None
        self.model       = None
        self.scaler      = None
        self.meta        = None
        self.cpu_monitor = None

        # Rule-based detection engine (runs before model)
        self.rule_engine = RuleEngine()

        # IP tracking  {ip: count_of_flagged_messages}
        self.ip_counts   = defaultdict(int)
        self.flagged_ips = set()

        # Alert counters
        self.counters = {"CLEAN": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0}

        # ── Build UI ──────────────────────────────────────────────────────────
        self._build_header()
        self._build_body()
        self._build_statusbar()

        # ── Poll the event queue from MQTT thread ─────────────────────────────
        self._poll_queue()

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ══════════════════════════════════════════════════════════════════════════
    #  THEME
    # ══════════════════════════════════════════════════════════════════════════
    def _set_dark_ttk_theme(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure(".",
            background=PAL["bg"], foreground=PAL["text"],
            fieldbackground=PAL["surface2"], bordercolor=PAL["border"],
            darkcolor=PAL["bg"], lightcolor=PAL["surface"],
            troughcolor=PAL["surface"], selectbackground=PAL["accent_dim"],
            selectforeground=PAL["text"], font=("Segoe UI", 9))

        style.configure("Treeview",
            background=PAL["surface"], foreground=PAL["text"],
            fieldbackground=PAL["surface"], rowheight=28,
            borderwidth=0, font=("Segoe UI", 9))
        style.configure("Treeview.Heading",
            background=PAL["surface2"], foreground=PAL["text"],
            font=("Segoe UI", 9, "bold"), relief="flat")
        style.map("Treeview",
            background=[("selected", PAL["accent_dim"])],
            foreground=[("selected", PAL["text"])])

        style.configure("TScrollbar",
            background=PAL["surface2"], troughcolor=PAL["surface"],
            arrowcolor=PAL["text_dim"], bordercolor=PAL["border"])

        style.configure("TNotebook",
            background=PAL["bg"], borderwidth=0)
        style.configure("TNotebook.Tab",
            background=PAL["surface2"], foreground=PAL["text_dim"],
            padding=[12, 6], font=("Segoe UI", 9))
        style.map("TNotebook.Tab",
            background=[("selected", PAL["surface"])],
            foreground=[("selected", PAL["accent"])])

        style.configure("TFrame", background=PAL["bg"])
        style.configure("TLabel",
            background=PAL["bg"], foreground=PAL["text"],
            font=("Segoe UI", 9))
        style.configure("TEntry",
            fieldbackground=PAL["surface2"], foreground=PAL["text"],
            insertcolor=PAL["text"], bordercolor=PAL["border"])
        style.configure("TCombobox",
            fieldbackground=PAL["surface2"], foreground=PAL["text"],
            background=PAL["surface2"])

    # ══════════════════════════════════════════════════════════════════════════
    #  HEADER BAR
    # ══════════════════════════════════════════════════════════════════════════
    def _build_header(self):
        hdr = tk.Frame(self, bg=PAL["surface"], height=64)
        hdr.pack(fill="x", side="top")
        hdr.pack_propagate(False)

        # Logo / title
        tk.Label(hdr, text="🛡  Patient IDS",
                 font=("Segoe UI", 16, "bold"),
                 bg=PAL["surface"], fg=PAL["accent"]).pack(side="left", padx=20, pady=14)
        tk.Label(hdr, text="Isolation Forest  •  Real-Time MQTT Monitor",
                 font=("Segoe UI", 9), bg=PAL["surface"],
                 fg=PAL["text_dim"]).pack(side="left", padx=0, pady=14)

        # Right-side control buttons
        btn_frame = tk.Frame(hdr, bg=PAL["surface"])
        btn_frame.pack(side="right", padx=16, pady=10)

        self.btn_start = self._make_button(
            btn_frame, "▶  Start IDS", PAL["btn_start"],
            self._start_ids, width=14)
        self.btn_start.pack(side="left", padx=4)

        self.btn_stop = self._make_button(
            btn_frame, "⏹  Stop IDS", PAL["btn_stop"],
            self._stop_ids, width=14, state="disabled")
        self.btn_stop.pack(side="left", padx=4)

        self._make_button(
            btn_frame, "⚙  Settings", PAL["surface2"],
            self._open_settings, width=12).pack(side="left", padx=4)

        # Status pill
        self.status_pill = tk.Label(
            btn_frame, text="● OFFLINE", font=("Segoe UI", 9, "bold"),
            bg=PAL["surface"], fg=PAL["text_dim"], padx=10)
        self.status_pill.pack(side="left", padx=8)

    # ══════════════════════════════════════════════════════════════════════════
    #  BODY (sidebar + notebook)
    # ══════════════════════════════════════════════════════════════════════════
    def _build_body(self):
        body = tk.Frame(self, bg=PAL["bg"])
        body.pack(fill="both", expand=True, padx=0, pady=0)

        # ── Left sidebar ──────────────────────────────────────────────────────
        sidebar = tk.Frame(body, bg=PAL["surface"], width=220)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        self._build_sidebar(sidebar)

        # ── Right content area (notebook) ─────────────────────────────────────
        content = tk.Frame(body, bg=PAL["bg"])
        content.pack(side="left", fill="both", expand=True)
        self._build_notebook(content)

    # ── Sidebar ───────────────────────────────────────────────────────────────
    def _build_sidebar(self, parent):
        # Section: Alert Counts
        self._sidebar_section(parent, "ALERT SUMMARY")

        self.count_labels = {}
        for level, cfg in SEVERITY_COLOURS.items():
            row = tk.Frame(parent, bg=PAL["surface"])
            row.pack(fill="x", padx=12, pady=2)
            tk.Label(row, text=level, font=("Segoe UI", 9, "bold"),
                     bg=PAL["surface"], fg=cfg["fg"], width=10,
                     anchor="w").pack(side="left")
            lbl = tk.Label(row, text="0", font=("Consolas", 11, "bold"),
                           bg=PAL["surface"], fg=cfg["fg"], width=5,
                           anchor="e")
            lbl.pack(side="right")
            self.count_labels[level] = lbl

        self._sidebar_divider(parent)
        self._sidebar_section(parent, "SYSTEM RESOURCES")

        # CPU gauge
        tk.Label(parent, text="CPU Usage", font=("Segoe UI", 8),
                 bg=PAL["surface"], fg=PAL["text_dim"]).pack(anchor="w", padx=12, pady=(4,0))
        self.cpu_bar = self._make_gauge(parent)
        self.cpu_lbl = tk.Label(parent, text="0.0%",
                                font=("Consolas", 10, "bold"),
                                bg=PAL["surface"], fg=PAL["text"])
        self.cpu_lbl.pack(anchor="e", padx=14)

        # RAM gauge
        tk.Label(parent, text="RAM Usage", font=("Segoe UI", 8),
                 bg=PAL["surface"], fg=PAL["text_dim"]).pack(anchor="w", padx=12, pady=(6,0))
        self.ram_bar = self._make_gauge(parent)
        self.ram_lbl = tk.Label(parent, text="0.0%",
                                font=("Consolas", 10, "bold"),
                                bg=PAL["surface"], fg=PAL["text"])
        self.ram_lbl.pack(anchor="e", padx=14)

        self._sidebar_divider(parent)
        self._sidebar_section(parent, "EXPORT LOGS")

        for fmt, cmd in [
            ("📄  Export JSON", lambda: self._export("json")),
            ("📊  Export CSV",  lambda: self._export("csv")),
            ("🗂️   Export XML",  lambda: self._export("xml")),
            ("📑  Export PDF",  lambda: self._export("pdf")),
        ]:
            self._make_button(parent, fmt, PAL["btn_export"],
                              cmd, width=22, pady=3).pack(padx=12, pady=3, fill="x")

        self._sidebar_divider(parent)
        self._sidebar_section(parent, "FLAGGED IPs")
        self.ip_listbox = tk.Listbox(
            parent, bg=PAL["surface2"], fg=PAL["red"],
            selectbackground=PAL["accent_dim"], borderwidth=0,
            highlightthickness=0, font=("Consolas", 9), height=6)
        self.ip_listbox.pack(fill="x", padx=12, pady=4)

    def _sidebar_section(self, parent, title):
        tk.Label(parent, text=title,
                 font=("Segoe UI", 8, "bold"),
                 bg=PAL["surface"], fg=PAL["text_dim"],
                 anchor="w").pack(fill="x", padx=12, pady=(10, 2))

    def _sidebar_divider(self, parent):
        tk.Frame(parent, bg=PAL["border"], height=1).pack(
            fill="x", padx=12, pady=6)

    def _make_gauge(self, parent) -> tk.Canvas:
        c = tk.Canvas(parent, height=8, bg=PAL["surface2"],
                      highlightthickness=0, bd=0)
        c.pack(fill="x", padx=12, pady=2)
        c.create_rectangle(0, 0, 0, 8, fill=PAL["accent"], tags="bar",
                           outline="")
        return c

    def _update_gauge(self, canvas: tk.Canvas, label: tk.Label,
                      pct: float, warn=80.0):
        canvas.update_idletasks()
        w = canvas.winfo_width()
        fill_w = int(w * min(pct, 100) / 100)
        colour  = PAL["red"] if pct >= warn else PAL["green"] if pct < 50 else PAL["yellow"]
        canvas.coords("bar", 0, 0, fill_w, 8)
        canvas.itemconfig("bar", fill=colour)
        label.config(text=f"{pct:.1f}%", fg=colour)

    # ── Notebook tabs ─────────────────────────────────────────────────────────
    def _build_notebook(self, parent):
        nb = ttk.Notebook(parent)
        nb.pack(fill="both", expand=True, padx=8, pady=8)

        # Tab 1: Live Alerts
        tab1 = tk.Frame(nb, bg=PAL["bg"])
        nb.add(tab1, text="  🚨 Live Alerts  ")
        self._build_alerts_tab(tab1)

        # Tab 2: Flagged IPs detail
        tab2 = tk.Frame(nb, bg=PAL["bg"])
        nb.add(tab2, text="  🌐 IP Tracker  ")
        self._build_ip_tab(tab2)

        # Tab 3: System log
        tab3 = tk.Frame(nb, bg=PAL["bg"])
        nb.add(tab3, text="  📋 System Log  ")
        self._build_log_tab(tab3)

    # Tab 1 — Live Alerts
    def _build_alerts_tab(self, parent):
        # Filter bar
        fbar = tk.Frame(parent, bg=PAL["surface"], pady=6)
        fbar.pack(fill="x", padx=0)

        tk.Label(fbar, text="Filter:", bg=PAL["surface"],
                 fg=PAL["text_dim"], font=("Segoe UI", 9)).pack(side="left", padx=(12,4))

        self.filter_var = tk.StringVar(value="ALL")
        for lvl in ["ALL", "HIGH", "MEDIUM", "LOW", "CLEAN"]:
            col = SEVERITY_COLOURS.get(lvl, {}).get("fg", PAL["text"])
            rb = tk.Radiobutton(fbar, text=lvl, variable=self.filter_var,
                                value=lvl, command=self._apply_filter,
                                bg=PAL["surface"], fg=col,
                                selectcolor=PAL["surface2"],
                                activebackground=PAL["surface"],
                                font=("Segoe UI", 9, "bold"),
                                relief="flat", bd=0)
            rb.pack(side="left", padx=6)

        self.btn_clear = self._make_button(
            fbar, "🗑 Clear", PAL["surface2"],
            self._clear_alerts, width=10, pady=2)
        self.btn_clear.pack(side="right", padx=12)

        # Treeview
        cols = ("time", "patient", "ward", "severity",
                "attack", "source_ip", "score", "description")
        headings = ("Time", "Patient ID", "Ward", "Severity",
                    "Attack Type", "Source IP", "Score", "Description")

        frame = tk.Frame(parent, bg=PAL["bg"])
        frame.pack(fill="both", expand=True, padx=0, pady=0)

        self.tree = ttk.Treeview(frame, columns=cols, show="headings",
                                 selectmode="browse")
        widths = (130, 90, 90, 80, 160, 110, 70, 400)
        for col, hd, w in zip(cols, headings, widths):
            self.tree.heading(col, text=hd)
            self.tree.column(col, width=w, minwidth=60, anchor="center")
        self.tree.column("description", anchor="w")

        # Severity colour tags
        for level, cfg in SEVERITY_COLOURS.items():
            self.tree.tag_configure(
                cfg["tag"],
                background=cfg["bg"],
                foreground=cfg["fg"])

        vsb = ttk.Scrollbar(frame, orient="vertical",
                            command=self.tree.yview)
        hsb = ttk.Scrollbar(frame, orient="horizontal",
                            command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set,
                            xscrollcommand=hsb.set)

        vsb.pack(side="right",  fill="y")
        hsb.pack(side="bottom", fill="x")
        self.tree.pack(fill="both", expand=True)

        # Row click — show detail panel
        self.tree.bind("<<TreeviewSelect>>", self._on_row_select)

        # Detail panel
        detail_frame = tk.Frame(parent, bg=PAL["surface"], height=110)
        detail_frame.pack(fill="x", padx=0)
        detail_frame.pack_propagate(False)

        tk.Label(detail_frame, text="Event Detail",
                 font=("Segoe UI", 9, "bold"),
                 bg=PAL["surface"], fg=PAL["accent"]).pack(anchor="w", padx=12, pady=(8,2))

        self.detail_text = tk.Text(
            detail_frame, bg=PAL["surface2"], fg=PAL["text"],
            font=("Consolas", 8), height=4,
            relief="flat", bd=0, wrap="word",
            insertbackground=PAL["text"])
        self.detail_text.pack(fill="both", expand=True, padx=12, pady=(0,8))
        self.detail_text.config(state="disabled")

    # Tab 2 — IP Tracker
    def _build_ip_tab(self, parent):
        tk.Label(parent,
                 text="Source IP addresses are extracted from MQTT client properties.\n"
                      "IPs generating flagged (non-CLEAN) events are highlighted in red.",
                 font=("Segoe UI", 9), bg=PAL["bg"], fg=PAL["text_dim"],
                 justify="left").pack(anchor="w", padx=16, pady=(12, 4))

        cols = ("ip", "total", "flagged", "last_seen", "last_attack")
        hdgs = ("Source IP", "Total Msgs", "Flagged", "Last Seen", "Last Attack Type")

        frame = tk.Frame(parent, bg=PAL["bg"])
        frame.pack(fill="both", expand=True, padx=8, pady=4)

        self.ip_tree = ttk.Treeview(frame, columns=cols, show="headings")
        for col, hd, w in zip(cols, hdgs, (160, 90, 90, 180, 200)):
            self.ip_tree.heading(col, text=hd)
            self.ip_tree.column(col, width=w, anchor="center")

        self.ip_tree.tag_configure("flagged", foreground=PAL["red"],
                                   background=PAL["high_bg"])
        self.ip_tree.tag_configure("clean",   foreground=PAL["green"])

        vsb2 = ttk.Scrollbar(frame, orient="vertical",
                              command=self.ip_tree.yview)
        self.ip_tree.configure(yscrollcommand=vsb2.set)
        vsb2.pack(side="right", fill="y")
        self.ip_tree.pack(fill="both", expand=True)

    # Tab 3 — System Log
    def _build_log_tab(self, parent):
        frame = tk.Frame(parent, bg=PAL["bg"])
        frame.pack(fill="both", expand=True, padx=8, pady=8)

        self.log_text = tk.Text(
            frame, bg=PAL["surface"], fg=PAL["text"],
            font=("Consolas", 9), relief="flat", bd=0,
            wrap="word", insertbackground=PAL["text"])

        self.log_text.tag_configure("info",    foreground=PAL["text"])
        self.log_text.tag_configure("warning", foreground=PAL["yellow"])
        self.log_text.tag_configure("error",   foreground=PAL["red"])
        self.log_text.tag_configure("success", foreground=PAL["green"])
        self.log_text.tag_configure("dim",     foreground=PAL["text_dim"])

        vsb3 = ttk.Scrollbar(frame, orient="vertical",
                              command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=vsb3.set)
        vsb3.pack(side="right", fill="y")
        self.log_text.pack(fill="both", expand=True)
        self.log_text.config(state="disabled")

    # ══════════════════════════════════════════════════════════════════════════
    #  STATUS BAR
    # ══════════════════════════════════════════════════════════════════════════
    def _build_statusbar(self):
        sb = tk.Frame(self, bg=PAL["surface2"], height=28)
        sb.pack(fill="x", side="bottom")
        sb.pack_propagate(False)

        self.sb_left  = tk.Label(sb, text="Ready",
                                 font=("Segoe UI", 8),
                                 bg=PAL["surface2"], fg=PAL["text_dim"])
        self.sb_left.pack(side="left", padx=12, pady=4)

        self.sb_right = tk.Label(sb, text="Events: 0",
                                 font=("Segoe UI", 8),
                                 bg=PAL["surface2"], fg=PAL["text_dim"])
        self.sb_right.pack(side="right", padx=12, pady=4)

        self.sb_time  = tk.Label(sb, text="",
                                 font=("Segoe UI", 8),
                                 bg=PAL["surface2"], fg=PAL["text_dim"])
        self.sb_time.pack(side="right", padx=20, pady=4)
        self._tick_clock()

    def _tick_clock(self):
        self.sb_time.config(
            text=datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        self.after(1000, self._tick_clock)

    # ══════════════════════════════════════════════════════════════════════════
    #  BUTTON FACTORY
    # ══════════════════════════════════════════════════════════════════════════
    def _make_button(self, parent, text, bg, cmd,
                     width=None, pady=5, state="normal") -> tk.Button:
        kw = dict(text=text, bg=bg, fg=PAL["text"],
                  activebackground=PAL["btn_hover"],
                  activeforeground=PAL["text"],
                  font=("Segoe UI", 9, "bold"),
                  relief="flat", bd=0, pady=pady,
                  cursor="hand2", command=cmd, state=state)
        if width:
            kw["width"] = width
        return tk.Button(parent, **kw)

    # ══════════════════════════════════════════════════════════════════════════
    #  IDS CONTROL
    # ══════════════════════════════════════════════════════════════════════════
    def _start_ids(self):
        if self.ids_running:
            return
        self._log("Starting IDS engine…", "info")

        # Load model
        try:
            mp = self.config["model_path"]
            sp = self.config["scaler_path"]
            ep = self.config["meta_path"]
            for p in (mp, sp, ep):
                if not Path(p).exists():
                    raise FileNotFoundError(f"Not found: {p}")
            self.model  = joblib.load(mp)
            self.scaler = joblib.load(sp)
            with open(ep) as f:
                self.meta = json.load(f)
            self._log(f"Model loaded from {mp}", "success")
        except Exception as e:
            self._log(f"Model load failed: {e}", "error")
            messagebox.showerror("Model Error",
                f"Could not load model artefacts:\n{e}\n\n"
                "Run train_isolation_forest.py first.")
            return

        # Start CPU monitor
        if PSUTIL_AVAILABLE:
            self.cpu_monitor = _CPUMonitorThread(interval=2.0)
            self.cpu_monitor.start()

        # Connect MQTT
        try:
            self.mqtt_client = mqtt.Client(
                client_id=self.config["client_id"])
            if self.config["mqtt_username"]:
                self.mqtt_client.username_pw_set(
                    self.config["mqtt_username"],
                    self.config["mqtt_password"])

            self.mqtt_client.on_connect    = self._on_mqtt_connect
            self.mqtt_client.on_disconnect = self._on_mqtt_disconnect
            self.mqtt_client.on_message    = self._on_mqtt_message

            self.mqtt_client.connect(
                self.config["broker_host"],
                self.config["broker_port"],
                keepalive=self.config["keepalive"])
            self.mqtt_client.loop_start()
        except Exception as e:
            self._log(f"MQTT connection failed: {e}", "error")
            messagebox.showerror("Connection Error",
                f"Could not connect to MQTT broker:\n{e}")
            return

        self.ids_running = True
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        self.status_pill.config(text="● LIVE", fg=PAL["green"])
        self._log(
            f"Connected to {self.config['broker_host']}:{self.config['broker_port']}",
            "success")
        self.sb_left.config(text="IDS running…")

    def _stop_ids(self):
        if not self.ids_running:
            return
        if self.mqtt_client:
            self.mqtt_client.loop_stop()
            self.mqtt_client.disconnect()
        self.ids_running = False
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")
        self.status_pill.config(text="● OFFLINE", fg=PAL["text_dim"])
        self._log("IDS stopped.", "warning")
        self.sb_left.config(text="Stopped")

    # ══════════════════════════════════════════════════════════════════════════
    #  MQTT CALLBACKS  (run in MQTT thread — put events on queue)
    # ══════════════════════════════════════════════════════════════════════════
    def _on_mqtt_connect(self, client, userdata, flags, rc):
        topic = self.config["topic"]
        client.subscribe(topic, qos=1)
        self.event_queue.put(("log", f"Subscribed to '{topic}'", "success"))

    def _on_mqtt_disconnect(self, client, userdata, rc):
        if rc != 0:
            self.event_queue.put(("log", "MQTT unexpected disconnect", "warning"))

    def _on_mqtt_message(self, client, userdata, msg):
        received_at = datetime.now(timezone.utc).isoformat()

        # Extract source IP from mqtt client socket if possible
        source_ip = "Unknown"
        try:
            sock = client.socket()
            if sock:
                peer = sock.getpeername()
                source_ip = peer[0] if peer else "Unknown"
        except Exception:
            pass

        # ── LAYER 0: Topic-level signature scan (before even parsing JSON) ────
        topic_hit = _scan_string(msg.topic)
        if topic_hit:
            event = {
                "event_time":    received_at,
                "mqtt_topic":    msg.topic,
                "patient_id":    "UNKNOWN",
                "patient_name":  "",
                "ward":          "",
                "bed":           "",
                "alert_level":   "HIGH",
                "anomaly_score": None,
                "if_prediction": None,
                "attack": {
                    "type":   "UNAUTHORIZED_ACCESS",
                    "reason": f"Attack signature detected in MQTT topic path — {topic_hit}",
                    "source": "RULE_ENGINE",
                },
                "features":  {},
                "cpu":       self._cpu_snapshot(),
                "scan_ms":   0,
                "source_ip": source_ip,
                "detection": "RULE_ENGINE",
            }
            self.event_queue.put(("event", event))
            return

        # Parse JSON
        try:
            payload = json.loads(msg.payload.decode("utf-8"))
        except Exception as e:
            event = {
                "event_time":   received_at,
                "mqtt_topic":   msg.topic,
                "patient_id":   "UNKNOWN",
                "patient_name": "",
                "ward":         "",
                "bed":          "",
                "alert_level":  "HIGH",
                "anomaly_score": None,
                "if_prediction": None,
                "attack": {"type": "UNRELATED_PAYLOAD",
                           "reason": f"JSON decode error: {e}"},
                "features":  {},
                "cpu":       self._cpu_snapshot(),
                "scan_ms":   0,
                "source_ip": source_ip,
            }
            self.event_queue.put(("event", event))
            return

        # Add source IP to payload
        payload["_source_ip"] = source_ip

        # ── LAYER 1: Rule-based engine (content/signature analysis) ──────
        # Runs BEFORE the model — overrides it for deterministic threats
        rule_verdict = self.rule_engine.check(payload, msg.topic, source_ip)
        if rule_verdict is not None:
            # Rule fired — build event without running the model
            cpu_stats = self._cpu_snapshot()
            event = {
                "event_time":    received_at,
                "mqtt_topic":    msg.topic,
                "patient_id":    str(payload.get("patient_id", "UNKNOWN")),
                "patient_name":  payload.get("name", ""),
                "ward":          payload.get("ward", ""),
                "bed":           payload.get("bed", ""),
                "alert_level":   rule_verdict["alert_level"],
                "anomaly_score": None,
                "if_prediction": None,
                "attack":        rule_verdict["attack"],
                "features":      {},
                "cpu":           cpu_stats,
                "scan_ms":       0,
                "source_ip":     source_ip,
                "detection":     "RULE_ENGINE",
            }
            self.event_queue.put(("event", event))
            return

        # ── LAYER 2: Isolation Forest (statistical anomaly detection) ──────
        # Feature engineering
        features = engineer_features(payload)
        if features is None:
            return

        # Inference
        try:
            X_df     = pd.DataFrame(
                [[features[f] for f in ALL_FEATURES]],
                columns=ALL_FEATURES)
            X_scaled = self.scaler.transform(X_df)
            score    = float(self.model.decision_function(X_scaled)[0])
            pred     = int(self.model.predict(X_scaled)[0])
        except Exception as e:
            self.event_queue.put(("log", f"Inference error: {e}", "error"))
            return

        alert_level = classify_alert(score, self.config)
        attack      = classify_attack(score, features, payload,
                                      alert_level, self.config)
        cpu_stats   = self._cpu_snapshot()

        event = {
            "event_time":    received_at,
            "mqtt_topic":    msg.topic,
            "patient_id":    payload.get("patient_id", "UNKNOWN"),
            "patient_name":  payload.get("name", ""),
            "ward":          payload.get("ward", ""),
            "bed":           payload.get("bed", ""),
            "alert_level":   alert_level,
            "anomaly_score": round(score, 6),
            "if_prediction": pred,
            "attack":        attack,
            "features":      {k: round(v, 4) if isinstance(v, float) else v
                              for k, v in features.items()},
            "cpu":           cpu_stats,
            "scan_ms":       0,
            "source_ip":     source_ip,
            "detection":     "ISOLATION_FOREST",
        }
        self.event_queue.put(("event", event))

    def _cpu_snapshot(self) -> dict:
        if self.cpu_monitor:
            return self.cpu_monitor.snapshot()
        return {"cpu_avg_pct": 0.0, "mem_used_pct": 0.0,
                "cpu_per_core_pct": [], "cpu_freq_mhz": None,
                "mem_used_mb": 0.0}

    # ══════════════════════════════════════════════════════════════════════════
    #  EVENT QUEUE POLL  (runs on main/GUI thread via after())
    # ══════════════════════════════════════════════════════════════════════════
    def _poll_queue(self):
        try:
            while True:
                item = self.event_queue.get_nowait()
                if item[0] == "event":
                    self._handle_event(item[1])
                elif item[0] == "log":
                    self._log(item[1], item[2])
        except queue.Empty:
            pass

        # Update CPU/RAM gauges from monitor
        if self.cpu_monitor and PSUTIL_AVAILABLE:
            snap = self.cpu_monitor.snapshot()
            self._update_gauge(self.cpu_bar, self.cpu_lbl,
                               snap["cpu_avg_pct"],
                               self.config["cpu_warn_pct"])
            self._update_gauge(self.ram_bar, self.ram_lbl,
                               snap["mem_used_pct"], 90.0)

        self.after(250, self._poll_queue)

    # ══════════════════════════════════════════════════════════════════════════
    #  EVENT HANDLER
    # ══════════════════════════════════════════════════════════════════════════
    def _handle_event(self, event: dict):
        self.events.append(event)

        level       = event.get("alert_level", "CLEAN")
        attack_type = event.get("attack", {}).get("type", "NONE")
        source_ip   = event.get("source_ip", "Unknown")

        # Update counters
        if level in self.counters:
            self.counters[level] += 1
            self.count_labels[level].config(
                text=str(self.counters[level]))

        # IP tracking
        self.ip_counts[source_ip] += 1
        if level != "CLEAN":
            self.flagged_ips.add(source_ip)
            self._update_ip_sidebar(source_ip)

        self._update_ip_tree(source_ip, level, attack_type, event)

        # Write to JSON log
        log_path = Path(self.config["alert_log"])
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")

        # Add row to treeview
        self._add_tree_row(event)

        # Status bar
        total = sum(self.counters.values())
        self.sb_right.config(text=f"Events: {total}")

        # System log (non-CLEAN only to keep it readable)
        if level != "CLEAN":
            icon      = ATTACK_ICONS.get(attack_type, "❓")
            detection = event.get("detection", "ISOLATION_FOREST")
            layer_tag = "[RULE]" if detection == "RULE_ENGINE" else "[MODEL]"
            reason    = event.get("attack", {}).get("reason", "")
            # Truncate long rule reasons to keep log readable
            reason_short = reason[:90] + "…" if len(reason) > 90 else reason
            self._log(
                f"{icon} {layer_tag} [{level}] {event['patient_id']} — "
                f"{attack_type}  |  IP: {source_ip}  |  {reason_short}",
                "warning" if level == "HIGH" else "info")

    def _add_tree_row(self, event: dict):
        level      = event.get("alert_level", "CLEAN")
        tag        = SEVERITY_COLOURS.get(level, {}).get("tag", "clean")
        attack     = event.get("attack", {})
        attack_type = attack.get("type", "NONE")
        icon       = ATTACK_ICONS.get(attack_type, "")
        ts         = event.get("event_time", "")[:19].replace("T", " ")
        score      = event.get("anomaly_score")
        score_str  = f"{score:+.4f}" if score is not None else "RULE"
        detection  = event.get("detection", "ISOLATION_FOREST")

        # For rule engine hits: show the exact specific reason (e.g. "path traversal: ../../etc/passwd")
        # For model hits: show the generic human description
        if detection == "RULE_ENGINE" and attack.get("reason"):
            desc = f"[RULE] {attack['reason']}"
        else:
            desc = ATTACK_DESCRIPTIONS.get(attack_type, attack.get("reason", ""))

        iid = self.tree.insert("", "end", tags=(tag,), values=(
            ts,
            event.get("patient_id", ""),
            event.get("ward", ""),
            level,
            f"{icon} {attack_type}",
            event.get("source_ip", ""),
            score_str,
            desc,
        ))

        # Apply filter
        if self.filter_var.get() not in ("ALL", level):
            self.tree.detach(iid)

        # Auto-scroll
        self.tree.see(iid)

    def _update_ip_sidebar(self, ip: str):
        """Keep the sidebar flagged-IP listbox updated."""
        items = list(self.ip_listbox.get(0, "end"))
        display = f"⚠ {ip}"
        if display not in items:
            self.ip_listbox.insert("end", display)

    def _update_ip_tree(self, ip, level, attack_type, event):
        ts = event.get("event_time", "")[:19].replace("T", " ")
        # Update existing entry or insert new
        for iid in self.ip_tree.get_children():
            if self.ip_tree.item(iid, "values")[0] == ip:
                vals   = self.ip_tree.item(iid, "values")
                total  = int(vals[1]) + 1
                flagged = int(vals[2]) + (1 if level != "CLEAN" else 0)
                tag    = "flagged" if ip in self.flagged_ips else "clean"
                self.ip_tree.item(iid, values=(
                    ip, total, flagged, ts, attack_type), tags=(tag,))
                return

        tag = "flagged" if ip in self.flagged_ips else "clean"
        self.ip_tree.insert("", "end", tags=(tag,), values=(
            ip, 1,
            1 if level != "CLEAN" else 0,
            ts, attack_type))

    # ══════════════════════════════════════════════════════════════════════════
    #  ROW SELECT — DETAIL PANEL
    # ══════════════════════════════════════════════════════════════════════════
    def _on_row_select(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        idx   = self.tree.index(sel[0])
        # Map visible rows back to events
        visible = [c for c in self.tree.get_children()]
        if idx >= len(self.events):
            return
        ev = None
        # Find by matching timestamp in tree row
        row_vals = self.tree.item(sel[0], "values")
        ts_key   = row_vals[0].replace(" ", "T") if row_vals else ""
        for e in self.events:
            if e.get("event_time", "")[:19].replace("T", " ") == row_vals[0]:
                ev = e
                break
        if not ev:
            return

        atk        = ev.get("attack", {})
        detection  = ev.get("detection", "ISOLATION_FOREST")
        score_disp = f"{ev.get('anomaly_score'):+.6f}" if ev.get("anomaly_score") is not None else "N/A (Rule Engine)"
        layer_disp = "🔴 RULE ENGINE (deterministic)" if detection == "RULE_ENGINE" else "🤖 ISOLATION FOREST (statistical)"

        detail = (
            f"Detection  : {layer_disp}\n"
            f"Event Time : {ev.get('event_time','')}\n"
            f"Patient    : {ev.get('patient_id','')} — {ev.get('patient_name','')} "
            f"| Ward: {ev.get('ward','')} | Bed: {ev.get('bed','')}\n"
            f"Alert      : {ev.get('alert_level','')}  |  Score: {score_disp}\n"
            f"Attack     : {atk.get('type','')}\n"
            f"Reason     : {atk.get('reason','')}\n"
            f"Source IP  : {ev.get('source_ip','N/A')}  |  "
            f"CPU: {ev.get('cpu',{}).get('cpu_avg_pct','?')}%  |  "
            f"RAM: {ev.get('cpu',{}).get('mem_used_pct','?')}%"
        )
        self.detail_text.config(state="normal")
        self.detail_text.delete("1.0", "end")
        self.detail_text.insert("end", detail)
        self.detail_text.config(state="disabled")

    # ══════════════════════════════════════════════════════════════════════════
    #  FILTER
    # ══════════════════════════════════════════════════════════════════════════
    def _apply_filter(self):
        chosen = self.filter_var.get()
        # Clear and re-insert matching rows
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        for event in self.events:
            level = event.get("alert_level", "CLEAN")
            if chosen == "ALL" or level == chosen:
                self._add_tree_row(event)

    # ══════════════════════════════════════════════════════════════════════════
    #  CLEAR
    # ══════════════════════════════════════════════════════════════════════════
    def _clear_alerts(self):
        if messagebox.askyesno("Clear Alerts",
                               "Clear all alerts from the view?\n"
                               "(The JSON log on disk is not affected.)"):
            self.tree.delete(*self.tree.get_children())
            self.events.clear()
            for k in self.counters:
                self.counters[k] = 0
                self.count_labels[k].config(text="0")
            self.sb_right.config(text="Events: 0")

    # ══════════════════════════════════════════════════════════════════════════
    #  EXPORT
    # ══════════════════════════════════════════════════════════════════════════
    def _export(self, fmt: str):
        if not self.events:
            messagebox.showinfo("Export", "No events to export yet.")
            return

        ext_map  = {"json": ".json", "csv": ".csv",
                    "xml": ".xml", "pdf": ".pdf"}
        type_map = {
            "json": [("JSON files", "*.json")],
            "csv":  [("CSV files",  "*.csv")],
            "xml":  [("XML files",  "*.xml")],
            "pdf":  [("PDF files",  "*.pdf")],
        }

        path = filedialog.asksaveasfilename(
            defaultextension=ext_map[fmt],
            filetypes=type_map[fmt],
            initialfile=f"ids_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}{ext_map[fmt]}")

        if not path:
            return

        try:
            if fmt == "json":
                export_json(self.events, path)
            elif fmt == "csv":
                export_csv(self.events, path)
            elif fmt == "xml":
                export_xml(self.events, path)
            elif fmt == "pdf":
                export_pdf(self.events, path)
            self._log(f"Exported {len(self.events)} events → {path}", "success")
            messagebox.showinfo("Export Complete",
                                f"Successfully exported {len(self.events)} events to:\n{path}")
        except Exception as e:
            self._log(f"Export failed: {e}", "error")
            messagebox.showerror("Export Error", str(e))

    # ══════════════════════════════════════════════════════════════════════════
    #  SETTINGS DIALOG
    # ══════════════════════════════════════════════════════════════════════════
    def _open_settings(self):
        dlg = tk.Toplevel(self)
        dlg.title("Settings")
        dlg.geometry("560x560")
        dlg.configure(bg=PAL["bg"])
        dlg.grab_set()

        tk.Label(dlg, text="IDS Configuration",
                 font=("Segoe UI", 13, "bold"),
                 bg=PAL["bg"], fg=PAL["accent"]).pack(pady=(16,4))
        tk.Frame(dlg, bg=PAL["border"], height=1).pack(fill="x", padx=16, pady=4)

        scroll_frame = tk.Frame(dlg, bg=PAL["bg"])
        scroll_frame.pack(fill="both", expand=True, padx=20, pady=8)

        fields = [
            ("MQTT Broker Host",        "broker_host",      False),
            ("MQTT Broker Port",        "broker_port",      False),
            ("MQTT Topic",              "topic",            False),
            ("MQTT Username",           "mqtt_username",    False),
            ("MQTT Password",           "mqtt_password",    True),
            ("Model Path (.pkl)",       "model_path",       False),
            ("Scaler Path (.pkl)",      "scaler_path",      False),
            ("Meta Path (.json)",       "meta_path",        False),
            ("Alert Log Path (.jsonl)", "alert_log",        False),
            ("Threshold LOW",           "threshold_low",    False),
            ("Threshold MEDIUM",        "threshold_medium", False),
            ("Threshold HIGH",          "threshold_high",   False),
            ("CPU Warn %",              "cpu_warn_pct",     False),
        ]

        entries = {}
        for label, key, secret in fields:
            row = tk.Frame(scroll_frame, bg=PAL["bg"])
            row.pack(fill="x", pady=3)
            tk.Label(row, text=label, font=("Segoe UI", 9),
                     bg=PAL["bg"], fg=PAL["text_dim"],
                     width=24, anchor="w").pack(side="left")
            show = "*" if secret else ""
            var = tk.StringVar(value=str(self.config.get(key, "")))
            e = tk.Entry(row, textvariable=var, show=show,
                         bg=PAL["surface2"], fg=PAL["text"],
                         insertbackground=PAL["text"],
                         relief="flat", bd=4, font=("Segoe UI", 9))
            e.pack(side="left", fill="x", expand=True)
            entries[key] = var

        def save():
            for key, var in entries.items():
                val = var.get()
                try:
                    if isinstance(DEFAULT_CONFIG[key], int):
                        val = int(val)
                    elif isinstance(DEFAULT_CONFIG[key], float):
                        val = float(val)
                except (ValueError, KeyError):
                    pass
                self.config[key] = val
            self._log("Settings saved.", "success")
            dlg.destroy()

        btn_row = tk.Frame(dlg, bg=PAL["bg"])
        btn_row.pack(pady=12)
        self._make_button(btn_row, "  Save  ", PAL["btn_start"],
                          save, width=12).pack(side="left", padx=6)
        self._make_button(btn_row, "  Cancel  ", PAL["surface2"],
                          dlg.destroy, width=12).pack(side="left", padx=6)

    # ══════════════════════════════════════════════════════════════════════════
    #  SYSTEM LOG
    # ══════════════════════════════════════════════════════════════════════════
    def _log(self, msg: str, level: str = "info"):
        ts  = datetime.now().strftime("%H:%M:%S")
        self.log_text.config(state="normal")
        self.log_text.insert("end", f"[{ts}]  ", "dim")
        self.log_text.insert("end", msg + "\n", level)
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    # ══════════════════════════════════════════════════════════════════════════
    #  CLOSE
    # ══════════════════════════════════════════════════════════════════════════
    def _on_close(self):
        self._stop_ids()
        self.destroy()


# ─────────────────────────────────────────────────────────────────────────────
#  CPU MONITOR THREAD  (same non-blocking pattern as patient_ids.py)
# ─────────────────────────────────────────────────────────────────────────────
class _CPUMonitorThread:
    def __init__(self, interval=2.0):
        self._lock  = threading.Lock()
        self._stats = {"cpu_avg_pct": 0.0, "mem_used_pct": 0.0,
                       "cpu_per_core_pct": [], "cpu_freq_mhz": None,
                       "mem_used_mb": 0.0}
        self._interval = interval
        if PSUTIL_AVAILABLE:
            psutil.cpu_percent(percpu=True)   # seed

    def start(self):
        t = threading.Thread(target=self._run, daemon=True)
        t.start()

    def _run(self):
        while True:
            time.sleep(self._interval)
            if not PSUTIL_AVAILABLE:
                break
            cores = psutil.cpu_percent(percpu=True)
            avg   = sum(cores) / len(cores) if cores else 0.0
            freq  = psutil.cpu_freq()
            mem   = psutil.virtual_memory()
            with self._lock:
                self._stats = {
                    "cpu_avg_pct":      round(avg, 2),
                    "cpu_per_core_pct": [round(c, 1) for c in cores],
                    "cpu_freq_mhz":     round(freq.current, 1) if freq else None,
                    "mem_used_pct":     round(mem.percent, 2),
                    "mem_used_mb":      round(mem.used / 1024**2, 1),
                }

    def snapshot(self) -> dict:
        with self._lock:
            return dict(self._stats)


# ─────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = IDSApp()
    app.mainloop()
