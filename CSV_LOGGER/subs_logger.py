#!/usr/bin/env python3
"""
Patient Health Data — MQTT Subscriber & CSV Logger
====================================================
Subscribes to  hospital/patients/#  on the MQTT broker (Windows VM),
parses each JSON payload, and appends a flat row to a rotating CSV file.

A new CSV file is created each day, e.g.:
    patient_data_2026-04-25.csv
    patient_data_2026-04-26.csv
    …

Run this on the Windows VM (or any machine that can reach the broker).

Requirements:
    pip install paho-mqtt
"""

import csv
import json
import logging
import os
import signal
import sys
from datetime import datetime, date
from pathlib import Path

import paho.mqtt.client as mqtt

# ─────────────────────────────────────────────
#  CONFIGURATION  ← edit these values
# ─────────────────────────────────────────────
CONFIG = {
    # MQTT broker address
    "broker_host": "192.168.190.130",   # Windows VM IP (or localhost if running ON the VM)
    "broker_port": 1883,
    "topic":       "hospital/patients/#",   # wildcard — catches all 20 patients
    "client_id":   "windows-csv-subscriber",
    "mqtt_username": "",              # leave empty if broker has no auth
    "mqtt_password": "",

    # Where to save CSV files
    "output_dir":  r"C:\patient_data\csv",   # Windows path; use /home/user/patient_data on Linux

    # Rotate to a new file each day (True) or use a single file forever (False)
    "daily_rotation": True,

    # If False, a single file name is used regardless of date
    "single_file_name": "patient_data.csv",

    # Flush to disk after every N rows (lower = safer, higher = faster)
    "flush_every": 5,
}
# ─────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# ── CSV column order ──────────────────────────
CSV_COLUMNS = [
    "received_at",          # when this machine received the message
    "published_at",         # timestamp from the publisher payload
    "mqtt_topic",           # e.g. hospital/patients/P003
    "patient_id",
    "name",
    "age",
    "gender",
    "ward",
    "bed",
    # vitals ↓
    "bp_systolic_mmhg",
    "bp_diastolic_mmhg",
    "heart_rate_bpm",
    "spo2_percent",
    "respiratory_rate_bpm",
    "temperature_celsius",
    "blood_glucose_mgdl",
    "ecg_rhythm",
    "pain_scale",
    "consciousness",
]


class CSVLogger:
    """Thread-safe CSV writer with optional daily file rotation."""

    def __init__(self, output_dir: str, daily_rotation: bool, single_name: str, flush_every: int):
        self.output_dir = Path(output_dir)
        self.daily_rotation = daily_rotation
        self.single_name = single_name
        self.flush_every = flush_every

        self.output_dir.mkdir(parents=True, exist_ok=True)

        self._current_date = None
        self._file = None
        self._writer = None
        self._row_count = 0
        self._total_rows = 0

        self._open_file()

    def _csv_path(self) -> Path:
        if self.daily_rotation:
            return self.output_dir / f"patient_data_{date.today().isoformat()}.csv"
        return self.output_dir / self.single_name

    def _open_file(self):
        """Open (or reopen) the CSV file and write the header if it's new."""
        if self._file:
            self._file.close()

        path = self._csv_path()
        is_new = not path.exists()

        self._file = open(path, "a", newline="", encoding="utf-8")
        self._writer = csv.DictWriter(self._file, fieldnames=CSV_COLUMNS, extrasaction="ignore")

        if is_new:
            self._writer.writeheader()
            log.info(f"CSV ✓ New file created: {path}")
        else:
            log.info(f"CSV ✓ Appending to existing file: {path}")

        self._current_date = date.today()

    def _check_rotation(self):
        """Rotate file if the day has changed."""
        if self.daily_rotation and date.today() != self._current_date:
            log.info("CSV ↻ Day changed — rotating to new file")
            self._open_file()
            self._row_count = 0

    def write(self, row: dict):
        self._check_rotation()
        self._writer.writerow(row)
        self._row_count += 1
        self._total_rows += 1

        if self._row_count % self.flush_every == 0:
            self._file.flush()
            os.fsync(self._file.fileno())

    def close(self):
        if self._file:
            self._file.flush()
            self._file.close()
            log.info(f"CSV ✓ File closed. Total rows written this session: {self._total_rows}")


def flatten_payload(topic: str, payload: dict, received_at: str) -> dict:
    """Convert the nested JSON payload into a flat CSV row."""
    vitals = payload.get("vitals", {})
    bp = vitals.get("blood_pressure", {})

    return {
        "received_at":          received_at,
        "published_at":         payload.get("timestamp", ""),
        "mqtt_topic":           topic,
        "patient_id":           payload.get("patient_id", ""),
        "name":                 payload.get("name", ""),
        "age":                  payload.get("age", ""),
        "gender":               payload.get("gender", ""),
        "ward":                 payload.get("ward", ""),
        "bed":                  payload.get("bed", ""),
        "bp_systolic_mmhg":     bp.get("systolic_mmhg", ""),
        "bp_diastolic_mmhg":    bp.get("diastolic_mmhg", ""),
        "heart_rate_bpm":       vitals.get("heart_rate_bpm", ""),
        "spo2_percent":         vitals.get("spo2_percent", ""),
        "respiratory_rate_bpm": vitals.get("respiratory_rate_bpm", ""),
        "temperature_celsius":  vitals.get("temperature_celsius", ""),
        "blood_glucose_mgdl":   vitals.get("blood_glucose_mgdl", ""),
        "ecg_rhythm":           vitals.get("ecg_rhythm", ""),
        "pain_scale":           vitals.get("pain_scale", ""),
        "consciousness":        vitals.get("consciousness", ""),
    }


# ── MQTT callbacks ────────────────────────────
def make_on_message(csv_logger: CSVLogger):
    def on_message(client, userdata, msg):
        received_at = datetime.utcnow().isoformat() + "Z"
        topic = msg.topic

        try:
            payload = json.loads(msg.payload.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            log.warning(f"[{topic}] Bad payload — skipping: {e}")
            return

        row = flatten_payload(topic, payload, received_at)
        csv_logger.write(row)

        log.info(
            f"[{row['patient_id']}] {row['name']:20s} | "
            f"BP {row['bp_systolic_mmhg']}/{row['bp_diastolic_mmhg']} | "
            f"HR {row['heart_rate_bpm']} bpm | "
            f"SpO2 {row['spo2_percent']}% | "
            f"Temp {row['temperature_celsius']}°C"
        )

    return on_message


def on_connect(client, userdata, flags, rc):
    if rc == 0:
        topic = CONFIG["topic"]
        client.subscribe(topic, qos=1)
        log.info(f"MQTT ✓ Connected — subscribed to '{topic}'")
    else:
        log.error(f"MQTT ✗ Connection refused (rc={rc})")


def on_disconnect(client, userdata, rc):
    if rc != 0:
        log.warning("MQTT unexpected disconnect — will auto-reconnect…")


# ── Entry point ───────────────────────────────
def main():
    log.info("=== Patient Data MQTT Subscriber & CSV Logger ===")

    csv_logger = CSVLogger(
        output_dir=CONFIG["output_dir"],
        daily_rotation=CONFIG["daily_rotation"],
        single_name=CONFIG["single_file_name"],
        flush_every=CONFIG["flush_every"],
    )

    client = mqtt.Client(client_id=CONFIG["client_id"])

    if CONFIG["mqtt_username"]:
        client.username_pw_set(CONFIG["mqtt_username"], CONFIG["mqtt_password"])

    client.on_connect    = on_connect
    client.on_disconnect = on_disconnect
    client.on_message    = make_on_message(csv_logger)

    # Graceful shutdown on Ctrl+C or SIGTERM
    def shutdown(sig, frame):
        log.info("Shutting down…")
        client.loop_stop()
        client.disconnect()
        csv_logger.close()
        sys.exit(0)

    signal.signal(signal.SIGINT,  shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    log.info(f"Connecting to broker {CONFIG['broker_host']}:{CONFIG['broker_port']} …")
    client.connect(CONFIG["broker_host"], CONFIG["broker_port"], keepalive=60)

    # Blocking loop — runs forever until Ctrl+C / SIGTERM
    client.loop_forever()


if __name__ == "__main__":
    main()
