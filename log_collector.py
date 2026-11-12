
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import requests

BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "logs" / "security_events.jsonl"
API_URL = "http://127.0.0.1:8000/api/v1/events"
POLL_INTERVAL = 2
SENSOR_KEY = os.getenv("SENTRIX_SENSOR_API_KEY", "").strip()


def convert_to_security_event(raw_event: dict) -> dict:
    """Convert one JSON log entry into the API's SecurityEvent format."""
    return {
        "event_id": str(uuid4()),
        "schema_version": "1.0",
        "event_type": "NETWORK_FLOW",
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "source_ip": raw_event.get("source_ip"),
        "destination_ip": raw_event.get("destination_ip"),
        "source_port": raw_event.get("source_port"),
        "destination_port": raw_event.get("destination_port"),
        "protocol": raw_event.get("protocol"),
        "features": raw_event["features"],
    }


def send_event(raw_event: dict) -> None:
    if not SENSOR_KEY:
        raise SystemExit("[FATAL] SENTRIX_SENSOR_API_KEY environment variable is missing. Log collector fails closed.")

    event = convert_to_security_event(raw_event)
    headers = {
        "Content-Type": "application/json",
        "X-SENTRIX-SENSOR-KEY": SENSOR_KEY,
    }

    try:
        response = requests.post(API_URL, json=event, headers=headers, timeout=10)

        if response.status_code == 202:
            print(f"[ACCEPTED] Event {event['event_id']}")
        elif response.status_code == 401:
            raise SystemExit(
                f"[AUTHENTICATION ERROR] HTTP 401 Unauthorized: Invalid or missing sensor key. Log collector fails closed.\n{response.text}"
            )
        else:
            print(
                f"[ERROR] HTTP {response.status_code}: "
                f"{response.text}"
            )

    except requests.RequestException as exc:
        print(f"[CONNECTION ERROR] {exc}")


def main() -> None:
    if not SENSOR_KEY:
        raise SystemExit("[FATAL] SENTRIX_SENSOR_API_KEY environment variable is missing. Log collector fails closed.")

    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    LOG_FILE.touch(exist_ok=True)

    print(f"SENTRIX collector watching: {LOG_FILE}")
    print(f"Sending events to: {API_URL}")
    print("Append a new JSON event line to test ingestion.")
    print("Press Ctrl+C to stop.")

    # This first prototype reads existing entries once.
    # Then it watches for newly appended lines.
    with LOG_FILE.open("r", encoding="utf-8") as log_file:
        while True:
            line = log_file.readline()

            if not line:
                time.sleep(POLL_INTERVAL)
                continue

            line = line.strip()
            if not line:
                continue

            try:
                raw_event = json.loads(line)

                if not isinstance(raw_event, dict):
                    raise ValueError("Each log line must be a JSON object")

                if not isinstance(raw_event.get("features"), dict):
                    raise ValueError("'features' must be a JSON object")

                if not raw_event["features"]:
                    raise ValueError("'features' cannot be empty")

                send_event(raw_event)

            except (json.JSONDecodeError, ValueError, KeyError) as exc:
                print(f"[INVALID LOG ENTRY] {exc}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nSENTRIX collector stopped.")
