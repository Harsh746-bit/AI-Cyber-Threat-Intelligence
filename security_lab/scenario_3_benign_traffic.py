"""
SENTRIX Security Lab — Scenario 3: Benign Traffic & False-Positive Validation
----------------------------------------------------------------------------
Fires high-fidelity benign network flows and legitimate web access traffic.
Validates:
- ML pipeline classifies normal traffic as BENIGN
- Normal web browsing (HTTP 200) ingested without raising false positive alerts
- ZERO incidents created for legitimate host (False Positive Rate = 0.0%)
"""

import json
import os
import time
import urllib.request
import urllib.error
from pathlib import Path

BASE_URL = "http://127.0.0.1:8000/api/v1"
BENIGN_FILE = Path("benign_request.json")


def run_scenario(base_url: str = BASE_URL, benign_ip: str = "198.51.100.222", sensor_key: str | None = None) -> dict:
    print(f"\n[SCENARIO 3] Executing Benign Traffic & False-Positive Validation Simulation...")
    print(f"[*] Benign Host IP: {benign_ip} -> Target Server: {base_url}")

    resolved_key = (sensor_key or os.getenv("SENTRIX_SENSOR_API_KEY", "")).strip()
    if not resolved_key:
        raise RuntimeError(
            "SENTRIX_SENSOR_API_KEY environment variable is required to authenticate telemetry with the SENTRIX backend."
        )

    # Load 78-feature benign payload
    if not BENIGN_FILE.exists():
        raise FileNotFoundError(f"Missing {BENIGN_FILE}")
    with open(BENIGN_FILE, "r", encoding="utf-8") as f:
        benign_template = json.load(f)

    features = benign_template["features"]

    # 1. Ingest benign network flow
    event_payload = {
        "source_ip": benign_ip,
        "destination_port": 443,
        "protocol": "TCP",
        "features": features,
    }

    req_net = urllib.request.Request(
        f"{base_url}/events",
        data=json.dumps(event_payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-SENTRIX-SENSOR-KEY": resolved_key,
        },
    )

    with urllib.request.urlopen(req_net) as resp:
        net_result = json.loads(resp.read().decode("utf-8"))

    print(f"    Network Flow Result: Status={net_result.get('status')} | Predicted={net_result.get('predicted_label')} | IncidentCreated={net_result.get('incident_created')}")

    # 2. Ingest benign web log (GET /index.html 200 OK)
    normal_log = f'{benign_ip} - - [11/Nov/2026:14:32:20 +0000] "GET /index.html HTTP/1.1" 200 4096 "https://google.com" "Mozilla/5.0"'
    raw_payload = {
        "source_type": "NGINX_ACCESS",
        "raw_payload": normal_log,
    }

    req_web = urllib.request.Request(
        f"{base_url}/ingest/raw",
        data=json.dumps(raw_payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-SENTRIX-SENSOR-KEY": resolved_key,
        },
    )

    with urllib.request.urlopen(req_web) as resp:
        web_result = json.loads(resp.read().decode("utf-8"))

    print(f"    Web Access Result  : Status={web_result.get('status')} | IncidentCreated={web_result.get('incident_created')}")

    # 3. Check incidents search for benign_ip
    login_user = os.getenv("SENTRIX_TEST_USER", "analyst")
    login_pass = os.getenv("SENTRIX_TEST_PASSWORD", "analyst123")
    login_req = urllib.request.Request(
        f"{base_url}/auth/login",
        data=json.dumps({"username": login_user, "password": login_pass}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(login_req) as auth_resp:
        auth_token = json.loads(auth_resp.read().decode("utf-8")).get("access_token", "")

    search_req = urllib.request.Request(
        f"{base_url}/incidents?search={benign_ip}",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    with urllib.request.urlopen(search_req) as resp:
        search_data = json.loads(resp.read().decode("utf-8"))
        incidents_for_ip = search_data.get("incidents", [])

    incident_count = len(incidents_for_ip)
    print(f"[+] Total Incidents Created for {benign_ip}: {incident_count}")

    success = (
        net_result.get("predicted_label") == "BENIGN"
        and net_result.get("incident_created") is False
        and web_result.get("incident_created") is False
        and incident_count == 0
    )

    return {
        "scenario": "Benign Traffic & False-Positive Validation",
        "status": "PASSED" if success else "FAILED",
        "benign_host_ip": benign_ip,
        "ml_predicted_label": net_result.get("predicted_label"),
        "false_positive_incidents_created": incident_count,
        "traffic_accepted": True,
    }


if __name__ == "__main__":
    res = run_scenario()
    print("\nScenario 3 Result:", json.dumps(res, indent=2))
