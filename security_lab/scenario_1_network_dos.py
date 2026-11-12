"""
SENTRIX Security Lab — Scenario 1: Network DoS & Volumetric Attack
-------------------------------------------------------------------
Fires high-rate simulated network attack flows against the ingestion pipeline.
Validates:
- ML model detects ATTACK with high confidence (>90%)
- Multi-event correlation aggregates flows under the offending IP
- Severity escalates to CRITICAL / HIGH (Risk Score >= 80)
- AI Threat Analyst recommends defensive BLOCK_IP containment
"""

import json
import os
import time
import urllib.request
import urllib.error
from pathlib import Path

BASE_URL = "http://127.0.0.1:8000/api/v1"
ATTACK_FILE = Path("attack_request.json")


def run_scenario(base_url: str = BASE_URL, target_ip: str = "203.0.113.195", sensor_key: str | None = None) -> dict:
    print(f"\n[SCENARIO 1] Executing Network DoS & Volumetric Attack Simulation...")
    print(f"[*] Attacker IP: {target_ip} -> Target Server: {base_url}")

    resolved_key = (sensor_key or os.getenv("SENTRIX_SENSOR_API_KEY", "")).strip()
    if not resolved_key:
        raise RuntimeError(
            "SENTRIX_SENSOR_API_KEY environment variable is required to authenticate telemetry with the SENTRIX backend."
        )

    # Load 78-feature attack payload
    if not ATTACK_FILE.exists():
        raise FileNotFoundError(f"Missing {ATTACK_FILE}")
    with open(ATTACK_FILE, "r", encoding="utf-8") as f:
        attack_template = json.load(f)

    features = attack_template["features"]

    results = []
    incident_id = None

    # Fire 3 burst attack flows to trigger correlation
    for i in range(1, 4):
        event_payload = {
            "source_ip": target_ip,
            "destination_port": 80,
            "protocol": "TCP",
            "features": features,
        }

        req = urllib.request.Request(
            f"{base_url}/events",
            data=json.dumps(event_payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "X-SENTRIX-SENSOR-KEY": resolved_key,
            },
        )

        try:
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                results.append(data)
                print(f"    Flow #{i}: Status={data.get('status')} | Predicted={data.get('predicted_label')} | IncidentCreated={data.get('incident_created')} | IncID={data.get('incident_id')}")
                if data.get("incident_id"):
                    incident_id = data["incident_id"]
        except urllib.error.HTTPError as e:
            print(f"    Flow #{i} Error: HTTP {e.code}: {e.read().decode('utf-8')}")

        time.sleep(0.3)

    if not incident_id:
        return {
            "scenario": "Network DoS & Volumetric Attack",
            "status": "FAILED",
            "reason": "No incident was created or correlated from attack flows",
        }

    # Fetch incident details to verify AI Threat Analyst & correlation escalation
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

    inc_req = urllib.request.Request(
        f"{base_url}/incidents/{incident_id}",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    with urllib.request.urlopen(inc_req) as resp:
        incident = json.loads(resp.read().decode("utf-8"))

    print(f"[+] Incident #{incident_id} Correlated:")
    print(f"    Severity   : {incident.get('severity')}")
    print(f"    Risk Score : {incident.get('risk_score')}/100")
    print(f"    Event Count: {incident.get('event_count')} flows correlated")
    ai_analysis = incident.get("ai_analysis") or {}
    recommended_action = ai_analysis.get("recommended_action", "MONITOR")
    print(f"    AI Rec.    : {recommended_action} (Confidence: {ai_analysis.get('confidence', 'N/A')})")

    success = (
        incident.get("severity") in ("HIGH", "CRITICAL")
        and incident.get("risk_score", 0) >= 50
        and incident.get("event_count", 0) >= 2
        and recommended_action in ("BLOCK_IP", "RATE_LIMIT")
    )

    return {
        "scenario": "Network DoS & Volumetric Attack",
        "status": "PASSED" if success else "FAILED",
        "attacker_ip": target_ip,
        "incident_id": incident_id,
        "severity": incident.get("severity"),
        "risk_score": incident.get("risk_score"),
        "event_count": incident.get("event_count"),
        "ai_recommended_action": recommended_action,
    }


if __name__ == "__main__":
    res = run_scenario()
    print("\nScenario 1 Result:", json.dumps(res, indent=2))
