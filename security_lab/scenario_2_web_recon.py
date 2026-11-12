"""
SENTRIX Security Lab — Scenario 2: Web Reconnaissance & Directory Enumeration
----------------------------------------------------------------------------
Simulates an external threat actor performing automated directory scanning,
path traversal, and secret discovery against web infrastructure.
Validates:
- Nginx connector regex parses Common/Combined log lines
- Sensitive path inspection flags reconnaissance attempts
- Automatic mapping to MITRE ATT&CK technique T1190 (Exploit Public-Facing Application)
- Offending IP logged and escalated into an active incident
"""

import json
import os
import time
import urllib.request
import urllib.error

BASE_URL = "http://127.0.0.1:8000/api/v1"


def run_scenario(base_url: str = BASE_URL, target_ip: str = "203.0.113.196", sensor_key: str | None = None) -> dict:
    print(f"\n[SCENARIO 2] Executing Web Reconnaissance & Directory Enumeration Simulation...")
    print(f"[*] Attacker IP: {target_ip} -> Target Server: {base_url}")

    resolved_key = (sensor_key or os.getenv("SENTRIX_SENSOR_API_KEY", "")).strip()
    if not resolved_key:
        raise RuntimeError(
            "SENTRIX_SENSOR_API_KEY environment variable is required to authenticate telemetry with the SENTRIX backend."
        )

    recon_logs = [
        f'{target_ip} - - [11/Nov/2026:14:32:10 +0000] "GET /admin/config.php HTTP/1.1" 404 342 "-" "sqlmap/1.6"',
        f'{target_ip} - - [11/Nov/2026:14:32:12 +0000] "GET /../../etc/passwd HTTP/1.1" 403 218 "-" "Nikto/2.1.6"',
        f'{target_ip} - - [11/Nov/2026:14:32:14 +0000] "GET /.env HTTP/1.1" 404 195 "-" "Go-http-client/1.1"',
    ]

    results = []
    incident_id = None

    for i, log_line in enumerate(recon_logs, 1):
        payload = {
            "source_type": "NGINX_ACCESS",
            "raw_payload": log_line,
        }

        req = urllib.request.Request(
            f"{base_url}/ingest/raw",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "X-SENTRIX-SENSOR-KEY": resolved_key,
            },
        )

        try:
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                results.append(data)
                print(f"    Probe #{i}: Status={data.get('status')} | EventType={data.get('normalized_data', {}).get('event_type')} | IncCreated={data.get('incident_created')} | IncID={data.get('incident_id')}")
                if data.get("incident_id"):
                    incident_id = data["incident_id"]
        except urllib.error.HTTPError as e:
            print(f"    Probe #{i} Error: HTTP {e.code}: {e.read().decode('utf-8')}")

        time.sleep(0.3)

    if not incident_id:
        return {
            "scenario": "Web Reconnaissance & Directory Enumeration",
            "status": "FAILED",
            "reason": "No incident was created or correlated from web recon logs",
        }

    # Fetch incident details to verify MITRE mapping
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

    mitre = incident.get("mitre_attack") or {}
    print(f"[+] Incident #{incident_id} Correlated:")
    print(f"    MITRE Technique : {mitre.get('technique_id')} ({mitre.get('technique_name')})")
    print(f"    MITRE Tactic    : {mitre.get('tactic')}")
    print(f"    Detection Reason: {incident.get('reasons')}")

    success = (
        incident.get("severity") in ("MEDIUM", "HIGH", "CRITICAL")
        and mitre.get("technique_id") in ("T1190", "T1046", "T1595")
    )

    return {
        "scenario": "Web Reconnaissance & Directory Enumeration",
        "status": "PASSED" if success else "FAILED",
        "attacker_ip": target_ip,
        "incident_id": incident_id,
        "mitre_technique": mitre.get("technique_id"),
        "mitre_name": mitre.get("technique_name"),
        "severity": incident.get("severity"),
        "risk_score": incident.get("risk_score"),
    }


if __name__ == "__main__":
    res = run_scenario()
    print("\nScenario 2 Result:", json.dumps(res, indent=2))
