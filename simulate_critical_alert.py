"""
SENTRIX - Critical Emergency Incident Simulator
------------------------------------------------
This script allows you to inject or trigger a CRITICAL EMERGENCY incident in SENTRIX.

Option 1: Ingest via real ML & Correlation API (POST /api/v1/events)
Option 2: Direct Emergency Breach insertion into cyber_threats.db
"""

import os
import sys
import json
import uuid
from datetime import datetime, timezone

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

def trigger_via_api():
    import urllib.request
    from pathlib import Path

    payload_path = Path(__file__).resolve().parent / "attack_request.json"
    if not payload_path.exists():
        print("[!] attack_request.json not found")
        return

    data = json.loads(payload_path.read_text())
    # Use known mock malicious IP with 85% abuse reputation to trigger full dynamic escalation
    target_ip = "198.51.100.25"
    data["source_ip"] = target_ip

    print(f"[*] Simulating Multi-Flow Cyber Attack from {target_ip}...")

    # Fail closed if sensor key is missing
    sensor_key = os.getenv("SENTRIX_SENSOR_API_KEY", "").strip()
    if not sensor_key:
        print("[!] FATAL: SENTRIX_SENSOR_API_KEY environment variable is missing. Standalone simulation fails closed.")
        sys.exit(1)

    req_headers = {
        "Content-Type": "application/json",
        "X-SENTRIX-SENSOR-KEY": sensor_key,
    }

    for i in range(1, 4):
        url = "http://127.0.0.1:8000/api/v1/events"
        req = urllib.request.Request(
            url,
            data=json.dumps(data).encode("utf-8"),
            headers=req_headers
        )
        try:
            with urllib.request.urlopen(req) as resp:
                res_body = json.loads(resp.read().decode("utf-8"))
                inc_id = res_body.get("incident_id")
                print(f"  -> Flow #{i} sent: Status 202, Incident ID #{inc_id}")
        except urllib.error.HTTPError as e:
            if e.code == 401:
                print(f"  [!] Authentication Failed: HTTP 401 Unauthorized (Invalid or missing sensor API key). Fails closed.")
                sys.exit(1)
            print(f"  [!] Request #{i} failed with HTTP {e.code}: {e.read().decode('utf-8')}")
            sys.exit(1)
        except Exception as e:
            print(f"  [!] Request #{i} failed: {e}")
            sys.exit(1)

    # Fetch incident details
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:8000/api/v1/incidents/{inc_id}") as resp:
            inc = json.loads(resp.read().decode("utf-8"))
            print("\n" + "="*60)
            print("  🚨 CRITICAL EMERGENCY INCIDENT ACTIVE IN SENTRIX 🚨")
            print("="*60)
            print(f"  Incident ID   : #{inc['incident_id']}")
            print(f"  Source IP     : {inc['source_ip']}")
            print(f"  Severity      : {inc['severity']} (CRITICAL)")
            print(f"  Risk Score    : {inc['risk_score']} / 100")
            print(f"  Event Count   : {inc['event_count']} aggregated attacks")
            print(f"  MITRE ATT&CK  : {inc['mitre_attack']['technique_id']} - {inc['mitre_attack']['technique_name']} ({inc['mitre_attack']['tactic']})")
            print(f"  Threat Intel  : {inc['threat_intel']['abuse_confidence_score']}% Abuse Score ({inc['threat_intel']['status']})")
            print("="*60)
            print("👉 Open http://localhost:5173/ in your browser to view the incident!")
    except Exception as e:
        print(f"[!] Error fetching details: {e}")

def direct_db_injection():
    from backend.app.db.database import SessionLocal
    from backend.app.models.incident import Incident

    db = SessionLocal()
    now = datetime.now(timezone.utc)
    target_ip = "185.220.101.5"

    emergency_incident = Incident(
        event_id=f"emergency-{uuid.uuid4().hex[:8]}",
        source_ip=target_ip,
        risk_score=96.5,
        severity="CRITICAL",
        status="OPEN",
        reasons="🚨 CRITICAL EMERGENCY: Coordinated Zero-Day Remote Code Execution & C2 Exfiltration detected.",
        threat_intel={
            "ip": target_ip,
            "is_private": False,
            "abuse_confidence_score": 98,
            "total_reports": 1420,
            "last_reported_at": now.isoformat(),
            "country_code": "RU",
            "domain": "bulletproof-hosting.xyz",
            "usage_type": "Tor Exit Node / Hosting",
            "status": "MALICIOUS",
            "source": "AbuseIPDB Threat Intelligence",
        },
        event_count=5,
        correlated_events=[
            {"event_id": f"evt-{uuid.uuid4().hex[:6]}", "timestamp": now.isoformat(), "destination_port": 443},
            {"event_id": f"evt-{uuid.uuid4().hex[:6]}", "timestamp": now.isoformat(), "destination_port": 8080},
            {"event_id": f"evt-{uuid.uuid4().hex[:6]}", "timestamp": now.isoformat(), "destination_port": 22},
            {"event_id": f"evt-{uuid.uuid4().hex[:6]}", "timestamp": now.isoformat(), "destination_port": 3389},
            {"event_id": f"evt-{uuid.uuid4().hex[:6]}", "timestamp": now.isoformat(), "destination_port": 53},
        ],
        mitre_attack={
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
        },
        created_at=now,
        last_seen_at=now,
    )

    db.add(emergency_incident)
    db.commit()
    db.refresh(emergency_incident)
    db.close()

    print("\n" + "="*60)
    print("  🚨 DIRECT EMERGENCY BREACH INJECTED INTO DATABASE 🚨")
    print("="*60)
    print(f"  Incident ID   : #{emergency_incident.id}")
    print(f"  Source IP     : {target_ip}")
    print(f"  Severity      : CRITICAL")
    print(f"  Risk Score    : 96.5 / 100")
    print(f"  Event Count   : 5 correlated multi-vector attacks")
    print(f"  Reasons       : {emergency_incident.reasons}")
    print("="*60)
    print("👉 Open http://localhost:5173/ in your browser to inspect the emergency incident live!")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--db":
        direct_db_injection()
    else:
        trigger_via_api()
