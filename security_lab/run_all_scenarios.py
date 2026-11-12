"""
SENTRIX Security Lab — Master Scenario Runner & Audit Report
-----------------------------------------------------------
Executes all 3 attack and verification scenarios sequentially:
1. Network DoS & Volumetric Attack
2. Web Reconnaissance & Directory Enumeration
3. Benign Traffic & False-Positive Validation

Outputs an executive SOC Audit Table validating platform resilience.
"""

import os
import sys
import json
from pathlib import Path
from datetime import datetime, timezone

# Ensure project root directory is on sys.path for standalone script execution
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from security_lab.scenario_1_network_dos import run_scenario as run_scenario_1
from security_lab.scenario_2_web_recon import run_scenario as run_scenario_2
from security_lab.scenario_3_benign_traffic import run_scenario as run_scenario_3


def main():
    print("=" * 72)
    print("        SENTRIX SECURITY LAB — AUTOMATED ATTACK SIMULATION SUITE")
    print("=" * 72)
    print(f" Execution Started: {datetime.now(timezone.utc).isoformat()}")
    print(" Target: Local SENTRIX Deployment (http://127.0.0.1:8000)")

    sensor_key = os.getenv("SENTRIX_SENSOR_API_KEY", "").strip()
    if not sensor_key:
        print("[!] FATAL: SENTRIX_SENSOR_API_KEY environment variable is not configured.")
        print("    Configure SENTRIX_SENSOR_API_KEY before running the automated security lab.")
        return 1

    scenarios = []

    # Scenario 1
    try:
        s1 = run_scenario_1(sensor_key=sensor_key)
        scenarios.append(s1)
    except Exception as exc:
        scenarios.append({
            "scenario": "Network DoS & Volumetric Attack",
            "status": "ERROR",
            "error": str(exc),
        })

    # Scenario 2
    try:
        s2 = run_scenario_2(sensor_key=sensor_key)
        scenarios.append(s2)
    except Exception as exc:
        scenarios.append({
            "scenario": "Web Reconnaissance & Directory Enumeration",
            "status": "ERROR",
            "error": str(exc),
        })

    # Scenario 3
    try:
        s3 = run_scenario_3(sensor_key=sensor_key)
        scenarios.append(s3)
    except Exception as exc:
        scenarios.append({
            "scenario": "Benign Traffic & False-Positive Validation",
            "status": "ERROR",
            "error": str(exc),
        })

    # Print Executive Summary Table
    print("\n" + "=" * 72)
    print("                   EXECUTIVE SECURITY LAB AUDIT REPORT")
    print("=" * 72)
    print(f" {'Scenario':<42} | {'Result':<10} | {'Details'}")
    print("-" * 72)

    all_passed = True
    for sc in scenarios:
        name = sc["scenario"]
        status = sc["status"]
        if status != "PASSED":
            all_passed = False

        if "incident_id" in sc:
            details = f"Inc #{sc['incident_id']} ({sc.get('severity', 'N/A')})"
            if sc.get("ai_recommended_action"):
                details += f" -> {sc['ai_recommended_action']}"
            elif sc.get("mitre_technique"):
                details += f" -> MITRE {sc['mitre_technique']}"
        elif "false_positive_incidents_created" in sc:
            details = f"0 False Positives (Label={sc.get('ml_predicted_label', 'BENIGN')})"
        else:
            details = sc.get("error") or sc.get("reason", "N/A")

        print(f" {name:<42} | {status:<10} | {details}")

    print("=" * 72)
    if all_passed:
        print(" [PASSED] ALL 3 SECURITY SCENARIOS VALIDATED WITH ZERO REGRESSIONS.")
        return 0
    else:
        print(" [FAILED] ONE OR MORE SECURITY SCENARIOS FAILED AUDIT CHECKS.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
