"""
SENTRIX AI Threat Analyst & Automated Reasoning Engine
-------------------------------------------------------
Provides grounded, schema-validated incident investigation summaries and
actionable defensive recommendations. Supports external LLM providers
(Google Gemini, OpenAI) with a 100% deterministic, offline-capable fallback
template (LocalRuleEngine).
"""

import json
import logging
import os
import re
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Any, Dict, Optional

logger = logging.getLogger("sentrix.ai_analyst")

VALID_ACTIONS = {"BLOCK_IP", "RATE_LIMIT", "ISOLATE_HOST", "MONITOR"}
VALID_CONFIDENCES = {"HIGH", "MEDIUM", "LOW"}


class AIThreatAnalyst:
    """Investigates incidents and generates structured threat intelligence reports."""

    def __init__(self):
        self.gemini_api_key = os.getenv("GEMINI_API_KEY")
        self.openai_api_key = os.getenv("OPENAI_API_KEY")

    def _extract_attributes(self, incident_data: Any) -> Dict[str, Any]:
        """Normalizes attributes whether passed an Incident model or a dict."""
        if hasattr(incident_data, "__dict__") and not isinstance(incident_data, dict):
            raw = {
                "id": getattr(incident_data, "id", None) or getattr(incident_data, "incident_id", None),
                "source_ip": getattr(incident_data, "source_ip", "UNKNOWN"),
                "risk_score": float(getattr(incident_data, "risk_score", 0.0) or 0.0),
                "severity": str(getattr(incident_data, "severity", "LOW")),
                "event_count": int(getattr(incident_data, "event_count", 1) or 1),
                "reasons": str(getattr(incident_data, "reasons", "")),
                "threat_intel": getattr(incident_data, "threat_intel", None) or {},
                "mitre_attack": getattr(incident_data, "mitre_attack", None) or {},
                "correlated_events": getattr(incident_data, "correlated_events", None) or [],
            }
        else:
            raw = dict(incident_data)

        # Extract target port from correlated events or features if available
        port = raw.get("destination_port")
        if not port and raw.get("correlated_events"):
            corr = raw["correlated_events"]
            if isinstance(corr, list) and len(corr) > 0 and isinstance(corr[-1], dict):
                port = corr[-1].get("destination_port")
        if not port:
            port = 80

        # Extract ML probability from reasons string if not passed directly
        ml_prob = raw.get("ml_confidence")
        if ml_prob is None:
            match = re.search(r"attack_probability=([0-9.]+)", raw.get("reasons", ""))
            if match:
                try:
                    ml_prob = float(match.group(1))
                except ValueError:
                    ml_prob = 0.95
            else:
                ml_prob = 0.95

        raw["destination_port"] = port
        raw["protocol"] = raw.get("protocol") or "TCP"
        raw["ml_confidence"] = float(ml_prob)

        return raw

    def construct_grounded_prompt(self, attrs: Dict[str, Any]) -> str:
        """Constructs a strict JSON-enforcing prompt from telemetry."""
        threat_intel = attrs.get("threat_intel") or {}
        mitre = attrs.get("mitre_attack") or {}

        abuse_score = threat_intel.get("abuse_confidence_score", 0)
        total_reports = threat_intel.get("total_reports", 0)
        country = threat_intel.get("country_code", "UNKNOWN")
        isp = threat_intel.get("domain", threat_intel.get("isp", "Unknown ISP"))

        technique_id = mitre.get("technique_id", "T1190")
        technique_name = mitre.get("technique_name", "Exploit Public-Facing Application")
        tactic = mitre.get("tactic", "Initial Access")

        return f"""You are the SENTRIX AI Threat Analyst. Analyze this confirmed security incident and generate a concise, grounded investigation report.
Return ONLY a valid JSON object matching the requested schema without markdown code blocks.

Incident Telemetry:
- Incident ID: #{attrs.get('id', 'N/A')}
- Severity: {attrs.get('severity', 'HIGH')}
- Dynamic Risk Score: {attrs.get('risk_score', 75.0)} / 100
- Correlated Event Count: {attrs.get('event_count', 1)}
- Source IP: {attrs.get('source_ip', 'UNKNOWN')}
- Destination Port: {attrs.get('destination_port', 80)} ({attrs.get('protocol', 'TCP')})
- Machine Learning Model: Binary Attack Classifier with {attrs.get('ml_confidence', 0.95)*100:.1f}% confidence
- Threat Intelligence: AbuseIPDB score {abuse_score}%, {total_reports} reports, Origin: {country} ({isp})
- MITRE ATT&CK: {technique_id} ({technique_name}), Tactic: {tactic}

Required JSON Output Schema:
{{
  "summary": "1-2 sentence executive summary of the incident",
  "analysis": "Technical reasoning referencing ML confidence, IP reputation, port context, and MITRE mapping",
  "recommended_action": "BLOCK_IP" | "RATE_LIMIT" | "ISOLATE_HOST" | "MONITOR",
  "action_target": "{attrs.get('source_ip', 'UNKNOWN')}",
  "confidence": "HIGH" | "MEDIUM" | "LOW"
}}"""

    def _generate_rule_based_analysis(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        """100% deterministic fallback generator providing realistic SOC analyses."""
        source_ip = attrs.get("source_ip", "UNKNOWN")
        port = attrs.get("destination_port", 80)
        proto = attrs.get("protocol", "TCP")
        event_count = attrs.get("event_count", 1)
        risk_score = attrs.get("risk_score", 50.0)
        severity = attrs.get("severity", "MEDIUM")
        ml_confidence = attrs.get("ml_confidence", 0.95)

        threat_intel = attrs.get("threat_intel") or {}
        abuse_score = threat_intel.get("abuse_confidence_score", 0)
        total_reports = threat_intel.get("total_reports", 0)
        country = threat_intel.get("country_code", "UNKNOWN")
        is_private = threat_intel.get("is_private", False)

        mitre = attrs.get("mitre_attack") or {}
        technique_id = mitre.get("technique_id", "T1190")
        technique_name = mitre.get("technique_name", "Exploit Public-Facing Application")
        tactic = mitre.get("tactic", "Initial Access")

        # 1. Executive Summary
        if event_count > 1:
            summary = (
                f"Sustained attack cluster: {event_count} malicious network flows detected from {source_ip} "
                f"targeting {proto} port {port}, consistent with MITRE ATT&CK technique {technique_id} ({technique_name})."
            )
        else:
            summary = (
                f"Anomalous network intrusion detected from {source_ip} targeting {proto} port {port}, "
                f"matching MITRE ATT&CK technique {technique_id} ({technique_name})."
            )

        # 2. Technical Reasoning
        rep_context = (
            f"threat intelligence identifies a verified private address (internal origin)"
            if is_private
            else f"external threat intelligence flags an abuse confidence score of {abuse_score}% across {total_reports} report(s) (Origin: {country})"
        )

        analysis = (
            f"The SENTRIX ML detection engine classified network flow telemetry as ATTACK with {ml_confidence * 100:.1f}% confidence. "
            f"Correlated {rep_context}. "
            f"The correlation engine aggregated {event_count} suspicious event(s) in the active window, yielding a dynamic risk score of "
            f"{risk_score}/100 ({severity} severity) executing under the {tactic} tactic."
        )

        # 3. Defensive Recommendation
        if risk_score >= 76.0 or abuse_score >= 80:
            recommended_action = "BLOCK_IP"
            confidence = "HIGH"
        elif risk_score >= 51.0 or abuse_score >= 30:
            recommended_action = "RATE_LIMIT"
            confidence = "MEDIUM"
        else:
            recommended_action = "MONITOR"
            confidence = "LOW"

        return {
            "summary": summary,
            "analysis": analysis,
            "recommended_action": recommended_action,
            "action_target": source_ip,
            "confidence": confidence,
            "provider": "LocalRuleEngine",
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    def _call_gemini(self, prompt: str, attrs: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Invokes Google Gemini API if GEMINI_API_KEY is configured."""
        if not self.gemini_api_key:
            return None

        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={self.gemini_api_key}"
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.2, "response_mime_type": "application/json"},
        }

        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )

        try:
            with urllib.request.urlopen(req, timeout=4.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                text = data["candidates"][0]["content"]["parts"][0]["text"]
                parsed = json.loads(text)
                return self._validate_and_format_result(parsed, attrs, "Gemini")
        except Exception as e:
            logger.warning("Gemini invocation failed or timed out: %s. Falling back to local rules.", e)
            return None

    def _call_openai(self, prompt: str, attrs: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Invokes OpenAI API if OPENAI_API_KEY is configured."""
        if not self.openai_api_key:
            return None

        url = "https://api.openai.com/v1/chat/completions"
        payload = {
            "model": "gpt-4o-mini",
            "messages": [
                {"role": "system", "content": "You are a cybersecurity incident responder that responds in valid JSON."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
            "response_format": {"type": "json_object"},
        }

        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.openai_api_key}",
            },
        )

        try:
            with urllib.request.urlopen(req, timeout=4.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                text = data["choices"][0]["message"]["content"]
                parsed = json.loads(text)
                return self._validate_and_format_result(parsed, attrs, "OpenAI")
        except Exception as e:
            logger.warning("OpenAI invocation failed or timed out: %s. Falling back to local rules.", e)
            return None

    def _validate_and_format_result(
        self, parsed: Dict[str, Any], attrs: Dict[str, Any], provider: str
    ) -> Dict[str, Any]:
        """Validates LLM output against the strict schema and backfills missing keys."""
        summary = str(parsed.get("summary") or "").strip()
        analysis = str(parsed.get("analysis") or "").strip()
        action = str(parsed.get("recommended_action") or "MONITOR").strip().upper()
        if action not in VALID_ACTIONS:
            action = "RATE_LIMIT" if attrs.get("risk_score", 0) >= 51 else "MONITOR"

        action_target = str(parsed.get("action_target") or attrs.get("source_ip", "UNKNOWN")).strip()
        confidence = str(parsed.get("confidence") or "MEDIUM").strip().upper()
        if confidence not in VALID_CONFIDENCES:
            confidence = "MEDIUM"

        if not summary or not analysis:
            # Fallback if text is blank
            return self._generate_rule_based_analysis(attrs)

        return {
            "summary": summary,
            "analysis": analysis,
            "recommended_action": action,
            "action_target": action_target,
            "confidence": confidence,
            "provider": provider,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    def analyze_incident(self, incident_data: Any) -> Dict[str, Any]:
        """
        Main entry point: Attempts configured LLM providers with 4.0s timeout,
        falling back deterministically to LocalRuleEngine on any failure or missing key.
        """
        attrs = self._extract_attributes(incident_data)
        prompt = self.construct_grounded_prompt(attrs)

        # 1. Try Gemini if configured
        if self.gemini_api_key:
            res = self._call_gemini(prompt, attrs)
            if res:
                return res

        # 2. Try OpenAI if configured
        if self.openai_api_key:
            res = self._call_openai(prompt, attrs)
            if res:
                return res

        # 3. Deterministic local fallback
        return self._generate_rule_based_analysis(attrs)


# Global singleton
ai_threat_analyst = AIThreatAnalyst()
