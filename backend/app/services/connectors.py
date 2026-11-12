"""
SENTRIX Enterprise Telemetry Connectors & Universal Log Shipper
---------------------------------------------------------------
Parses, normalizes, and ingests heterogeneous enterprise security telemetry:
1. Web Access Logs: Nginx / Apache Combined and Common Log Formats.
2. Network IDS: Suricata / Snort EVE JSON alert streams.
3. Linux / System Authentication Logs: Syslog auth.log / secure SSH failed logins.
"""

import json
import re
import uuid
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any, Dict, List, Optional, Tuple


# Regex for Nginx/Apache Combined & Common Log Format:
# Matches: client_ip ident authuser [timestamp] "METHOD path HTTP/ver" status_code bytes ["referer" "user_agent"]
NGINX_COMBINED_REGEX = re.compile(
    r'^(\S+)\s+\S+\s+\S+\s+\[([\w:/]+\s[+\-]\d{4})\]\s+"(\S+)(?:\s+(\S+))?(?:\s+(\S+))?"\s+(\d{3})\s+(\d+|-)(?:\s+"([^"]*)"\s+"([^"]*)")?'
)

# Regex for SSH failed authentication in Syslog/auth.log:
# Examples:
# Failed password for invalid user admin from 198.51.100.77 port 48212 ssh2
# Failed password for root from 198.51.100.77 port 48214 ssh2
SYSLOG_AUTH_FAILED_REGEX = re.compile(
    r'Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+) ssh2',
    re.IGNORECASE,
)

# Common web recon / attack path patterns
SUSPICIOUS_WEB_PATHS = re.compile(
    r'(\.env|\.git|wp-admin|wp-login|config\.php|phpmyadmin|\.\./|/etc/passwd|cmd\.exe|/bin/sh|<script|select%20|union%20|/\.aws)',
    re.IGNORECASE,
)


class TelemetryConnectorService:
    """Service to parse, validate, and normalize diverse security telemetry into SENTRIX schema."""

    SUPPORTED_CONNECTORS = [
        {
            "id": "NGINX_ACCESS",
            "name": "Nginx / Apache Web Access Log",
            "format": "Combined Log Format (text)",
            "description": "Parses HTTP methods, target URIs, response status codes, and client IPs.",
            "status": "ACTIVE",
        },
        {
            "id": "SURICATA_EVE",
            "name": "Suricata / Snort NIDS Alert",
            "format": "EVE JSON (structured)",
            "description": "Parses Network IDS alert events, signature IDs, flow tuples, and threat categories.",
            "status": "ACTIVE",
        },
        {
            "id": "SYSLOG_AUTH",
            "name": "Linux Auth / SSH Syslog",
            "format": "Syslog text (auth.log / secure)",
            "description": "Extracts failed SSH authentications, targeted accounts, and source ports.",
            "status": "ACTIVE",
        },
        {
            "id": "NETWORK_FLOW",
            "name": "Network Flow (78-Feature ML)",
            "format": "Numerical vector (JSON)",
            "description": "Direct flow telemetry evaluated with the Random Forest / Stacking ML model.",
            "status": "ACTIVE",
        },
    ]

    def list_supported_connectors(self) -> List[Dict[str, Any]]:
        return self.SUPPORTED_CONNECTORS

    def _safe_ip(self, ip_str: Optional[str]) -> Optional[str]:
        if not ip_str:
            return None
        cleaned = ip_str.strip()
        try:
            return str(ip_address(cleaned))
        except ValueError:
            return None

    def _parse_nginx_timestamp(self, ts_str: str) -> datetime:
        """Parses Nginx log timestamps e.g. '10/Nov/2026:14:32:10 +0000'."""
        try:
            return datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)
        except Exception:
            return datetime.now(timezone.utc)

    def parse_web_access_log(self, line: str) -> Optional[Dict[str, Any]]:
        """
        Parses an Nginx/Apache Common or Combined log line.
        Returns normalized dictionary or None if unparseable.
        """
        if not line or not isinstance(line, str):
            return None
        cleaned = line.strip()
        match = NGINX_COMBINED_REGEX.match(cleaned)
        if not match:
            return None

        client_ip = match.group(1)
        ts_str = match.group(2)
        method = match.group(3) or "GET"
        path = match.group(4) or "/"
        http_ver = match.group(5) or "HTTP/1.1"
        status_code = int(match.group(6))
        bytes_sent = match.group(7)
        referer = match.group(8) if match.lastindex and match.lastindex >= 8 else None
        user_agent = match.group(9) if match.lastindex and match.lastindex >= 9 else None

        valid_ip = self._safe_ip(client_ip)
        observed_at = self._parse_nginx_timestamp(ts_str)

        # Assess if suspicious
        is_probing = bool(SUSPICIOUS_WEB_PATHS.search(path))
        is_client_error = status_code in (401, 403, 404)
        is_server_error = status_code >= 500
        is_suspicious = is_probing or is_client_error or is_server_error

        severity_hint = "LOW"
        reason = f"Web access flow {method} {path} returned HTTP {status_code}"
        if is_probing:
            severity_hint = "HIGH"
            reason = f"Web application probe targeting sensitive path '{path}' returned HTTP {status_code}"
        elif status_code == 401 or status_code == 403:
            severity_hint = "MEDIUM"
            reason = f"Unauthorized access attempt to '{path}' (HTTP {status_code})"
        elif is_server_error:
            severity_hint = "HIGH"
            reason = f"Server failure/exploit indicator on '{path}' (HTTP {status_code})"

        return {
            "event_id": str(uuid.uuid4()),
            "source_type": "NGINX_ACCESS",
            "event_type": "WEB_ACCESS",
            "observed_at": observed_at,
            "source_ip": valid_ip or client_ip,
            "destination_ip": "10.0.0.1",
            "source_port": None,
            "destination_port": 80,
            "protocol": "TCP",
            "is_suspicious": is_suspicious,
            "severity_hint": severity_hint,
            "detection_reason": reason,
            "raw_metadata": {
                "method": method,
                "path": path,
                "http_version": http_ver,
                "status_code": status_code,
                "bytes_sent": bytes_sent,
                "referer": referer,
                "user_agent": user_agent,
                "is_recon_path": is_probing,
            },
        }

    def parse_suricata_eve(self, data: Any) -> Optional[Dict[str, Any]]:
        """
        Parses a Suricata/Snort EVE JSON record.
        Accepts dict or raw JSON string.
        """
        payload: Dict[str, Any]
        if isinstance(data, str):
            try:
                payload = json.loads(data.strip())
            except Exception:
                return None
        elif isinstance(data, dict):
            payload = data
        else:
            return None

        src_ip = self._safe_ip(payload.get("src_ip") or payload.get("source_ip"))
        dest_ip = self._safe_ip(payload.get("dest_ip") or payload.get("destination_ip"))
        src_port = payload.get("src_port") or payload.get("source_port")
        dest_port = payload.get("dest_port") or payload.get("destination_port")
        proto = (payload.get("proto") or payload.get("protocol") or "TCP").upper()

        alert = payload.get("alert") or {}
        event_type = payload.get("event_type") or "alert"
        signature = alert.get("signature") or payload.get("signature") or "NIDS Anomalous Alert"
        category = alert.get("category") or "Network Intrusion"
        severity_num = alert.get("severity")  # Suricata severity: 1=High, 2=Medium, 3=Low

        # Parse timestamp
        ts_str = payload.get("timestamp")
        observed_at = datetime.now(timezone.utc)
        if ts_str:
            try:
                # Handle ISO timestamps with or without microseconds/Z
                clean_ts = ts_str.replace("Z", "+00:00")
                observed_at = datetime.fromisoformat(clean_ts).astimezone(timezone.utc)
            except Exception:
                pass

        severity_hint = "HIGH"
        if severity_num == 1:
            severity_hint = "CRITICAL"
        elif severity_num == 2:
            severity_hint = "HIGH"
        elif severity_num == 3:
            severity_hint = "MEDIUM"

        return {
            "event_id": str(uuid.uuid4()),
            "source_type": "SURICATA_EVE",
            "event_type": "NIDS_ALERT",
            "observed_at": observed_at,
            "source_ip": src_ip or payload.get("src_ip"),
            "destination_ip": dest_ip or payload.get("dest_ip"),
            "source_port": int(src_port) if src_port is not None else None,
            "destination_port": int(dest_port) if dest_port is not None else 80,
            "protocol": proto,
            "is_suspicious": True,
            "severity_hint": severity_hint,
            "detection_reason": f"Suricata NIDS Alert: [{category}] {signature}",
            "raw_metadata": {
                "suricata_event_type": event_type,
                "signature": signature,
                "signature_id": alert.get("signature_id"),
                "category": category,
                "suricata_severity": severity_num,
                "action": alert.get("action", "allowed"),
            },
        }

    def parse_syslog_auth(self, line: str) -> Optional[Dict[str, Any]]:
        """
        Parses Linux syslog auth.log line for SSH authentication failures.
        """
        if not line or not isinstance(line, str):
            return None
        cleaned = line.strip()
        match = SYSLOG_AUTH_FAILED_REGEX.search(cleaned)
        if not match:
            return None

        username = match.group(1)
        src_ip = match.group(2)
        src_port = int(match.group(3))

        valid_ip = self._safe_ip(src_ip)

        return {
            "event_id": str(uuid.uuid4()),
            "source_type": "SYSLOG_AUTH",
            "event_type": "AUTH_FAILURE",
            "observed_at": datetime.now(timezone.utc),
            "source_ip": valid_ip or src_ip,
            "destination_ip": "10.0.0.1",
            "source_port": src_port,
            "destination_port": 22,
            "protocol": "TCP",
            "is_suspicious": True,
            "severity_hint": "HIGH" if username.lower() in ("root", "admin", "administrator") else "MEDIUM",
            "detection_reason": f"SSH failed authentication for user '{username}' from {src_ip}:{src_port}",
            "raw_metadata": {
                "target_username": username,
                "service": "sshd",
                "auth_method": "password",
                "failure_reason": "Failed password",
            },
        }

    def normalize(self, source_type: str, raw_payload: Any) -> Optional[Dict[str, Any]]:
        """
        Routes the raw payload to the appropriate parser based on source_type.
        """
        st = (source_type or "").strip().upper()
        if st == "NGINX_ACCESS":
            return self.parse_web_access_log(str(raw_payload))
        elif st == "SURICATA_EVE":
            return self.parse_suricata_eve(raw_payload)
        elif st == "SYSLOG_AUTH":
            return self.parse_syslog_auth(str(raw_payload))
        else:
            raise ValueError(f"Unsupported connector source_type '{source_type}'.")


# Singleton instance
telemetry_connector_service = TelemetryConnectorService()
