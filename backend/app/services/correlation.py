from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.orm import Session

from backend.app.models.incident import Incident


class CorrelationEngine:
    """
    Multi-event correlation, dynamic risk scoring, and MITRE ATT&CK technique mapping.
    Aggregates repeated security events from identical source IPs within sliding time windows.
    """

    def find_active_incident(
        self,
        db: Session,
        source_ip: Optional[str],
        time_window_minutes: int = 10,
    ) -> Optional[Incident]:
        """
        Locate the most recent active incident for a source IP within the sliding time window.
        """
        if not source_ip or not isinstance(source_ip, str):
            return None

        clean_ip = source_ip.strip()
        candidates = (
            db.query(Incident)
            .filter(
                Incident.source_ip == clean_ip,
                Incident.status.in_(["OPEN", "INVESTIGATING"]),
            )
            .order_by(Incident.id.desc())
            .all()
        )

        if not candidates:
            return None

        now_utc = datetime.now(timezone.utc)
        cutoff = now_utc - timedelta(minutes=time_window_minutes)

        for candidate in candidates:
            last_seen = candidate.last_seen_at or candidate.created_at
            if last_seen is not None:
                if last_seen.tzinfo is None:
                    last_seen = last_seen.replace(tzinfo=timezone.utc)
                if last_seen >= cutoff:
                    return candidate

        return None

    @staticmethod
    def calculate_risk_score(
        ml_confidence: float,
        abuse_score: int,
        event_count: int,
    ) -> tuple[float, str]:
        """
        Dynamically calculate risk score and assign severity band.
        Formula:
          raw_score = (ml_confidence * 40.0) + (abuse_score * 0.30) + (min(event_count, 5) * 6.0)
          score = min(100.0, round(raw_score, 1))

        Bands:
          score >= 76.0: CRITICAL
          score >= 51.0: HIGH
          score >= 26.0: MEDIUM
          score < 26.0:  LOW
        """
        conf = max(0.0, min(1.0, float(ml_confidence)))
        abuse = max(0, min(100, int(abuse_score)))
        count = max(1, int(event_count))

        raw_score = (conf * 40.0) + (abuse * 0.30) + (min(count, 5) * 6.0)
        score = min(100.0, round(raw_score, 1))

        if score >= 76.0:
            severity = "CRITICAL"
        elif score >= 51.0:
            severity = "HIGH"
        elif score >= 26.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return score, severity

    @staticmethod
    def map_mitre_technique(
        destination_port: Optional[int],
        protocol: str = "TCP",
    ) -> dict:
        """
        Map destination port and protocol to MITRE ATT&CK Enterprise technique and tactic.
        """
        port = destination_port

        if port in (80, 443, 8080):
            return {
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
            }
        elif port in (22, 3389):
            return {
                "technique_id": "T1021",
                "technique_name": "Remote Services",
                "tactic": "Lateral Movement",
            }
        elif port == 53:
            return {
                "technique_id": "T1071.004",
                "technique_name": "DNS Application Layer Protocol",
                "tactic": "Command and Control",
            }
        else:
            return {
                "technique_id": "T1498",
                "technique_name": "Network Denial of Service",
                "tactic": "Impact",
            }


correlation_engine = CorrelationEngine()
