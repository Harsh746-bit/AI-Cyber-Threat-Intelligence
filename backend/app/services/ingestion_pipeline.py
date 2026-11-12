import json
import re
from datetime import datetime, timezone
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from backend.app.models.incident import Incident
from backend.app.models.response import ResponseAction
from backend.app.services.ai_analyst import ai_threat_analyst
from backend.app.services.correlation import correlation_engine
from backend.app.services.threat_intelligence import threat_intel_service


def severity_from_score(score: int | float) -> str:
    """Classifies risk score into severity tier."""
    if score >= 70:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    return "LOW"


def response_to_dict(action: ResponseAction) -> dict:
    """Serializes a ResponseAction SQLAlchemy model to dictionary."""
    return {
        "id": action.id,
        "incident_id": action.incident_id,
        "action_type": action.action_type,
        "target": action.target,
        "status": action.status,
        "requested_by": action.requested_by,
        "approved_by": action.approved_by,
        "execution_output": action.execution_output,
        "is_active": action.is_active,
        "created_at": action.created_at.isoformat() if action.created_at else None,
        "executed_at": action.executed_at.isoformat() if action.executed_at else None,
    }


def auto_propose_response_action(db: Session, incident: Incident) -> None:
    """Auto-propose a PENDING containment action if AI recommended BLOCK_IP, RATE_LIMIT, or ISOLATE_HOST."""
    if not incident or not incident.ai_analysis:
        return
    rec = incident.ai_analysis.get("recommended_action")
    target = incident.ai_analysis.get("action_target") or incident.source_ip
    if rec in ("BLOCK_IP", "RATE_LIMIT", "ISOLATE_HOST") and target:
        existing = (
            db.query(ResponseAction)
            .filter(
                ResponseAction.incident_id == incident.id,
                ResponseAction.action_type == rec,
                ResponseAction.target == target,
            )
            .first()
        )
        if not existing:
            action = ResponseAction(
                incident_id=incident.id,
                action_type=rec,
                target=target,
                status="PENDING",
                requested_by="AIThreatAnalyst",
                is_active=False,
            )
            db.add(action)
            try:
                db.commit()
            except Exception:
                db.rollback()


def incident_to_dict(incident: Incident, db: Session | None = None) -> dict:
    """Serializes an Incident SQLAlchemy model to dictionary."""
    threat_intel = incident.threat_intel
    if isinstance(threat_intel, str):
        try:
            threat_intel = json.loads(threat_intel)
        except Exception:
            pass

    correlated_events = incident.correlated_events
    if isinstance(correlated_events, str):
        try:
            correlated_events = json.loads(correlated_events)
        except Exception:
            correlated_events = []

    mitre_attack = incident.mitre_attack
    if isinstance(mitre_attack, str):
        try:
            mitre_attack = json.loads(mitre_attack)
        except Exception:
            pass

    ai_analysis = incident.ai_analysis
    if isinstance(ai_analysis, str):
        try:
            ai_analysis = json.loads(ai_analysis)
        except Exception:
            pass

    investigation_notes = incident.investigation_notes
    if isinstance(investigation_notes, str):
        try:
            investigation_notes = json.loads(investigation_notes)
        except Exception:
            investigation_notes = []
    elif investigation_notes is None:
        investigation_notes = []

    responses_data = []
    if db is not None:
        try:
            actions = (
                db.query(ResponseAction)
                .filter(ResponseAction.incident_id == incident.id)
                .order_by(ResponseAction.id.desc())
                .all()
            )
            responses_data = [response_to_dict(a) for a in actions]
        except Exception:
            pass

    return {
        "incident_id": incident.id,
        "event_id": incident.event_id,
        "source_ip": incident.source_ip,
        "risk_score": incident.risk_score,
        "severity": incident.severity,
        "status": incident.status,
        "reasons": incident.reasons,
        "threat_intel": threat_intel,
        "event_count": incident.event_count if incident.event_count is not None else 1,
        "correlated_events": correlated_events if correlated_events is not None else [],
        "mitre_attack": mitre_attack,
        "ai_analysis": ai_analysis,
        "assigned_to": incident.assigned_to,
        "investigation_notes": investigation_notes,
        "responses": responses_data,
        "last_seen_at": (
            incident.last_seen_at.isoformat()
            if incident.last_seen_at
            else None
        ),
        "created_at": incident.created_at,
    }


class IngestionPipeline:
    """
    Unified Ingestion & Triage Pipeline Service.
    Processes security events (ML-detected network flows or normalized raw telemetry),
    handles sliding-window correlation, threat intelligence enrichment, dynamic risk scoring,
    MITRE ATT&CK taxonomy mapping, AI Threat Analyst triage, and automated containment proposal.
    """

    @staticmethod
    def process_threat_event(
        db: Session,
        event_id: str,
        source_ip: str | None,
        destination_port: int | None = None,
        protocol: str = "TCP",
        observed_at: datetime | None = None,
        source_type: str = "NETWORK_FLOW",
        event_type: str = "NETWORK_FLOW",
        detection_reason: str = "",
        attack_probability: float = 0.60,
        model_type: str | None = None,
        mitre_attack_override: dict | None = None,
        is_ml_flow: bool = False,
    ) -> dict:
        now_utc = datetime.now(timezone.utc)
        timestamp_str = (
            observed_at.isoformat()
            if observed_at
            else now_utc.isoformat()
        )

        # 1. Check for active incident within correlation window
        active_incident = correlation_engine.find_active_incident(db, source_ip) if source_ip else None

        if active_incident is not None:
            active_incident.event_count = (active_incident.event_count or 1) + 1

            if is_ml_flow:
                new_entry = {
                    "event_id": event_id,
                    "timestamp": timestamp_str,
                    "destination_port": destination_port,
                }
            else:
                new_entry = {
                    "event_id": event_id,
                    "timestamp": timestamp_str,
                    "destination_port": destination_port,
                    "source_type": source_type,
                    "event_type": event_type,
                }

            curr_events = list(active_incident.correlated_events or [])
            curr_events.append(new_entry)
            active_incident.correlated_events = curr_events
            active_incident.last_seen_at = now_utc

            abuse_score = (
                active_incident.threat_intel.get("abuse_confidence_score", 0)
                if active_incident.threat_intel
                else 0
            )

            if is_ml_flow:
                prev_prob = 0.0
                match = re.search(r"attack_probability=([0-9.]+)", active_incident.reasons or "")
                if match:
                    try:
                        prev_prob = float(match.group(1))
                    except ValueError:
                        pass
                effective_prob = max(attack_probability, prev_prob)

                score, severity = correlation_engine.calculate_risk_score(
                    effective_prob, abuse_score, active_incident.event_count
                )
                active_incident.risk_score = max(score, active_incident.risk_score or 0.0)
                active_incident.severity = severity
                active_incident.reasons = (
                    f"[Aggregated] {active_incident.event_count} malicious network flows detected from {source_ip}; "
                    f"attack_probability={effective_prob:.6f}"
                )
                ai_prob = effective_prob
            else:
                score, severity = correlation_engine.calculate_risk_score(
                    attack_probability, abuse_score, active_incident.event_count
                )
                active_incident.risk_score = max(score, active_incident.risk_score or 0.0)
                active_incident.severity = severity
                active_incident.reasons = (
                    f"[{source_type}] {detection_reason}; "
                    f"total_correlated_events={active_incident.event_count}"
                )
                ai_prob = attack_probability

            try:
                active_incident.ai_analysis = ai_threat_analyst.analyze_incident({
                    "id": active_incident.id,
                    "source_ip": source_ip or "UNKNOWN",
                    "risk_score": active_incident.risk_score,
                    "severity": active_incident.severity,
                    "event_count": active_incident.event_count,
                    "destination_port": destination_port,
                    "protocol": protocol,
                    "ml_confidence": ai_prob,
                    "threat_intel": active_incident.threat_intel,
                    "mitre_attack": active_incident.mitre_attack,
                    "reasons": active_incident.reasons,
                    "correlated_events": active_incident.correlated_events,
                })
            except Exception:
                pass

            try:
                db.commit()
                db.refresh(active_incident)
                auto_propose_response_action(db, active_incident)
                return {
                    "incident_created": False,
                    "incident_id": active_incident.id,
                    "incident": active_incident,
                    "status": "CORRELATED",
                }
            except Exception:
                db.rollback()
                raise

        # 2. No active incident: create a new incident
        threat_intel = threat_intel_service.check_ip(source_ip) if source_ip else None
        abuse_score = threat_intel.get("abuse_confidence_score", 0) if threat_intel else 0
        score, severity = correlation_engine.calculate_risk_score(attack_probability, abuse_score, 1)

        if mitre_attack_override:
            mitre_attack = mitre_attack_override
        else:
            mitre_attack = correlation_engine.map_mitre_technique(destination_port, protocol)

        if is_ml_flow:
            initial_correlated = [{
                "event_id": event_id,
                "timestamp": timestamp_str,
                "destination_port": destination_port,
            }]
            reasons_str = (
                "Machine-learning model predicted ATTACK; "
                f"attack_probability={attack_probability:.6f}; "
                f"model_type={model_type or 'RandomForestClassifier'}"
            )
            ai_reasons_param = f"attack_probability={attack_probability:.6f}"
        else:
            initial_correlated = [{
                "event_id": event_id,
                "timestamp": timestamp_str,
                "destination_port": destination_port,
                "source_type": source_type,
                "event_type": event_type,
            }]
            reasons_str = f"[{source_type}] {detection_reason}"
            ai_reasons_param = reasons_str

        ai_report = None
        try:
            ai_report = ai_threat_analyst.analyze_incident({
                "id": None,
                "source_ip": source_ip or "UNKNOWN",
                "risk_score": score,
                "severity": severity,
                "event_count": 1,
                "destination_port": destination_port,
                "protocol": protocol,
                "ml_confidence": attack_probability,
                "threat_intel": threat_intel,
                "mitre_attack": mitre_attack,
                "reasons": ai_reasons_param,
                "correlated_events": initial_correlated,
            })
        except Exception:
            pass

        incident = Incident(
            event_id=event_id,
            source_ip=source_ip or "UNKNOWN",
            risk_score=score,
            severity=severity,
            reasons=reasons_str,
            threat_intel=threat_intel,
            event_count=1,
            correlated_events=initial_correlated,
            mitre_attack=mitre_attack,
            ai_analysis=ai_report,
            last_seen_at=now_utc,
        )

        try:
            db.add(incident)
            db.commit()
            db.refresh(incident)
            auto_propose_response_action(db, incident)
            return {
                "incident_created": True,
                "incident_id": incident.id,
                "incident": incident,
                "status": "CREATED",
            }
        except IntegrityError:
            db.rollback()
            existing_incident = (
                db.query(Incident)
                .filter(Incident.event_id == event_id)
                .first()
            )
            if existing_incident is not None:
                return {
                    "incident_created": False,
                    "incident_id": existing_incident.id,
                    "incident": existing_incident,
                    "status": "ALREADY_EXISTS",
                }
            raise
        except SQLAlchemyError:
            db.rollback()
            raise


ingestion_pipeline = IngestionPipeline()
