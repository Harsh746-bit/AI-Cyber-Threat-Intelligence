from datetime import datetime, timezone
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from backend.app.db.database import get_db
from backend.app.models.incident import Incident
from backend.app.models.security_event import SecurityEventRecord
from backend.app.models.user import User
from backend.app.schemas.security_event import SecurityEvent
from backend.app.services.auth import require_role
from backend.app.services.connectors import telemetry_connector_service
from backend.app.services.detection import analyze_event
from backend.app.services.ingestion_pipeline import (
    incident_to_dict,
    ingestion_pipeline,
)
from backend.app.services.ml_detection import predict_attack
from backend.app.services.response_engine import response_engine
from backend.app.services.sensor_auth import require_sensor_key
from backend.app.services.threat_intelligence import threat_intel_service

router = APIRouter(tags=["events"])


class RawIngestRequest(BaseModel):
    source_type: str = Field(min_length=1, max_length=50)
    raw_payload: Any = Field(...)


def _process_raw_telemetry(req: RawIngestRequest, db: Session) -> dict:
    source_type = req.source_type.strip().upper()
    valid_sources = {"NGINX_ACCESS", "SURICATA_EVE", "SYSLOG_AUTH"}
    if source_type not in valid_sources:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported source_type '{req.source_type}'. Supported: {', '.join(sorted(valid_sources))}",
        )

    try:
        normalized = telemetry_connector_service.normalize(source_type, req.raw_payload)
    except Exception as exc:
        raise HTTPException(
            status_code=422,
            detail=f"Failed to parse raw telemetry: {str(exc)}",
        ) from exc

    if not normalized:
        raise HTTPException(
            status_code=422,
            detail="Failed to parse raw telemetry: unrecognized log format or empty payload.",
        )

    source_ip = normalized.get("source_ip")
    # Ingestion Gate: enforce active firewall containment
    if source_ip and response_engine.is_ip_blocked(db, source_ip):
        raise HTTPException(
            status_code=403,
            detail=f"Event dropped: Source IP {source_ip} is actively blocked by SENTRIX Response Engine.",
        )

    # Persist normalized security event record
    event_record = SecurityEventRecord(
        event_id=normalized["event_id"],
        schema_version="1.0",
        event_type=normalized["event_type"],
        observed_at=normalized.get("observed_at"),
        source_ip=source_ip,
        destination_ip=normalized.get("destination_ip"),
        source_port=normalized.get("source_port"),
        destination_port=normalized.get("destination_port"),
        protocol=normalized.get("protocol"),
        features=normalized.get("raw_metadata") or {},
    )
    try:
        db.add(event_record)
        db.commit()
        db.refresh(event_record)
    except Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Failed to persist normalized security event.",
        ) from exc

    incident_created = False
    incident_id = None

    # Threat evaluation & correlation via shared IngestionPipeline
    is_suspicious = normalized.get("is_suspicious", False)
    status_code = normalized.get("raw_metadata", {}).get("status_code")
    if is_suspicious or normalized["event_type"] in ("NIDS_ALERT", "AUTH_FAILURE") or (status_code and status_code in (401, 403, 404, 500)):
        effective_dest_port = normalized.get("destination_port")

        base_prob = 0.60
        if normalized["event_type"] == "NIDS_ALERT":
            base_prob = 0.95
        elif normalized["event_type"] == "AUTH_FAILURE":
            base_prob = 0.90
        elif normalized.get("raw_metadata", {}).get("is_recon_path"):
            base_prob = 0.75

        # Determine MITRE mapping override
        if normalized["event_type"] == "AUTH_FAILURE":
            mitre_override = {
                "technique_id": "T1110",
                "technique_name": "Brute Force",
                "tactic": "Credential Access",
            }
        elif normalized["event_type"] == "NIDS_ALERT":
            mitre_override = {
                "technique_id": "T1046",
                "technique_name": "Network Service Discovery",
                "tactic": "Discovery",
            }
        elif normalized.get("raw_metadata", {}).get("is_recon_path"):
            mitre_override = {
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
            }
        else:
            mitre_override = None

        try:
            pipeline_res = ingestion_pipeline.process_threat_event(
                db=db,
                event_id=normalized["event_id"],
                source_ip=source_ip,
                destination_port=effective_dest_port,
                protocol=normalized.get("protocol") or "TCP",
                observed_at=normalized.get("observed_at"),
                source_type=source_type,
                event_type=normalized["event_type"],
                detection_reason=normalized.get("detection_reason") or "",
                attack_probability=base_prob,
                mitre_attack_override=mitre_override,
                is_ml_flow=False,
            )
            incident_created = pipeline_res["incident_created"]
            incident_id = pipeline_res["incident_id"]
        except Exception:
            pass

    serialized_norm = dict(normalized)
    if isinstance(serialized_norm.get("observed_at"), datetime):
        serialized_norm["observed_at"] = serialized_norm["observed_at"].isoformat()

    return {
        "status": "ACCEPTED",
        "source_type": source_type,
        "normalized_event_id": normalized["event_id"],
        "incident_created": incident_created,
        "incident_id": incident_id,
        "normalized_data": serialized_norm,
    }


def _process_security_event(event: SecurityEvent, db: Session) -> dict:
    if event.source_ip and response_engine.is_ip_blocked(db, event.source_ip):
        raise HTTPException(
            status_code=403,
            detail=f"Event dropped: Source IP {event.source_ip} is actively blocked by SENTRIX Response Engine.",
        )

    event_id = str(event.event_id)

    existing_event = (
        db.query(SecurityEventRecord)
        .filter(SecurityEventRecord.event_id == event_id)
        .first()
    )
    if existing_event is not None:
        raise HTTPException(
            status_code=409,
            detail="An event with this event_id already exists.",
        )

    event_record = SecurityEventRecord(
        event_id=event_id,
        schema_version=event.schema_version,
        event_type=event.event_type,
        observed_at=event.observed_at,
        source_ip=event.source_ip,
        destination_ip=event.destination_ip,
        source_port=event.source_port,
        destination_port=event.destination_port,
        protocol=str(event.protocol) if event.protocol is not None else None,
        features=event.features,
    )

    try:
        db.add(event_record)
        db.commit()
        db.refresh(event_record)
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="An event with this event_id already exists.",
        ) from exc
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Failed to persist the security event.",
        ) from exc

    response = {
        "status": "accepted",
        "event_id": event_record.event_id,
        "event_type": event_record.event_type,
        "schema_version": event_record.schema_version,
        "message": "Security event validated and persisted.",
        "analysis_status": "PENDING",
        "analysis_type": None,
        "predicted_label": None,
        "attack_probability": None,
        "incident_created": False,
        "incident_id": None,
    }

    try:
        result = predict_attack(event.features)
    except ValueError as exc:
        detail = exc.args[0] if exc.args else str(exc)
        response.update({
            "analysis_status": "PENDING",
            "analysis_message": "ML analysis requires exactly the trained feature set.",
            "feature_validation_error": detail,
        })
        return response
    except FileNotFoundError:
        response.update({
            "analysis_status": "UNAVAILABLE",
            "analysis_message": "The ML model artifact is unavailable.",
        })
        return response
    except Exception:
        # The event has already been committed; retain it if inference fails.
        response.update({
            "analysis_status": "FAILED",
            "analysis_message": "The event was stored, but ML inference failed.",
        })
        return response

    response.update({
        "analysis_status": "COMPLETED",
        "analysis_type": "machine_learning",
        "predicted_label": result["predicted_label"],
        "attack_probability": result["attack_probability"],
        "model_type": result["model_type"],
        "feature_count": result["feature_count"],
    })

    if result["predicted_label"] != "ATTACK":
        response["analysis_message"] = "ML prediction was BENIGN; no incident was created."
        return response

    probability = result["attack_probability"]

    # Check if this exact event_id already created an incident
    existing_event_incident = (
        db.query(Incident)
        .filter(Incident.event_id == event_id)
        .first()
    )
    if existing_event_incident is not None:
        response.update({
            "incident_created": False,
            "incident_id": existing_event_incident.id,
            "analysis_message": "An incident already exists for this event.",
        })
        return response

    # Determine effective destination port (from field or features dict)
    effective_dest_port = event.destination_port
    if effective_dest_port is None and event.features and "Destination Port" in event.features:
        try:
            effective_dest_port = int(event.features["Destination Port"])
        except (ValueError, TypeError):
            effective_dest_port = None

    # Triage and correlate through the shared IngestionPipeline
    try:
        pipeline_res = ingestion_pipeline.process_threat_event(
            db=db,
            event_id=event_id,
            source_ip=event.source_ip,
            destination_port=effective_dest_port,
            protocol=str(event.protocol) if event.protocol else "TCP",
            observed_at=event.observed_at,
            source_type="NETWORK_FLOW",
            event_type=event.event_type,
            detection_reason="",
            attack_probability=probability,
            model_type=result["model_type"],
            mitre_attack_override=None,
            is_ml_flow=True,
        )
    except IntegrityError:
        existing_incident = (
            db.query(Incident)
            .filter(Incident.event_id == event_id)
            .first()
        )
        if existing_incident is not None:
            response.update({
                "incident_created": False,
                "incident_id": existing_incident.id,
                "analysis_message": "An incident already exists for this event.",
            })
            return response
        response.update({
            "analysis_status": "INCIDENT_CREATION_FAILED",
            "analysis_message": "An integrity conflict occurred while saving the incident.",
        })
        return response
    except SQLAlchemyError:
        response.update({
            "analysis_status": "INCIDENT_CREATION_FAILED",
            "analysis_message": (
                "The event was stored and analyzed as ATTACK, "
                "but the incident could not be saved."
            ),
        })
        return response

    if pipeline_res["status"] == "CORRELATED":
        active_inc = pipeline_res["incident"]
        response.update({
            "incident_created": False,
            "incident_id": active_inc.id,
            "analysis_message": f"ML prediction was ATTACK; correlated into active incident #{active_inc.id} (event {active_inc.event_count}).",
        })
    elif pipeline_res["status"] == "ALREADY_EXISTS":
        response.update({
            "incident_created": False,
            "incident_id": pipeline_res["incident_id"],
            "analysis_message": "An incident already exists for this event.",
        })
    else:
        response.update({
            "incident_created": True,
            "incident_id": pipeline_res["incident_id"],
            "analysis_message": "ML prediction was ATTACK; an incident was created.",
        })

    return response


@router.get("/api/v1/ingest/connectors")
def get_supported_connectors():
    """Returns the list of supported telemetry connectors and formats."""
    return {"supported_connectors": telemetry_connector_service.list_supported_connectors()}


@router.post("/api/v1/ingest/raw", status_code=202)
def ingest_raw_telemetry(
    req: RawIngestRequest,
    sensor_key: str = Depends(require_sensor_key),
    db: Session = Depends(get_db),
):
    """
    Ingest raw enterprise telemetry from external sensor forwarders.
    Guarded by dedicated X-SENTRIX-SENSOR-KEY header.
    """
    return _process_raw_telemetry(req, db)


@router.post("/api/v1/simulation/raw", status_code=202)
def simulate_raw_telemetry(
    req: RawIngestRequest,
    current_user: User = Depends(require_role(["admin", "analyst"])),
    db: Session = Depends(get_db),
):
    """
    Authenticated SecOps analyst simulation for raw telemetry.
    Guarded by User JWT RBAC (requires admin or analyst role).
    """
    return _process_raw_telemetry(req, db)


@router.post("/api/v1/events", status_code=202)
def ingest_security_event(
    event: SecurityEvent,
    sensor_key: str = Depends(require_sensor_key),
    db: Session = Depends(get_db),
):
    """
    Ingest structured network flow event from external sensors.
    Guarded by dedicated X-SENTRIX-SENSOR-KEY header.
    """
    return _process_security_event(event, db)


@router.post("/api/v1/simulation/event", status_code=202)
def simulate_security_event(
    event: SecurityEvent,
    current_user: User = Depends(require_role(["admin", "analyst"])),
    db: Session = Depends(get_db),
):
    """
    Authenticated SecOps analyst simulation for structured events.
    Guarded by User JWT RBAC (requires admin or analyst role).
    """
    return _process_security_event(event, db)


@router.post("/api/v1/analyze")
def analyze_security_event(
    event: SecurityEvent,
    sensor_key: str = Depends(require_sensor_key),
    db: Session = Depends(get_db),
):
    """Run the existing rule-based prototype where its required fields exist."""
    try:
        result = analyze_event(event)
    except (AttributeError, TypeError) as exc:
        raise HTTPException(
            status_code=422,
            detail=(
                "Rule-based analysis requires failed_logins, requests_per_minute, "
                "and known_malicious_ip. These fields are not part of the current "
                "NETWORK_FLOW event schema."
            ),
        ) from exc

    threat_intel = None
    if event.source_ip:
        threat_intel = threat_intel_service.check_ip(event.source_ip)

    incident = Incident(
        source_ip=event.source_ip or "UNKNOWN",
        risk_score=result["risk_score"],
        severity=result["severity"],
        reasons="; ".join(result["reasons"]),
        threat_intel=threat_intel,
    )
    try:
        db.add(incident)
        db.commit()
        db.refresh(incident)
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Failed to save the incident.",
        ) from exc

    return {
        **incident_to_dict(incident),
        "reasons": result["reasons"],
        "analysis_type": "rule_based_prototype",
    }
