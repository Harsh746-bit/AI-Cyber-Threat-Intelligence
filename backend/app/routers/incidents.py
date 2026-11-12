import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from backend.app.db.database import get_db
from backend.app.models.incident import Incident
from backend.app.models.user import User
from backend.app.services.ai_analyst import ai_threat_analyst
from backend.app.services.auth import require_role
from backend.app.services.ingestion_pipeline import (
    auto_propose_response_action,
    incident_to_dict,
)

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])


class IncidentStatusUpdate(BaseModel):
    status: str


class AddNoteRequest(BaseModel):
    author: str = Field(default="SecOps Analyst", min_length=1, max_length=100)
    content: str = Field(min_length=1, max_length=1000)


class AssignIncidentRequest(BaseModel):
    assigned_to: str = Field(min_length=1, max_length=100)


@router.get("")
@router.get("/")
def get_incidents(
    limit: int = Query(default=20, ge=1, le=100),
    severity: str | None = Query(default=None),
    search: str | None = Query(default=None),
    current_user: User = Depends(require_role(["admin", "analyst"])),
    db: Session = Depends(get_db),
):
    query = db.query(Incident)

    if severity:
        severity_value = severity.strip().upper()
        if severity_value not in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            raise HTTPException(
                status_code=400,
                detail="Severity must be LOW, MEDIUM, HIGH, or CRITICAL",
            )
        query = query.filter(Incident.severity == severity_value)

    if search:
        search_value = search.strip()
        if search_value.isdigit():
            query = query.filter(Incident.id == int(search_value))
        elif search_value:
            query = query.filter(Incident.source_ip.contains(search_value))

    incidents = query.order_by(Incident.id.desc()).limit(limit).all()
    return {
        "total_returned": len(incidents),
        "incidents": [incident_to_dict(incident, db=db) for incident in incidents],
    }


# /summary must be registered before /{incident_id} so FastAPI does not
# treat the literal string "summary" as an integer path parameter.
@router.get("/summary")
def get_incident_summary(db: Session = Depends(get_db)):
    total = db.query(Incident).count()
    low = db.query(Incident).filter(Incident.severity == "LOW").count()
    medium = db.query(Incident).filter(Incident.severity == "MEDIUM").count()
    high = db.query(Incident).filter(Incident.severity == "HIGH").count()
    critical = db.query(Incident).filter(Incident.severity == "CRITICAL").count()

    status_breakdown = {
        "OPEN": db.query(Incident).filter(Incident.status == "OPEN").count(),
        "INVESTIGATING": db.query(Incident).filter(Incident.status == "INVESTIGATING").count(),
        "RESOLVED": db.query(Incident).filter(Incident.status == "RESOLVED").count(),
    }

    severity_breakdown = {"LOW": low, "MEDIUM": medium, "HIGH": high}
    if critical > 0:
        severity_breakdown["CRITICAL"] = critical

    return {
        "total_incidents": total,
        "severity_breakdown": severity_breakdown,
        "status_breakdown": status_breakdown,
    }


@router.get("/{incident_id}")
def get_incident(
    incident_id: int,
    current_user: User = Depends(require_role(["admin", "analyst"])),
    db: Session = Depends(get_db),
):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident_to_dict(incident, db=db)


@router.patch("/{incident_id}/status")
def update_incident_status(
    incident_id: int,
    update: IncidentStatusUpdate,
    current_user: User = Depends(require_role(["admin"])),
    db: Session = Depends(get_db),
):
    allowed_statuses = ["OPEN", "INVESTIGATING", "RESOLVED"]
    new_status = update.status.strip().upper()

    if new_status not in allowed_statuses:
        raise HTTPException(
            status_code=400,
            detail="Status must be OPEN, INVESTIGATING, or RESOLVED",
        )

    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident.status = new_status
    try:
        db.commit()
        db.refresh(incident)
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Failed to update the incident status.",
        ) from exc

    return incident_to_dict(incident, db=db)


@router.post("/{incident_id}/analyze-ai")
def trigger_ai_incident_analysis(
    incident_id: int,
    current_user: User = Depends(require_role(["admin", "analyst"])),
    db: Session = Depends(get_db),
):
    """
    On-demand AI Threat Analyst investigation.
    Digests structured incident telemetry and updates incident.ai_analysis.
    Requires Analyst or Admin role.
    """
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    try:
        analysis_result = ai_threat_analyst.analyze_incident(incident)
        incident.ai_analysis = analysis_result
        db.commit()
        db.refresh(incident)
        auto_propose_response_action(db, incident)
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to persist AI analysis") from exc

    return incident_to_dict(incident, db=db)


@router.post("/{incident_id}/notes")
def add_incident_note(
    incident_id: int,
    note_req: AddNoteRequest,
    current_user: User = Depends(require_role(["admin", "analyst"])),
    db: Session = Depends(get_db),
):
    """
    Append a timestamped analyst investigation note to an incident.
    """
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    author = note_req.author.strip()
    if (not author or author == "SecOps Analyst") and current_user:
        author = current_user.username

    curr_notes = list(incident.investigation_notes or [])
    new_note = {
        "note_id": str(uuid.uuid4()),
        "author": author or "SecOps Analyst",
        "content": note_req.content.strip(),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    curr_notes.append(new_note)
    incident.investigation_notes = curr_notes

    try:
        db.commit()
        db.refresh(incident)
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to save investigation note") from exc

    return incident_to_dict(incident, db=db)


@router.patch("/{incident_id}/assign")
def assign_incident(
    incident_id: int,
    assign_req: AssignIncidentRequest,
    current_user: User = Depends(require_role(["admin", "analyst"])),
    db: Session = Depends(get_db),
):
    """
    Assign or reassign an incident to a designated analyst or team.
    """
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident.assigned_to = assign_req.assigned_to.strip()

    try:
        db.commit()
        db.refresh(incident)
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to update incident assignment") from exc

    return incident_to_dict(incident, db=db)
