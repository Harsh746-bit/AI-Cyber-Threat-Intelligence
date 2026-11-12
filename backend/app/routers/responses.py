import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from backend.app.db.database import get_db
from backend.app.models.incident import Incident
from backend.app.models.response import ResponseAction
from backend.app.models.user import User
from backend.app.services.auth import require_role
from backend.app.services.ingestion_pipeline import response_to_dict
from backend.app.services.response_engine import response_engine

router = APIRouter(tags=["responses"])


class CreateResponseActionRequest(BaseModel):
    action_type: str = Field(min_length=1, max_length=50)
    target: str = Field(min_length=1, max_length=100)


@router.get("/api/v1/incidents/{incident_id}/responses")
def get_incident_responses(
    incident_id: int,
    current_user: User = Depends(require_role(["admin", "analyst"])),
    db: Session = Depends(get_db),
):
    """
    Retrieve all containment and defensive response actions for an incident.
    """
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    actions = (
        db.query(ResponseAction)
        .filter(ResponseAction.incident_id == incident_id)
        .order_by(ResponseAction.id.desc())
        .all()
    )
    return [response_to_dict(a) for a in actions]


@router.post("/api/v1/incidents/{incident_id}/responses")
def propose_incident_response(
    incident_id: int,
    resp_req: CreateResponseActionRequest,
    auth_user: User = Depends(require_role(["admin", "analyst"])),
    db: Session = Depends(get_db),
):
    """
    Propose a new defensive containment action for an incident.
    """
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    action_type = resp_req.action_type.strip().upper()
    target = resp_req.target.strip()
    if action_type not in ("BLOCK_IP", "RATE_LIMIT", "ISOLATE_HOST"):
        raise HTTPException(
            status_code=400,
            detail="Invalid action_type. Must be BLOCK_IP, RATE_LIMIT, or ISOLATE_HOST",
        )

    # Validate against protected allowlist and IP safety policies
    allowed, safety_reason = response_engine.validate_target(target)
    if not allowed:
        raise HTTPException(
            status_code=400,
            detail=f"Safety Violation: {safety_reason}",
        )

    action = ResponseAction(
        incident_id=incident.id,
        action_type=action_type,
        target=target,
        status="PENDING",
        requested_by=auth_user.username if auth_user else "SecOps Analyst",
        is_active=False,
    )
    db.add(action)
    try:
        db.commit()
        db.refresh(action)
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to propose response action") from exc

    return response_to_dict(action)


@router.post("/api/v1/responses/{response_id}/approve")
def approve_response_action(
    response_id: int,
    auth_user: User = Depends(require_role(["admin"])),
    db: Session = Depends(get_db),
):
    """
    Admin approval & execution gate for defensive containment action.
    """
    action = db.query(ResponseAction).filter(ResponseAction.id == response_id).first()
    if action is None:
        raise HTTPException(status_code=404, detail="Response action not found")

    allowed, safety_reason = response_engine.validate_target(action.target)
    if not allowed:
        raise HTTPException(
            status_code=400,
            detail=f"Safety Violation: {safety_reason}",
        )

    try:
        executed_action = response_engine.execute_action(
            db, action, admin_user=auth_user.username if auth_user else "Admin"
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # Add audit note into incident
    incident = db.query(Incident).filter(Incident.id == action.incident_id).first()
    if incident:
        curr_notes = list(incident.investigation_notes or [])
        audit_note = {
            "note_id": str(uuid.uuid4()),
            "author": auth_user.username if auth_user else "Admin",
            "content": f"[CONTAINMENT EXECUTED] Approved and applied {action.action_type} on {action.target}. {action.execution_output or ''}",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        curr_notes.append(audit_note)
        incident.investigation_notes = curr_notes
        db.commit()

    return response_to_dict(executed_action)


@router.post("/api/v1/responses/{response_id}/reject")
def reject_response_action(
    response_id: int,
    auth_user: User = Depends(require_role(["admin"])),
    db: Session = Depends(get_db),
):
    """
    Admin rejection of a proposed defensive containment action.
    """
    action = db.query(ResponseAction).filter(ResponseAction.id == response_id).first()
    if action is None:
        raise HTTPException(status_code=404, detail="Response action not found")

    action.status = "REJECTED"
    action.is_active = False
    action.approved_by = auth_user.username if auth_user else "Admin"
    action.execution_output = f"Containment proposal rejected by {action.approved_by}."
    db.commit()
    db.refresh(action)

    incident = db.query(Incident).filter(Incident.id == action.incident_id).first()
    if incident:
        curr_notes = list(incident.investigation_notes or [])
        audit_note = {
            "note_id": str(uuid.uuid4()),
            "author": auth_user.username if auth_user else "Admin",
            "content": f"[CONTAINMENT REJECTED] Rejected {action.action_type} on {action.target}.",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        curr_notes.append(audit_note)
        incident.investigation_notes = curr_notes
        db.commit()

    return response_to_dict(action)


@router.post("/api/v1/responses/{response_id}/rollback")
def rollback_response_action(
    response_id: int,
    auth_user: User = Depends(require_role(["admin"])),
    db: Session = Depends(get_db),
):
    """
    Admin rollback & deactivation of an active defensive containment rule.
    """
    action = db.query(ResponseAction).filter(ResponseAction.id == response_id).first()
    if action is None:
        raise HTTPException(status_code=404, detail="Response action not found")

    rolled_back = response_engine.rollback_action(
        db, action, admin_user=auth_user.username if auth_user else "Admin"
    )

    incident = db.query(Incident).filter(Incident.id == action.incident_id).first()
    if incident:
        curr_notes = list(incident.investigation_notes or [])
        audit_note = {
            "note_id": str(uuid.uuid4()),
            "author": auth_user.username if auth_user else "Admin",
            "content": f"[CONTAINMENT ROLLED BACK] Deactivated {action.action_type} on {action.target}. Ingress telemetry restored.",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        curr_notes.append(audit_note)
        incident.investigation_notes = curr_notes
        db.commit()

    return response_to_dict(rolled_back)
