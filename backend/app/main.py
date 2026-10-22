
from fastapi import FastAPI, Depends, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app.services.detection import analyze_event
from backend.app.db.database import Base, engine, SessionLocal
from backend.app.models.incident import Incident


app = FastAPI(
    title="AI Cyber Threat Intelligence Platform",
    version="0.1.0"
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


Base.metadata.create_all(bind=engine)


# -------------------- REQUEST MODELS --------------------

class SecurityEvent(BaseModel):
    source_ip: str
    failed_logins: int = Field(default=0, ge=0)
    requests_per_minute: int = Field(default=0, ge=0)
    known_malicious_ip: bool = False


class IncidentStatusUpdate(BaseModel):
    status: str


# -------------------- DATABASE SESSION --------------------

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# -------------------- BASIC ENDPOINTS --------------------

@app.get("/")
def home():
    return {
        "message": "Our Cybersecurity Platform is running!"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }


# -------------------- ANALYZE SECURITY EVENT --------------------

@app.post("/api/v1/analyze")
def analyze_security_event(
    event: SecurityEvent,
    db: Session = Depends(get_db)
):
    result = analyze_event(event)

    incident = Incident(
        source_ip=event.source_ip,
        risk_score=result["risk_score"],
        severity=result["severity"],
        reasons="; ".join(result["reasons"])
    )

    db.add(incident)
    db.commit()
    db.refresh(incident)

    return {
        "incident_id": incident.id,
        "source_ip": incident.source_ip,
        "risk_score": incident.risk_score,
        "severity": incident.severity,
        "status": incident.status,
        "reasons": result["reasons"],
        "analysis_type": "rule_based_prototype"
    }


# -------------------- LIST, SEARCH AND FILTER INCIDENTS --------------------

@app.get("/api/v1/incidents")
def get_incidents(
    limit: int = Query(default=20, ge=1, le=100),
    severity: str | None = Query(default=None),
    search: str | None = Query(default=None),
    db: Session = Depends(get_db)
):
    query = db.query(Incident)

    if severity:
        severity_value = severity.strip().upper()

        if severity_value not in ["LOW", "MEDIUM", "HIGH"]:
            raise HTTPException(
                status_code=400,
                detail="Severity must be LOW, MEDIUM, or HIGH"
            )

        query = query.filter(
            Incident.severity == severity_value
        )

    if search:
        search_value = search.strip()

        if search_value.isdigit():
            query = query.filter(
                Incident.id == int(search_value)
            )
        elif search_value:
            query = query.filter(
                Incident.source_ip.contains(search_value)
            )

    incidents = (
        query.order_by(Incident.id.desc())
        .limit(limit)
        .all()
    )

    return {
        "total_returned": len(incidents),
        "incidents": [
            {
                "incident_id": incident.id,
                "source_ip": incident.source_ip,
                "risk_score": incident.risk_score,
                "severity": incident.severity,
                "status": incident.status,
                "reasons": incident.reasons,
                "created_at": incident.created_at
            }
            for incident in incidents
        ]
    }


# -------------------- UPDATE INCIDENT INVESTIGATION STATUS --------------------

@app.patch("/api/v1/incidents/{incident_id}/status")
def update_incident_status(
    incident_id: int,
    update: IncidentStatusUpdate,
    db: Session = Depends(get_db)
):
    allowed_statuses = [
        "OPEN",
        "INVESTIGATING",
        "RESOLVED"
    ]

    new_status = update.status.strip().upper()

    if new_status not in allowed_statuses:
        raise HTTPException(
            status_code=400,
            detail="Status must be OPEN, INVESTIGATING, or RESOLVED"
        )

    incident = (
        db.query(Incident)
        .filter(Incident.id == incident_id)
        .first()
    )

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found"
        )

    incident.status = new_status

    db.commit()
    db.refresh(incident)

    return {
        "incident_id": incident.id,
        "status": incident.status,
        "message": "Incident status updated successfully"
    }


# -------------------- INCIDENT DASHBOARD SUMMARY --------------------

@app.get("/api/v1/incidents/summary")
def get_incident_summary(
    db: Session = Depends(get_db)
):
    total = db.query(Incident).count()

    low = db.query(Incident).filter(
        Incident.severity == "LOW"
    ).count()

    medium = db.query(Incident).filter(
        Incident.severity == "MEDIUM"
    ).count()

    high = db.query(Incident).filter(
        Incident.severity == "HIGH"
    ).count()

    status_breakdown = {
        "OPEN": db.query(Incident).filter(
            Incident.status == "OPEN"
        ).count(),
        "INVESTIGATING": db.query(Incident).filter(
            Incident.status == "INVESTIGATING"
        ).count(),
        "RESOLVED": db.query(Incident).filter(
            Incident.status == "RESOLVED"
        ).count(),
    }

    return {
        "total_incidents": total,
        "severity_breakdown": {
            "LOW": low,
            "MEDIUM": medium,
            "HIGH": high
        },
        "status_breakdown": status_breakdown
    }
