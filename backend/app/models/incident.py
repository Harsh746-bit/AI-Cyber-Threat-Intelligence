from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Float, Integer, JSON, String, Text

from backend.app.db.database import Base


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)

    # Links an incident to its originating security event.
    # Nullable so existing and rule-based incidents remain compatible.
    event_id = Column(String(36), nullable=True, unique=True)

    source_ip = Column(String(45), nullable=False)
    risk_score = Column(Float, nullable=False)
    severity = Column(String(10), nullable=False)
    reasons = Column(Text, nullable=False)

    status = Column(
        String(20),
        nullable=False,
        default="OPEN",
    )

    threat_intel = Column(
        JSON,
        nullable=True,
    )

    # Multi-Event Correlation & Dynamic Scoring (Milestone 4)
    event_count = Column(
        Integer,
        default=1,
        nullable=False,
    )

    correlated_events = Column(
        JSON,
        default=list,
        nullable=False,
    )

    mitre_attack = Column(
        JSON,
        nullable=True,
    )

    last_seen_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # AI Threat Analyst & Automated Reasoning (Milestone 5)
    ai_analysis = Column(
        JSON,
        nullable=True,
    )

    # Incident Investigation & Audit Trail (Milestone 6)
    assigned_to = Column(
        String(100),
        nullable=True,
        default=None,
    )

    investigation_notes = Column(
        JSON,
        default=list,
        nullable=False,
    )

    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
