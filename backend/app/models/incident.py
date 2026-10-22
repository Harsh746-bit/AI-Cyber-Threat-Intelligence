
from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, Integer, String, Text
from backend.app.db.database import Base


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    source_ip = Column(String(45), nullable=False)
    risk_score = Column(Integer, nullable=False)
    severity = Column(String(10), nullable=False)
    reasons = Column(Text, nullable=False)

    status = Column(
        String(20),
        nullable=False,
        default="OPEN"
    )

    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
