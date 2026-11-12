from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text

from backend.app.db.database import Base


class ResponseAction(Base):
    __tablename__ = "response_actions"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False, index=True)
    action_type = Column(String(50), nullable=False)  # "BLOCK_IP", "RATE_LIMIT", "ISOLATE_HOST"
    target = Column(String(100), nullable=False)  # Target IP / Host
    status = Column(
        String(20),
        nullable=False,
        default="PENDING",
    )  # "PENDING", "APPROVED", "EXECUTED", "REJECTED", "ROLLED_BACK", "FAILED"
    requested_by = Column(String(50), default="AIThreatAnalyst")
    approved_by = Column(String(50), nullable=True)
    execution_output = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True, index=True)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    executed_at = Column(DateTime(timezone=True), nullable=True)
