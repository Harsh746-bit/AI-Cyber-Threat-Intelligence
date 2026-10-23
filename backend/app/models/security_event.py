
from datetime import datetime, timezone

from sqlalchemy import (
    Column,
    DateTime,
    Integer,
    JSON,
    String,
)

from backend.app.db.database import Base


class SecurityEventRecord(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)

    event_id = Column(String(36), unique=True, nullable=False, index=True)
    schema_version = Column(String(10), nullable=False)
    event_type = Column(String(30), nullable=False)

    observed_at = Column(DateTime(timezone=True), nullable=True)
    received_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    source_ip = Column(String(45), nullable=True)
    destination_ip = Column(String(45), nullable=True)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)
    protocol = Column(String(30), nullable=True)

    features = Column(JSON, nullable=False)
