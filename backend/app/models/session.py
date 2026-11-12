from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from backend.app.db.database import Base


class UserSession(Base):
    __tablename__ = "sessions"

    # SHA-256 hex digest of the raw session token (never store raw token)
    id = Column(String(64), primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # SHA-256 hex digest of the session's active CSRF token (never store raw token)
    csrf_token_hash = Column(String(64), nullable=False)
    
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    # Absolute maximum ceiling (12 hours) - immutable once created
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    
    # Sliding activity timestamp for 60-minute inactivity timeout
    last_activity_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    
    revoked = Column(Boolean, default=False, nullable=False, index=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)

    user = relationship("User", backref="sessions")
