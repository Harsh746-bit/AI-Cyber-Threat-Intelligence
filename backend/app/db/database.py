import os
from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./cyber_threats.db")

connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False
    # Set busy_timeout at the connection driver level (in milliseconds)
    connect_args["timeout"] = 30.0

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
)

# Apply SQLite-specific PRAGMAs (WAL mode, busy timeout, synchronous, foreign keys)
# strictly when connected to a SQLite database. Never apply to PostgreSQL or other dialects.
if DATABASE_URL.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def _set_sqlite_pragmas(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute("PRAGMA synchronous=NORMAL;")
            cursor.execute("PRAGMA busy_timeout=30000;")
            cursor.execute("PRAGMA foreign_keys=ON;")
        finally:
            cursor.close()

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def ensure_schema_migrations(target_engine):
    """Ensure any newly added columns and tables exist in existing SQLite databases."""
    try:
        from backend.app.models.response import ResponseAction
        ResponseAction.__table__.create(target_engine, checkfirst=True)
    except Exception:
        pass

    try:
        from backend.app.models.session import UserSession
        UserSession.__table__.create(target_engine, checkfirst=True)
    except Exception:
        pass

    try:
        with target_engine.connect() as connection:
            columns = {
                row[1]
                for row in connection.exec_driver_sql("PRAGMA table_info(incidents)").fetchall()
            }
            if columns:
                if "threat_intel" not in columns:
                    connection.exec_driver_sql("ALTER TABLE incidents ADD COLUMN threat_intel JSON")
                if "event_count" not in columns:
                    connection.exec_driver_sql("ALTER TABLE incidents ADD COLUMN event_count INTEGER NOT NULL DEFAULT 1")
                if "correlated_events" not in columns:
                    connection.exec_driver_sql("ALTER TABLE incidents ADD COLUMN correlated_events JSON NOT NULL DEFAULT '[]'")
                if "mitre_attack" not in columns:
                    connection.exec_driver_sql("ALTER TABLE incidents ADD COLUMN mitre_attack JSON")
                if "last_seen_at" not in columns:
                    connection.exec_driver_sql("ALTER TABLE incidents ADD COLUMN last_seen_at DATETIME")
                if "ai_analysis" not in columns:
                    connection.exec_driver_sql("ALTER TABLE incidents ADD COLUMN ai_analysis JSON")
                if "assigned_to" not in columns:
                    connection.exec_driver_sql("ALTER TABLE incidents ADD COLUMN assigned_to VARCHAR(100)")
                if "investigation_notes" not in columns:
                    connection.exec_driver_sql("ALTER TABLE incidents ADD COLUMN investigation_notes JSON NOT NULL DEFAULT '[]'")
                connection.commit()
    except Exception:
        pass
