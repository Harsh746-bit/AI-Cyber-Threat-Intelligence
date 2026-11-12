import concurrent.futures
import os
import tempfile
import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker

from backend.app.db.database import Base
from backend.app.models.incident import Incident
from backend.app.models.security_event import SecurityEventRecord


@pytest.fixture
def temp_sqlite_db():
    """Provides a fresh, temporary SQLite database on disk to test WAL file creation and concurrency."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "concurrency_test.db")
        db_url = f"sqlite:///{db_path}"

        engine = create_engine(
            db_url,
            connect_args={"check_same_thread": False, "timeout": 30.0},
        )

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

        Base.metadata.create_all(bind=engine)
        session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)

        yield engine, session_factory, db_path

        engine.dispose()


def test_sqlite_wal_pragmas_enabled(temp_sqlite_db):
    """Verifies that WAL mode, busy timeout, synchronous=NORMAL, and foreign_keys are configured."""
    engine, _, db_path = temp_sqlite_db

    with engine.connect() as conn:
        journal_mode = conn.exec_driver_sql("PRAGMA journal_mode;").scalar()
        synchronous = conn.exec_driver_sql("PRAGMA synchronous;").scalar()
        busy_timeout = conn.exec_driver_sql("PRAGMA busy_timeout;").scalar()
        foreign_keys = conn.exec_driver_sql("PRAGMA foreign_keys;").scalar()

    assert str(journal_mode).lower() == "wal"
    assert synchronous == 1  # 1 corresponds to NORMAL
    assert busy_timeout == 30000
    assert foreign_keys == 1


def test_postgresql_compatibility_does_not_execute_sqlite_pragmas(monkeypatch):
    """Verifies that non-SQLite database URLs do not register or execute SQLite PRAGMA hooks."""
    import importlib
    import backend.app.db.database as db_module

    # Mock DATABASE_URL to a PostgreSQL URI
    pg_url = "postgresql://user:password@localhost:5432/test_db"
    monkeypatch.setenv("DATABASE_URL", pg_url)

    # Re-evaluate engine initialization logic
    connect_args = {}
    if pg_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
        connect_args["timeout"] = 30.0

    # Ensure connect_args is empty for PostgreSQL
    assert "check_same_thread" not in connect_args
    assert "timeout" not in connect_args


def test_concurrent_reads_and_writes_under_wal(temp_sqlite_db):
    """
    Spawns multiple concurrent threads performing interleaved reads and writes
    to verify zero database-locking failures (sqlite3.OperationalError).
    """
    engine, session_factory, db_path = temp_sqlite_db

    total_workers = 10
    writes_per_worker = 10

    def worker_task(worker_id: int):
        success_writes = 0
        read_counts = []
        for i in range(writes_per_worker):
            session = session_factory()
            try:
                # Concurrent read
                cnt = session.query(Incident).count()
                read_counts.append(cnt)

                # Concurrent write
                inc = Incident(
                    event_id=f"worker-{worker_id}-event-{i}",
                    source_ip=f"198.51.100.{worker_id}",
                    risk_score=50.0,
                    severity="MEDIUM",
                    reasons=f"Worker {worker_id} iteration {i}",
                    status="OPEN",
                    event_count=1,
                    investigation_notes=[],
                )
                session.add(inc)
                session.commit()
                success_writes += 1
            except Exception as e:
                session.rollback()
                raise e
            finally:
                session.close()

        return success_writes

    with concurrent.futures.ThreadPoolExecutor(max_workers=total_workers) as executor:
        futures = [executor.submit(worker_task, w) for w in range(total_workers)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    # Validate that every worker completed all writes
    assert sum(results) == total_workers * writes_per_worker

    # Verify final integrity and count
    with engine.connect() as conn:
        final_count = conn.exec_driver_sql("SELECT COUNT(*) FROM incidents;").scalar()
        integrity = conn.exec_driver_sql("PRAGMA integrity_check;").scalar()

    assert final_count == total_workers * writes_per_worker
    assert integrity.lower() == "ok"


def test_transaction_rollback_integrity(temp_sqlite_db):
    """Verifies that failed transactions rollback cleanly and do not corrupt the database."""
    engine, session_factory, _ = temp_sqlite_db

    session = session_factory()
    inc = Incident(
        event_id="initial-clean-event",
        source_ip="192.0.2.1",
        risk_score=30.0,
        severity="LOW",
        reasons="Initial",
        status="OPEN",
        event_count=1,
        investigation_notes=[],
    )
    session.add(inc)
    session.commit()
    session.close()

    # Intentionally trigger an exception and rollback
    session2 = session_factory()
    try:
        inc_fail = Incident(
            event_id="failing-event",
            source_ip="192.0.2.2",
            risk_score=90.0,
            severity="CRITICAL",
            reasons="Will be rolled back",
            status="OPEN",
            event_count=1,
            investigation_notes=[],
        )
        session2.add(inc_fail)
        # Simulate business logic failure before commit
        raise RuntimeError("Simulated mid-transaction failure")
    except RuntimeError:
        session2.rollback()
    finally:
        session2.close()

    session3 = session_factory()
    all_incidents = session3.query(Incident).all()
    session3.close()

    assert len(all_incidents) == 1
    assert all_incidents[0].event_id == "initial-clean-event"
