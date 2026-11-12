import os
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend.app.db.database import (
    Base,
    SessionLocal,
    engine,
    ensure_schema_migrations,
    get_db,
)
from backend.app.routers.auth import (
    LoginRequest,
    router as auth_router,
)
from backend.app.routers.events import (
    RawIngestRequest,
    router as events_router,
)
from backend.app.routers.incidents import (
    AddNoteRequest,
    AssignIncidentRequest,
    IncidentStatusUpdate,
    router as incidents_router,
)
from backend.app.routers.ml import (
    MLPredictionRequest,
    router as ml_router,
)
from backend.app.routers.responses import (
    CreateResponseActionRequest,
    router as responses_router,
)
from backend.app.services.auth import seed_default_users
from backend.app.services.ingestion_pipeline import (
    auto_propose_response_action,
    incident_to_dict,
    response_to_dict,
    severity_from_score,
)

# Re-exports for backwards compatibility
__all__ = [
    "app",
    "get_db",
    "auto_propose_response_action",
    "incident_to_dict",
    "response_to_dict",
    "severity_from_score",
    "LoginRequest",
    "IncidentStatusUpdate",
    "AddNoteRequest",
    "AssignIncidentRequest",
    "CreateResponseActionRequest",
    "RawIngestRequest",
    "MLPredictionRequest",
]

app = FastAPI(
    title="SENTRIX - AI Cyber Threat Intelligence Platform",
    version="0.2.0",
    description="Security event ingestion, ML threat detection, and incident management.",
)

def get_cors_origins() -> list[str]:
    raw = os.getenv("SENTRIX_CORS_ORIGINS", "").strip()
    is_prod = (os.getenv("SENTRIX_ENV") or os.getenv("APP_ENV") or "").lower() in ("production", "prod")
    if raw:
        origins = [o.strip() for o in raw.split(",") if o.strip()]
        if "*" in origins:
            raise ValueError("CORS wildcard origin '*' is strictly prohibited when credentials are enabled")
        return origins
    if is_prod:
        raise ValueError("SENTRIX_CORS_ORIGINS must be explicitly configured in production mode")
    return ["http://localhost:5173", "http://127.0.0.1:5173"]


cors_origins = get_cors_origins()

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-SENTRIX-SENSOR-KEY", "X-SENTRIX-CSRF"],
)


def is_trusted_proxy(client_host: str | None) -> bool:
    if not client_host:
        return False
    raw_proxies = os.getenv("SENTRIX_TRUSTED_PROXIES", "127.0.0.1,::1,testclient").strip()
    trusted = {p.strip() for p in raw_proxies.split(",") if p.strip()}
    return client_host in trusted


def should_apply_hsts(request: Request) -> bool:
    """
    Enforces HSTS only when connections are confirmed HTTPS.
    Forwarded headers are only honored when originating from a trusted reverse proxy.
    """
    if request.url.scheme == "https":
        return True
    forwarded_proto = request.headers.get("x-forwarded-proto")
    if forwarded_proto and forwarded_proto.lower() == "https":
        client_host = request.client.host if request.client else None
        return is_trusted_proxy(client_host)
    return False


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    if should_apply_hsts(request):
        include_subdomains = os.getenv("SENTRIX_HSTS_INCLUDE_SUBDOMAINS", "0").lower() in ("1", "true", "yes")
        hsts_header = "max-age=31536000; includeSubDomains" if include_subdomains else "max-age=31536000"
        response.headers["Strict-Transport-Security"] = hsts_header

    return response

# Register models and create missing tables.
Base.metadata.create_all(bind=engine)
ensure_schema_migrations(engine)
try:
    with SessionLocal() as _seed_db:
        seed_default_users(_seed_db)
except ValueError as val_err:
    # Fail fast if invalid production configuration
    if (os.getenv("SENTRIX_ENV") or os.getenv("APP_ENV") or "").lower() in ("production", "prod"):
        raise
except Exception:
    pass

# Mount modular API routers
app.include_router(auth_router)
app.include_router(incidents_router)
app.include_router(responses_router)
app.include_router(events_router)
app.include_router(ml_router)


@app.get("/")
def home():
    return {
        "message": "SENTRIX is running.",
        "tagline": "Intelligence That Defends.",
    }


@app.get("/health")
def health_check():
    return {"status": "healthy"}


# ============================================================================
# Production Static SPA Mounting (Container & Deployment)
# ============================================================================
DIST_DIR = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"
if (DIST_DIR / "index.html").is_file() and os.getenv("SENTRIX_SERVE_STATIC", "0") == "1":
    if (DIST_DIR / "assets").is_dir():
        app.mount("/assets", StaticFiles(directory=str(DIST_DIR / "assets")), name="static_assets")

    @app.get("/{full_path:path}")
    def serve_frontend_spa(full_path: str):
        if full_path.startswith("api/") or full_path == "health":
            raise HTTPException(status_code=404, detail="Not Found")
        target_file = DIST_DIR / full_path
        if target_file.is_file():
            return FileResponse(target_file)
        return FileResponse(DIST_DIR / "index.html")
