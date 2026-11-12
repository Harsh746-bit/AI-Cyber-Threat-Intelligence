"""
SENTRIX Sensor API Key Authentication Service
----------------------------------------------
Enforces dedicated sensor authentication for telemetry ingestion endpoints.
Validates the X-SENTRIX-SENSOR-KEY header using constant-time comparison
against the configured SENTRIX_SENSOR_API_KEY environment variable.

Design principles:
- Fails closed if SENTRIX_SENSOR_API_KEY is not configured or lacks entropy (< 32 chars).
- Uses hmac.compare_digest for timing-attack resistance.
- Zero key leakage in exceptions, logs, or error responses.
- Completely isolated from user JWT session management.
"""

import hmac
import os
from fastapi import HTTPException, Request, Security, status
from fastapi.security.api_key import APIKeyHeader

SENSOR_HEADER_NAME = "X-SENTRIX-SENSOR-KEY"
MINIMUM_SENSOR_KEY_LENGTH = 32

_sensor_key_header_scheme = APIKeyHeader(
    name=SENSOR_HEADER_NAME,
    auto_error=False,
    description="Dedicated API key for telemetry sensors and ingest forwarders",
)


def get_configured_sensor_key() -> str:
    """
    Retrieves and validates the server-configured sensor API key.
    Fails closed if the key is missing or shorter than 32 characters.
    Never logs or exposes the secret material.
    """
    key = os.getenv("SENTRIX_SENSOR_API_KEY")
    if not key or len(key.strip()) < MINIMUM_SENSOR_KEY_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Sensor authentication is not configured or lacks required entropy on the server.",
        )
    return key.strip()


def require_sensor_key(
    request: Request,
    api_key: str | None = Security(_sensor_key_header_scheme),
) -> str:
    """
    FastAPI dependency enforcing valid sensor API key authentication.
    - Rejects missing, empty, or whitespace-only keys with HTTP 401.
    - Fails closed if the server is not properly configured with SENTRIX_SENSOR_API_KEY.
    - Uses constant-time comparison to prevent timing side-channel attacks.
    """
    # 1. Check client-supplied key presence
    if not api_key or not api_key.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Missing sensor authentication key. Provide '{SENSOR_HEADER_NAME}' header.",
        )

    # 2. Server configuration check — fail closed if unconfigured or weak
    server_key = get_configured_sensor_key()

    # 3. Constant-time comparison
    is_valid = hmac.compare_digest(
        api_key.strip().encode("utf-8"),
        server_key.encode("utf-8"),
    )
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid sensor authentication key.",
        )

    return api_key.strip()
