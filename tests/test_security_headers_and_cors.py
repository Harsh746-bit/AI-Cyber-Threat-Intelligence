import pytest
from fastapi.testclient import TestClient
from backend.app.main import app, get_cors_origins


@pytest.fixture
def test_client():
    return TestClient(app)


# ============================================================================
# SEC-06: Security Headers Tests
# ============================================================================

def test_security_headers_present_on_http_responses(test_client):
    """SEC-06: Verifies security headers are injected on all API responses."""
    resp = test_client.get("/health")
    assert resp.status_code == 200
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert resp.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    # Over plain HTTP, HSTS must not be sent
    assert "Strict-Transport-Security" not in resp.headers


def test_hsts_header_present_over_https_trusted_proxy(test_client):
    """SEC-06: Verifies HSTS is enforced when request is forwarded as HTTPS by a trusted proxy."""
    resp = test_client.get("/health", headers={"X-Forwarded-Proto": "https"})
    assert resp.status_code == 200
    # Safe default: subdomains are not blindly included
    assert resp.headers.get("Strict-Transport-Security") == "max-age=31536000"


def test_hsts_header_with_include_subdomains_opt_in(test_client, monkeypatch):
    """SEC-06: Verifies includeSubDomains can be explicitly enabled when subdomains are verified HTTPS."""
    monkeypatch.setenv("SENTRIX_HSTS_INCLUDE_SUBDOMAINS", "true")
    resp = test_client.get("/health", headers={"X-Forwarded-Proto": "https"})
    assert resp.status_code == 200
    assert resp.headers.get("Strict-Transport-Security") == "max-age=31536000; includeSubDomains"


def test_hsts_rejected_from_untrusted_proxy(test_client, monkeypatch):
    """SEC-06: X-Forwarded-Proto is ignored if request client is not a configured trusted proxy."""
    # Configure trusted proxies excluding testclient
    monkeypatch.setenv("SENTRIX_TRUSTED_PROXIES", "10.0.0.1, 192.168.1.1")
    resp = test_client.get("/health", headers={"X-Forwarded-Proto": "https"})
    assert resp.status_code == 200
    assert "Strict-Transport-Security" not in resp.headers


# ============================================================================
# SEC-05: CORS Configuration & Hardening Tests
# ============================================================================

def test_cors_preflight_trusted_origin(test_client):
    """SEC-05: Verifies CORS preflight succeeds for trusted development origins."""
    resp = test_client.options(
        "/api/v1/incidents/summary",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "Authorization, Content-Type",
        },
    )
    assert resp.status_code == 200
    assert resp.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert resp.headers.get("access-control-allow-credentials") == "true"


def test_cors_untrusted_origin_rejected(test_client):
    """SEC-05: Untrusted external origin does not receive CORS approval."""
    resp = test_client.options(
        "/api/v1/incidents/summary",
        headers={
            "Origin": "http://evil-attacker.example.com",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert resp.headers.get("access-control-allow-origin") != "http://evil-attacker.example.com"


def test_cors_wildcard_with_credentials_prohibited(monkeypatch):
    """SEC-05: Configuring wildcard origin '*' with credentials fails fast with ValueError."""
    monkeypatch.setenv("SENTRIX_CORS_ORIGINS", "*, http://localhost:5173")
    with pytest.raises(ValueError, match="CORS wildcard origin '\\*' is strictly prohibited"):
        get_cors_origins()


def test_cors_production_requires_explicit_origins(monkeypatch):
    """SEC-05: Production mode without explicit CORS origins fails fast."""
    monkeypatch.setenv("SENTRIX_ENV", "production")
    monkeypatch.delenv("SENTRIX_CORS_ORIGINS", raising=False)
    with pytest.raises(ValueError, match="SENTRIX_CORS_ORIGINS must be explicitly configured in production"):
        get_cors_origins()


def test_cors_parses_comma_separated_origins(monkeypatch):
    """SEC-05: Successfully parses comma-separated allowed origins."""
    monkeypatch.setenv("SENTRIX_CORS_ORIGINS", "https://sentrix.corp.local, https://soc.company.com ")
    origins = get_cors_origins()
    assert origins == ["https://sentrix.corp.local", "https://soc.company.com"]
