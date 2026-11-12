import time
from unittest.mock import MagicMock, patch

import pytest
import requests

from backend.app.services.threat_intelligence import ThreatIntelService


@pytest.fixture
def intel_service():
    service = ThreatIntelService(api_key=None, ttl_seconds=60)
    service.clear_cache()
    return service


def test_private_and_loopback_ips_never_call_external(intel_service):
    """Ensure RFC 1918, loopback, and reserved addresses return PRIVATE_IP without network calls."""
    private_ips = [
        "127.0.0.1",
        "10.0.0.5",
        "192.168.1.100",
        "172.16.5.20",
        "::1",
    ]

    for ip in private_ips:
        result = intel_service.check_ip(ip)
        assert result["ip"] == ip
        assert result["is_private"] is True
        assert result["abuse_confidence_score"] == 0
        assert result["total_reports"] == 0
        assert result["status"] == "PRIVATE_IP"
        assert result["source"] == "InternalRule"


def test_offline_mock_known_ip(intel_service):
    """When API key is absent, known test IPs return deterministic mock data."""
    result = intel_service.check_ip("198.51.100.25")
    assert result["ip"] == "198.51.100.25"
    assert result["is_private"] is False
    assert result["abuse_confidence_score"] == 85
    assert result["status"] == "MALICIOUS"
    assert result["source"] == "OfflineMock"


def test_ttl_cache_hit_returns_local_cache(intel_service):
    """Subsequent lookups within TTL return source='LocalCache'."""
    ip = "198.51.100.25"
    first = intel_service.check_ip(ip)
    assert first["source"] == "OfflineMock"

    second = intel_service.check_ip(ip)
    assert second["source"] == "LocalCache"
    assert second["abuse_confidence_score"] == first["abuse_confidence_score"]
    assert second["status"] == first["status"]


def test_ttl_cache_expiry():
    """Cache entry expires after ttl_seconds."""
    short_service = ThreatIntelService(api_key=None, ttl_seconds=1)
    short_service.clear_cache()
    ip = "198.51.100.25"

    first = short_service.check_ip(ip)
    assert first["source"] == "OfflineMock"

    # Sleep past TTL
    time.sleep(1.1)

    after_expiry = short_service.check_ip(ip)
    assert after_expiry["source"] == "OfflineMock"


@patch("requests.get")
def test_mocked_abuseipdb_http_200_normalizes_data(mock_get):
    """HTTP 200 from AbuseIPDB maps correctly to normalized schema."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {
            "ipAddress": "185.220.101.5",
            "abuseConfidenceScore": 92,
            "totalReports": 38,
            "lastReportedAt": "2026-11-04T12:00:00Z",
            "countryCode": "US",
            "domain": "bad-actor.com",
            "usageType": "Data Center/Web Hosting/Transit",
        }
    }
    mock_get.return_value = mock_response

    service = ThreatIntelService(api_key="test_api_key", ttl_seconds=60)
    service.clear_cache()

    result = service.check_ip("185.220.101.5")
    assert result["ip"] == "185.220.101.5"
    assert result["is_private"] is False
    assert result["abuse_confidence_score"] == 92
    assert result["status"] == "MALICIOUS"
    assert result["total_reports"] == 38
    assert result["country_code"] == "US"
    assert result["domain"] == "bad-actor.com"
    assert result["source"] == "AbuseIPDB"


@patch("requests.get")
def test_mocked_abuseipdb_rate_limit_degrades_to_unavailable(mock_get):
    """HTTP 429 returns UNAVAILABLE status gracefully."""
    mock_response = MagicMock()
    mock_response.status_code = 429
    mock_get.return_value = mock_response

    service = ThreatIntelService(api_key="test_api_key", ttl_seconds=60)
    service.clear_cache()

    result = service.check_ip("185.220.101.5")
    assert result["status"] == "UNAVAILABLE"
    assert result["source"] == "AbuseIPDB"



@patch("requests.get")
def test_network_timeout_degrades_to_unavailable(mock_get):
    """Network timeouts return UNAVAILABLE without crashing."""
    mock_get.side_effect = requests.Timeout("Connection timed out")

    service = ThreatIntelService(api_key="test_api_key", ttl_seconds=60)
    service.clear_cache()

    result = service.check_ip("185.220.101.5")
    assert result["status"] == "UNAVAILABLE"
    assert result["source"] == "AbuseIPDB"


@patch("requests.get")
def test_abuseipdb_redirect_rejected_and_degrades_to_unavailable(mock_get):
    """HTTP 301/302 redirects are rejected (allow_redirects=False) to prevent key exposure."""
    mock_response = MagicMock()
    mock_response.status_code = 302
    mock_response.is_redirect = True
    mock_get.return_value = mock_response

    service = ThreatIntelService(api_key="secret_api_key_12345", ttl_seconds=60)
    service.clear_cache()

    result = service.check_ip("185.220.101.5")

    # Verify requests.get was invoked with allow_redirects=False
    mock_get.assert_called_once()
    _, kwargs = mock_get.call_args
    assert kwargs.get("allow_redirects") is False

    # Verify redirect returned safe UNAVAILABLE status without parsing redirect destination
    assert result["status"] == "UNAVAILABLE"
    assert result["source"] == "AbuseIPDB"

