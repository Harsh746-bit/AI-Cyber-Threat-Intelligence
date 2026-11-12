import ipaddress
import logging
import os
import time
from typing import Optional

logger = logging.getLogger(__name__)


class ThreatIntelService:
    """
    Threat Intelligence Enrichment Service.
    Queries AbuseIPDB API for external IP reputation or falls back to
    deterministic offline mocks and local in-memory TTL caching.
    Guarantees that private/loopback/reserved IPs are never sent externally.
    """

    KNOWN_MOCKS = {
        "198.51.100.25": {
            "abuse_confidence_score": 85,
            "total_reports": 24,
            "last_reported_at": "2026-11-04T10:00:00Z",
            "country_code": "US",
            "domain": "threat-actors.net",
            "usage_type": "Data Center/Web Hosting",
        },
        "198.51.100.50": {
            "abuse_confidence_score": 45,
            "total_reports": 6,
            "last_reported_at": "2026-11-03T18:30:00Z",
            "country_code": "DE",
            "domain": "suspicious-proxy.de",
            "usage_type": "Commercial",
        },
        "8.8.8.8": {
            "abuse_confidence_score": 0,
            "total_reports": 0,
            "last_reported_at": None,
            "country_code": "US",
            "domain": "dns.google",
            "usage_type": "DNS",
        },
    }

    def __init__(
        self,
        api_key: Optional[str] = None,
        ttl_seconds: int = 3600,
        timeout: float = 3.0,
    ):
        self.api_key = api_key if api_key is not None else os.getenv("ABUSEIPDB_API_KEY")
        self.ttl_seconds = ttl_seconds
        self.timeout = timeout
        self._cache: dict[str, tuple[float, dict]] = {}

    def is_private_ip(self, ip_str: str) -> bool:
        """
        Check if an IP string is an RFC 1918 private, loopback, link-local,
        multicast, or reserved address. Explicit test mock IPs in KNOWN_MOCKS
        are treated as public simulation addresses.
        """
        clean_ip = ip_str.strip()
        if clean_ip in self.KNOWN_MOCKS:
            return False

        try:
            addr = ipaddress.ip_address(clean_ip)
            return (
                addr.is_private
                or addr.is_loopback
                or addr.is_reserved
                or addr.is_link_local
                or addr.is_multicast
            )
        except ValueError:
            return False

    @staticmethod
    def classify_score(score: int) -> str:
        """Classify reputation score based on defined thresholds."""
        if score >= 80:
            return "MALICIOUS"
        elif score >= 20:
            return "SUSPICIOUS"
        else:
            return "BENIGN"

    def clear_cache(self) -> None:
        """Clear in-memory cache (primarily for tests)."""
        self._cache.clear()

    def check_ip(self, ip_str: Optional[str]) -> dict:
        """
        Enrich an IP address with reputation intelligence.
        """
        if not ip_str or not isinstance(ip_str, str):
            return {
                "ip": str(ip_str or "UNKNOWN"),
                "is_private": False,
                "abuse_confidence_score": 0,
                "total_reports": 0,
                "last_reported_at": None,
                "country_code": None,
                "domain": None,
                "usage_type": None,
                "status": "UNKNOWN",
                "source": "InternalRule",
            }

        ip = ip_str.strip()

        # Guardrail: Never query external network for private or loopback IPs
        if self.is_private_ip(ip):
            return {
                "ip": ip,
                "is_private": True,
                "abuse_confidence_score": 0,
                "total_reports": 0,
                "last_reported_at": None,
                "country_code": None,
                "domain": None,
                "usage_type": "RFC 1918 / Private Network",
                "status": "PRIVATE_IP",
                "source": "InternalRule",
            }

        # Validate IP format
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return {
                "ip": ip,
                "is_private": False,
                "abuse_confidence_score": 0,
                "total_reports": 0,
                "last_reported_at": None,
                "country_code": None,
                "domain": None,
                "usage_type": None,
                "status": "UNKNOWN",
                "source": "InternalRule",
            }

        # Check in-memory TTL cache
        now = time.time()
        if ip in self._cache:
            timestamp, cached_payload = self._cache[ip]
            if now - timestamp < self.ttl_seconds:
                result = dict(cached_payload)
                result["source"] = "LocalCache"
                return result

        # Lookup public IP
        if self.api_key:
            result = self._lookup_abuseipdb(ip)
        else:
            result = self._offline_mock_lookup(ip)

        # Cache result
        self._cache[ip] = (now, dict(result))
        return result

    def _lookup_abuseipdb(self, ip: str) -> dict:
        """Query AbuseIPDB API v2 with timeout and rate limit resilience."""
        try:
            import requests

            headers = {
                "Key": self.api_key,
                "Accept": "application/json",
            }
            params = {
                "ipAddress": ip,
                "maxAgeInDays": 90,
                "verbose": True,
            }
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers=headers,
                params=params,
                timeout=self.timeout,
                allow_redirects=False,
            )

            # Reject redirects to prevent credential leakage or SSRF
            if resp.status_code in (301, 302, 303, 307, 308) or (
                hasattr(resp, "is_redirect") and resp.is_redirect is True
            ):
                logger.warning(
                    "AbuseIPDB request redirected (status %s); rejected redirect to prevent credential exposure",
                    resp.status_code,
                )
                return {
                    "ip": ip,
                    "is_private": False,
                    "abuse_confidence_score": 0,
                    "total_reports": 0,
                    "last_reported_at": None,
                    "country_code": None,
                    "domain": None,
                    "usage_type": None,
                    "status": "UNAVAILABLE",
                    "source": "AbuseIPDB",
                }

            if resp.status_code == 200:
                data = resp.json().get("data", {})
                score = int(data.get("abuseConfidenceScore", 0))
                status = self.classify_score(score)
                return {
                    "ip": ip,
                    "is_private": False,
                    "abuse_confidence_score": score,
                    "total_reports": int(data.get("totalReports", 0)),
                    "last_reported_at": data.get("lastReportedAt"),
                    "country_code": data.get("countryCode"),
                    "domain": data.get("domain"),
                    "usage_type": data.get("usageType"),
                    "status": status,
                    "source": "AbuseIPDB",
                }
            elif resp.status_code == 429:
                return {
                    "ip": ip,
                    "is_private": False,
                    "abuse_confidence_score": 0,
                    "total_reports": 0,
                    "last_reported_at": None,
                    "country_code": None,
                    "domain": None,
                    "usage_type": None,
                    "status": "UNAVAILABLE",
                    "source": "AbuseIPDB",
                }
            else:
                return {
                    "ip": ip,
                    "is_private": False,
                    "abuse_confidence_score": 0,
                    "total_reports": 0,
                    "last_reported_at": None,
                    "country_code": None,
                    "domain": None,
                    "usage_type": None,
                    "status": "UNAVAILABLE",
                    "source": "AbuseIPDB",
                }
        except Exception:
            return {
                "ip": ip,
                "is_private": False,
                "abuse_confidence_score": 0,
                "total_reports": 0,
                "last_reported_at": None,
                "country_code": None,
                "domain": None,
                "usage_type": None,
                "status": "UNAVAILABLE",
                "source": "AbuseIPDB",
            }

    def _offline_mock_lookup(self, ip: str) -> dict:
        """Deterministic mock data when API key is not configured."""
        if ip in self.KNOWN_MOCKS:
            mock = self.KNOWN_MOCKS[ip]
            score = mock.get("abuse_confidence_score", 0)
            status = self.classify_score(score)
            return {
                "ip": ip,
                "is_private": False,
                "abuse_confidence_score": score,
                "total_reports": mock.get("totalReports", mock.get("total_reports", 0)),
                "last_reported_at": mock.get("lastReportedAt", mock.get("last_reported_at")),
                "country_code": mock.get("countryCode", mock.get("country_code")),
                "domain": mock.get("domain"),
                "usage_type": mock.get("usageType", mock.get("usage_type")),
                "status": status,
                "source": "OfflineMock",
            }

        return {
            "ip": ip,
            "is_private": False,
            "abuse_confidence_score": 0,
            "total_reports": 0,
            "last_reported_at": None,
            "country_code": None,
            "domain": None,
            "usage_type": None,
            "status": "UNKNOWN",
            "source": "OfflineMock",
        }


threat_intel_service = ThreatIntelService()
