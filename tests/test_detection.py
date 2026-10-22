
from types import SimpleNamespace

from backend.app.services.detection import analyze_event


def make_event(
    failed_logins=0,
    requests_per_minute=0,
    known_malicious_ip=False
):
    return SimpleNamespace(
        failed_logins=failed_logins,
        requests_per_minute=requests_per_minute,
        known_malicious_ip=known_malicious_ip
    )


def test_normal_event():
    result = analyze_event(make_event())

    assert result["risk_score"] == 0
    assert result["severity"] == "LOW"
    assert result["reasons"] == ["No rules triggered"]


def test_failed_logins_rule():
    result = analyze_event(make_event(failed_logins=10))

    assert result["risk_score"] == 35
    assert result["severity"] == "MEDIUM"


def test_malicious_ip_rule():
    result = analyze_event(
        make_event(known_malicious_ip=True)
    )

    assert result["risk_score"] == 40
    assert result["severity"] == "MEDIUM"


def test_all_rules_triggered():
    result = analyze_event(
        make_event(
            failed_logins=15,
            requests_per_minute=120,
            known_malicious_ip=True
        )
    )

    assert result["risk_score"] == 100
    assert result["severity"] == "HIGH"
    assert len(result["reasons"]) == 3
