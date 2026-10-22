def analyze_event(event):
    score = 0
    reasons = []

    if event.failed_logins >= 10:
        score += 35
        reasons.append("High number of failed logins")

    if event.requests_per_minute >= 100:
        score += 25
        reasons.append("Unusually high request volume")

    if event.known_malicious_ip:
        score += 40
        reasons.append("IP marked as malicious in supplied data")

    score = min(score, 100)

    if score >= 70:
        severity = "HIGH"
    elif score >= 35:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "risk_score": score,
        "severity": severity,
        "reasons": reasons if reasons else ["No rules triggered"]
    }
