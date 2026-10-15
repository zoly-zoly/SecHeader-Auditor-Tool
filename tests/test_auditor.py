import httpx
from secheader.auditor import HeaderAuditor
from secheader.rules import calculate_grade


def test_grade_calculation():
    assert calculate_grade(95) == "A+"
    assert calculate_grade(88) == "A"
    assert calculate_grade(50) == "D"
    assert calculate_grade(20) == "F"


def test_auditor_evaluation():
    auditor = HeaderAuditor()
    mock_headers = httpx.Headers([
        ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
        ("X-Content-Type-Options", "nosniff"),
        ("Server", "nginx/1.18.0"),
    ])
    report = auditor._evaluate_response("https://example.com", "https://example.com", 200, mock_headers)
    assert report["score"] == 35  # 20 (HSTS) + 15 (X-Content-Type-Options)
    assert "server" in report["disclosed"]
    assert len(report["present"]) == 2


def test_cookie_security_evaluation():
    auditor = HeaderAuditor()
    mock_headers = httpx.Headers([
        ("Strict-Transport-Security", "max-age=31536000"),
        ("Set-Cookie", "session_id=xyz123; Secure; HttpOnly; SameSite=Strict"),
        ("Set-Cookie", "tracking_id=abc987; Path=/"),
    ])
    report = auditor._evaluate_response("https://example.com", "https://example.com", 200, mock_headers)
    cookies = report["cookies"]
    assert len(cookies) == 2

    # First cookie is completely secure
    assert cookies[0]["name"] == "session_id"
    assert cookies[0]["status"] == "SECURE"
    assert cookies[0]["secure"] is True
    assert cookies[0]["httponly"] is True
    assert cookies[0]["samesite"].lower() == "strict"

    # Second cookie is missing Secure (-5), HttpOnly (-5), and SameSite (-3) = -13 penalty
    assert cookies[1]["name"] == "tracking_id"
    assert cookies[1]["status"] == "VULNERABLE"
    assert len(cookies[1]["issues"]) == 3
    assert report["score"] == 7  # 20 (HSTS) - 13 (Cookie penalty)
