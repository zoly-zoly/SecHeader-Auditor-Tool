from typing import Dict, Any

SECURITY_HEADERS: Dict[str, Dict[str, Any]] = {
    "strict-transport-security": {
        "name": "Strict-Transport-Security (HSTS)",
        "weight": 20,
        "severity": "HIGH",
        "description": "Enforces secure (HTTPS) connections to the server.",
        "remediation": "Add 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload'",
    },
    "content-security-policy": {
        "name": "Content-Security-Policy (CSP)",
        "weight": 25,
        "severity": "HIGH",
        "description": "Mitigates XSS and data injection attacks by restricting resource loading.",
        "remediation": "Define a strict CSP, e.g., \"default-src 'self'; object-src 'none'; frame-ancestors 'none'\"",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "weight": 15,
        "severity": "MEDIUM",
        "description": "Protects against Clickjacking attacks by controlling iframe embedding.",
        "remediation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "weight": 15,
        "severity": "MEDIUM",
        "description": "Prevents MIME-sniffing vulnerabilities by forcing declared content-type.",
        "remediation": "Add 'X-Content-Type-Options: nosniff'",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "weight": 10,
        "severity": "LOW",
        "description": "Controls how much referrer information is included with requests.",
        "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'",
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "weight": 10,
        "severity": "LOW",
        "description": "Restricts browser features and APIs (camera, microphone, geolocation).",
        "remediation": "Add 'Permissions-Policy: geolocation=(), microphone=(), camera=()'",
    },
    "cross-origin-opener-policy": {
        "name": "Cross-Origin-Opener-Policy (COOP)",
        "weight": 5,
        "severity": "LOW",
        "description": "Isolates the browsing context exclusively to same-origin documents.",
        "remediation": "Add 'Cross-Origin-Opener-Policy: same-origin'",
    },
}

INFO_DISCLOSURE_HEADERS = [
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
]


def calculate_grade(score: int) -> str:
    if score >= 95:
        return "A+"
    elif score >= 85:
        return "A"
    elif score >= 75:
        return "B"
    elif score >= 60:
        return "C"
    elif score >= 45:
        return "D"
    return "F"
