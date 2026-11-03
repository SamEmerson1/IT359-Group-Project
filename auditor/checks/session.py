"""
session.py — inspect the session cookie set at login for HttpOnly and Secure.
"""

import requests
from auditor.core import Finding, Severity


def run(target_url: str) -> Finding:
    s = requests.Session()
    r = s.post(target_url + "/",
               data={"username": "alice", "password": "password123"},
               allow_redirects=False, timeout=10)
    set_cookie = r.headers.get("Set-Cookie", "")

    if not set_cookie:
        return Finding(
            category="Session Security",
            test_performed="Logged in and inspected the session cookie.",
            passed=False, severity=Severity.INFO,
            finding="No session cookie was set on login.",
            evidence="No Set-Cookie header on the login response.",
            recommendation="Issue a session cookie on login with HttpOnly and Secure set.")

    low = set_cookie.lower()
    missing = [flag for flag in ("httponly", "secure") if flag not in low]
    if missing:
        return Finding(
            category="Session Security",
            test_performed="Logged in and inspected the session cookie flags.",
            passed=False, severity=Severity.MEDIUM,
            finding=f"Session cookie is missing flag(s): {', '.join(missing)}.",
            evidence=f"Set-Cookie: {set_cookie}",
            recommendation="Set HttpOnly and Secure on the session cookie, give it an expiry, and rotate it on login.")
    return Finding(
        category="Session Security",
        test_performed="Logged in and inspected the session cookie flags.",
        passed=True, severity=Severity.INFO,
        finding="Session cookie sets both HttpOnly and Secure.",
        evidence=f"Set-Cookie: {set_cookie}",
        recommendation="No change needed.")


if __name__ == "__main__":
    print(run("http://127.0.0.1:5000").as_dict())
