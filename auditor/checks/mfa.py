"""
mfa.py — log in with a password only, then request the dashboard. If the
dashboard is reachable with just a password, no second factor is enforced.
"""

import requests
from auditor.core import Finding, Severity


def run(target_url: str) -> Finding:
    s = requests.Session()
    s.post(target_url + "/", data={"username": "alice", "password": "password123"},
           allow_redirects=False, timeout=10)
    r = s.get(target_url + "/dashboard", allow_redirects=False, timeout=10)
    reached = r.status_code == 200 and "welcome" in r.text.lower()

    if reached:
        return Finding(
            category="MFA Presence",
            test_performed="Logged in with a password only, then requested the dashboard.",
            passed=False, severity=Severity.HIGH,
            finding="The dashboard is reachable with a password alone; no second factor is enforced.",
            evidence="GET /dashboard returned the logged-in page right after a password-only login.",
            recommendation="Require and enforce a second factor before granting an authenticated session.")
    return Finding(
        category="MFA Presence",
        test_performed="Logged in with a password only, then requested the dashboard.",
        passed=True, severity=Severity.INFO,
        finding="A password-only login did not reach the dashboard; a second factor is enforced.",
        evidence=f"GET /dashboard after a password-only login returned HTTP {r.status_code}, not the dashboard.",
        recommendation="No change needed.")


if __name__ == "__main__":
    print(run("http://127.0.0.1:5000").as_dict())
