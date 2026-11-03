"""
password_policy.py — TEMPLATE check. The other six follow this same shape.

Every check exposes run(target_url) and returns a Finding. The pattern:
    1. Decide what "secure" looks like for this category.
    2. Interact with the target app to see how it actually behaves.
    3. Compare, and build a Finding with real evidence.
    4. Return it.
"""

import secrets
import requests
from auditor.core import Finding, Severity


def run(target_url: str) -> Finding:
    # Step 1: a strong policy should reject a trivially weak password.
    # Step 2: try to register a new account with the weak password "123".
    uname = "pwtest_" + secrets.token_hex(3)
    r = requests.post(target_url + "/register",
                      data={"username": uname, "password": "123"},
                      allow_redirects=False, timeout=10)
    accepted = "registered" in r.text.lower()

    # Step 3 + 4: build the Finding.
    if accepted:
        return Finding(
            category="Password Policy",
            test_performed="Registered a new account with the weak password '123'.",
            passed=False, severity=Severity.MEDIUM,
            finding="The app accepted a trivially weak password at registration.",
            evidence=f"Registering '{uname}' with password '123' succeeded.",
            recommendation="Enforce a minimum length and complexity, and reject common passwords.")
    return Finding(
        category="Password Policy",
        test_performed="Attempted to register with the weak password '123'.",
        passed=True, severity=Severity.INFO,
        finding="The app rejected a weak password at registration.",
        evidence=_snip(r.text),
        recommendation="No change needed.")


def _snip(text: str, n: int = 160) -> str:
    return " ".join(text.split())[:n]


if __name__ == "__main__":
    print(run("http://127.0.0.1:5000").as_dict())
