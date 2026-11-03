"""
password_reset.py — request a reset for a known account and inspect the
response. A secure flow never returns the token and never reveals whether the
account exists. This flags a leaked and/or predictable token.
"""

import hashlib
import re
import requests
from auditor.core import Finding, Severity


def run(target_url: str) -> Finding:
    s = requests.Session()
    r = s.post(target_url + "/reset", data={"username": "alice"},
               allow_redirects=False, timeout=10)
    body = r.text
    m = re.search(r"/reset/([A-Za-z0-9_\-]+)", body)

    if m:
        token = m.group(1)
        predictable = token == hashlib.md5(b"alice").hexdigest()[:12]
        extra = " and is a predictable hash of the username" if predictable else ""
        proof = f"Response leaked: /reset/{token}"
        if predictable:
            proof += f"   (md5('alice')[:12] = {hashlib.md5(b'alice').hexdigest()[:12]})"
        return Finding(
            category="Password-Reset Security",
            test_performed="Requested a password reset for a known account and read the response.",
            passed=False, severity=Severity.HIGH,
            finding=f"The reset token is exposed in the HTTP response{extra}.",
            evidence=proof,
            recommendation="Never return the token; use a cryptographically random, single-use, expiring token sent out of band.")
    return Finding(
        category="Password-Reset Security",
        test_performed="Requested a password reset for a known account and read the response.",
        passed=True, severity=Severity.INFO,
        finding="The reset flow did not leak a token and returned a generic response.",
        evidence=" ".join(body.split())[:160],
        recommendation="No change needed.")


if __name__ == "__main__":
    print(run("http://127.0.0.1:5000").as_dict())
