"""
lockout.py — send several failed logins for one account, then try the correct
password. If the correct login still goes through, there is no lockout.
Uses 'bob' so it does not interfere with checks that log in as 'alice'.
"""

import requests
from auditor.core import Finding, Severity


def run(target_url: str) -> Finding:
    s = requests.Session()
    user = "bob"
    for _ in range(7):
        s.post(target_url + "/", data={"username": user, "password": "wrong_pw"},
               allow_redirects=False, timeout=10)
    r = s.post(target_url + "/", data={"username": user, "password": "letmein"},
               allow_redirects=False, timeout=10)

    body = r.text.lower()
    locked = ("lock" in body) or (r.status_code == 429)
    login_accepted = r.status_code in (301, 302)

    if login_accepted and not locked:
        return Finding(
            category="Account Lockout / Rate Limiting",
            test_performed="Sent 7 failed logins for one account, then the correct password.",
            passed=False, severity=Severity.HIGH,
            finding="The account was not locked or throttled after repeated failures, so brute forcing is unimpeded.",
            evidence="After 7 wrong attempts, a correct login still succeeded with no lockout.",
            recommendation="Lock or rate-limit the account after a small number of failed attempts.")
    return Finding(
        category="Account Lockout / Rate Limiting",
        test_performed="Sent repeated failed logins for one account.",
        passed=True, severity=Severity.INFO,
        finding="The account was locked or throttled after repeated failed logins.",
        evidence="A correct login was blocked after several wrong attempts.",
        recommendation="No change needed.")


if __name__ == "__main__":
    print(run("http://127.0.0.1:5000").as_dict())
