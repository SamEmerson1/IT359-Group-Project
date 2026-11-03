"""
enumeration.py — does the login reveal which usernames exist? Compare the error
for a nonexistent username against the error for a real username + wrong password.
"""

import requests
from auditor.core import Finding, Severity


def run(target_url: str) -> Finding:
    s = requests.Session()
    r_missing = s.post(target_url + "/",
                       data={"username": "no_such_user_zzz", "password": "x"},
                       allow_redirects=False, timeout=10)
    r_wrong = s.post(target_url + "/",
                     data={"username": "alice", "password": "definitely_wrong"},
                     allow_redirects=False, timeout=10)
    b1, b2 = r_missing.text, r_wrong.text

    if b1 != b2:
        return Finding(
            category="Username Enumeration",
            test_performed="Compared login errors for a nonexistent vs. a real username.",
            passed=False, severity=Severity.MEDIUM,
            finding="The app returns different errors for unknown vs. known usernames, revealing which accounts exist.",
            evidence=f"unknown user -> [{_err(b1)}]   |   real user -> [{_err(b2)}]",
            recommendation="Return an identical generic message (and similar timing) whether or not the username exists.")
    return Finding(
        category="Username Enumeration",
        test_performed="Compared login errors for a nonexistent vs. a real username.",
        passed=True, severity=Severity.INFO,
        finding="The app returns the same error whether or not the username exists.",
        evidence=f"both responses -> [{_err(b1)}]",
        recommendation="No change needed.")


def _err(text: str) -> str:
    for marker in ("No account", "Incorrect password", "Invalid username"):
        if marker in text:
            return text[text.index(marker):text.index(marker) + 40].split("<")[0]
    return "(error text)"


if __name__ == "__main__":
    print(run("http://127.0.0.1:5000").as_dict())
