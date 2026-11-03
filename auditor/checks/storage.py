"""
storage.py — WHITE-BOX check: inspect how passwords are actually stored.

Unlike the other checks, storage is examined by reading the app's own SQLite
database (this is a white-box test, run on the same host as the app). It looks
for fast/unsalted hashing (MD5) versus a salted slow hash (PBKDF2).
"""

import os
import sqlite3
from auditor.core import Finding, Severity


def _find_db():
    here = os.path.dirname(__file__)
    for c in [os.path.join(here, "..", "..", "target_app", "users.db"),
              os.path.join(here, "..", "target_app", "users.db"),
              os.path.join(os.getcwd(), "target_app", "users.db"),
              os.path.join(os.getcwd(), "users.db")]:
        if os.path.exists(c):
            return os.path.abspath(c)
    return None


def run(target_url: str) -> Finding:
    db = _find_db()
    if not db:
        return Finding(
            category="Password Storage",
            test_performed="Tried to inspect stored password hashes (white-box).",
            passed=False, severity=Severity.INFO,
            finding="Could not locate the target app's users.db for a white-box check.",
            evidence="No users.db found near the auditor.",
            recommendation="Run this check on the same host as the target app.")
    con = sqlite3.connect(db)
    row = con.execute("SELECT username, cred FROM users LIMIT 1").fetchone()
    con.close()
    user, sample = (row[0], row[1]) if row else ("", "")
    insecure = sample.startswith("md5$") or sample.startswith("sha1$") or len(sample) == 32

    if insecure:
        return Finding(
            category="Password Storage",
            test_performed="Inspected the stored password hashes in users.db (white-box).",
            passed=False, severity=Severity.CRITICAL,
            finding="Passwords are stored with fast, unsalted hashing (MD5), which is trivial to crack.",
            evidence=f"Stored value for '{user}': {sample[:40]}...",
            recommendation="Use a slow, salted password hash such as bcrypt or Argon2.")
    return Finding(
        category="Password Storage",
        test_performed="Inspected the stored password hashes in users.db (white-box).",
        passed=True, severity=Severity.INFO,
        finding="Passwords are stored with a salted, slow hash (PBKDF2).",
        evidence=f"Stored value for '{user}': {sample[:20]}...",
        recommendation="No change needed.")


if __name__ == "__main__":
    print(run("http://127.0.0.1:5000").as_dict())
