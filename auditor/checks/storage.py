"""
storage.py — WHITE-BOX check: inspect how passwords are actually stored.

Unlike the other checks, storage is examined by reading the app's own SQLite
database (a white-box test). It looks for fast/unsalted hashing (MD5) versus a
salted slow hash (PBKDF2).

Running the auditor on a SEPARATE machine from the app (e.g. the auditor on
Kali, the app on Windows)? The DB isn't on this host, so point the check at a
copy you pulled over, either with the CLI flag:

    python -m auditor.main --target http://<win-ip>:5000 --db ./users.db

or by setting AUDITOR_DB in the environment. Copy the DB AFTER setting the mode
you're testing (the file is rewritten each app restart, MD5 in vulnerable mode,
PBKDF2 in hardened), so re-copy it when you flip SECURE_MODE.
"""

import os
import sqlite3
from auditor.core import Finding, Severity

# Set by main.py from --db; falls back to the AUDITOR_DB env var, then to
# auto-discovery of a local users.db.
DB_OVERRIDE = None


def _find_db():
    # 1) explicit --db, 2) AUDITOR_DB env var, 3) auto-discover locally.
    for cand in (DB_OVERRIDE, os.getenv("AUDITOR_DB")):
        if cand and os.path.exists(cand):
            return os.path.abspath(cand)
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
        requested = DB_OVERRIDE or os.getenv("AUDITOR_DB")
        hint = (f"Looked for '{requested}' but it was not found."
                if requested else
                "No users.db found near the auditor.")
        return Finding(
            category="Password Storage",
            test_performed="Tried to inspect stored password hashes (white-box).",
            passed=False, severity=Severity.INFO,
            finding="Could not locate the target app's users.db for a white-box check.",
            evidence=hint,
            recommendation="Copy users.db from the app host and pass --db <path>, or run this check on the app host.")

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
