"""
Credential & Authentication Security Auditor — TARGET APP
IT 359-002, Group 5.

A deliberately weak Flask + SQLite login/account app. One switch, SECURE_MODE,
hardens every flaw at once so the auditor can show a before/after. Authorized
class exercise; runs only inside our own lab.

Weaknesses covered (all toggle on SECURE_MODE):
  1. Password storage        MD5           -> salted PBKDF2
  2. Username enumeration    distinct errs -> generic error
  3. Account lockout         none          -> lock after 5 fails
  4. Session security        no flags      -> HttpOnly + Secure
  5. Password policy         accept any    -> length + complexity + common-list
  6. Password reset          leaked/guessable token -> random, single-use, expiring
  7. MFA                     none          -> second factor enforced
"""
SECURE_MODE = False   # <-- flip to True and restart to harden everything
# ============================================================================

import hashlib
import os
import re
import secrets
import sqlite3
import time
from flask import (Flask, request, redirect, session, render_template_string)

app = Flask(__name__)
app.secret_key = "dev-only-not-a-real-secret"

# Session cookie hardening is driven by the switch.
app.config["SESSION_COOKIE_HTTPONLY"] = SECURE_MODE
app.config["SESSION_COOKIE_SECURE"] = SECURE_MODE

DB = os.path.join(os.path.dirname(__file__), "users.db")
LOCK_AFTER = 5
RESET_TTL = 900  # seconds; hardened mode only

COMMON_PASSWORDS = {"123", "1234", "12345", "123456", "password", "password123",
                    "letmein", "admin", "qwerty", "111111", "iloveyou", "welcome"}

_failed = {}     # username -> consecutive failed logins (in-memory)
_resets = {}     # token -> {"user":.., "exp":.. or None}
_mfa_codes = {}  # username -> pending second-factor code (in-memory)


# ---------- password storage: weak vs hardened ----------
def store_password(password: str) -> str:
    """WEAK: raw MD5, no salt.  HARDENED: salted PBKDF2."""
    if SECURE_MODE:
        salt = os.urandom(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
        return "pbkdf2$" + salt.hex() + "$" + digest.hex()
    return "md5$" + hashlib.md5(password.encode()).hexdigest()


def check_password(password: str, stored: str) -> bool:
    if stored.startswith("pbkdf2$"):
        _, salt_hex, digest_hex = stored.split("$")
        salt = bytes.fromhex(salt_hex)
        test = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
        return test.hex() == digest_hex
    return ("md5$" + hashlib.md5(password.encode()).hexdigest()) == stored


def policy_ok(password: str) -> bool:
    """Hardened-mode password policy."""
    if len(password) < 10:
        return False
    if password.lower() in COMMON_PASSWORDS:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    return True


# ---------- database helpers ----------
def init_db():
    """Fresh DB every startup so the stored hashes match the current mode."""
    if os.path.exists(DB):
        os.remove(DB)
    con = sqlite3.connect(DB)
    con.execute("CREATE TABLE users (username TEXT PRIMARY KEY, cred TEXT)")
    for user, pw in [("alice", "password123"), ("bob", "letmein"), ("admin", "admin")]:
        con.execute("INSERT INTO users VALUES (?, ?)", (user, store_password(pw)))
    con.commit()
    con.close()


def get_user(username: str):
    con = sqlite3.connect(DB)
    row = con.execute("SELECT username, cred FROM users WHERE username = ?",
                      (username,)).fetchone()
    con.close()
    return row


def create_user(username: str, password: str):
    con = sqlite3.connect(DB)
    con.execute("INSERT INTO users VALUES (?, ?)", (username, store_password(password)))
    con.commit()
    con.close()


def set_password(username: str, password: str):
    con = sqlite3.connect(DB)
    con.execute("UPDATE users SET cred = ? WHERE username = ?",
                (store_password(password), username))
    con.commit()
    con.close()


# ---------- templates ----------
NAV = "<p><a href='/'>Login</a> | <a href='/register'>Register</a> | <a href='/reset'>Forgot password</a></p>"

LOGIN_PAGE = """<!doctype html><title>Northstar Commerce Login</title>
<h2>Northstar Commerce Account Login</h2>""" + NAV + """
<form method="post">
  <p>Username: <input name="username"></p>
  <p>Password: <input name="password" type="password"></p>
  <button>Log in</button>
</form>
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
<hr><small>SECURE_MODE = {{ secure }}</small>
"""

MFA_PAGE = """<!doctype html><title>Second factor</title>
<h2>Enter your verification code</h2>
<p>A 6-digit code was sent to your device. (In this lab it is printed to the server console.)</p>
<form method="post"><input name="code"><button>Verify</button></form>
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
"""

REGISTER_PAGE = """<!doctype html><title>Register</title>
<h2>Create an account</h2>""" + NAV + """
<form method="post">
  <p>Username: <input name="username"></p>
  <p>Password: <input name="password" type="password"></p>
  <button>Register</button>
</form>
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
{% if msg %}<p style="color:green">{{ msg }}</p>{% endif %}
<hr><small>SECURE_MODE = {{ secure }}</small>
"""

RESET_PAGE = """<!doctype html><title>Password reset</title>
<h2>Reset your password</h2>""" + NAV + """
<form method="post">
  <p>Username: <input name="username"></p>
  <button>Send reset link</button>
</form>
{% if message %}<p>{{ message }}</p>{% endif %}
<hr><small>SECURE_MODE = {{ secure }}</small>
"""

RESET_TOKEN_PAGE = """<!doctype html><title>Set new password</title>
{% if invalid %}<p style="color:red">Invalid or expired reset link.</p>
{% elif done %}<p style="color:green">Your password has been reset. <a href='/'>Log in</a>.</p>
{% else %}
<h2>Choose a new password</h2>
<form method="post"><input name="password" type="password"><button>Set password</button></form>
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
{% endif %}
"""


# ---------- routes ----------
@app.route("/", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")

        if SECURE_MODE and _failed.get(u, 0) >= LOCK_AFTER:
            return render_template_string(
                LOGIN_PAGE, error="Account locked. Try again later.", secure=SECURE_MODE)

        row = get_user(u)
        if row and check_password(p, row[1]):
            _failed[u] = 0
            if SECURE_MODE:
                # Hardened: require a second factor before issuing a session.
                code = "%06d" % secrets.randbelow(1_000_000)
                _mfa_codes[u] = code
                print(f"[MFA] verification code for {u}: {code}")
                session.clear()
                session["pre_mfa"] = u
                return redirect("/mfa")
            # Weak: no second factor, straight to the dashboard.
            session.clear()
            session["user"] = u
            return redirect("/dashboard")

        _failed[u] = _failed.get(u, 0) + 1
        if SECURE_MODE:
            error = "Invalid username or password."
        elif not row:
            error = "No account with that username."
        else:
            error = "Incorrect password."
    return render_template_string(LOGIN_PAGE, error=error, secure=SECURE_MODE)


@app.route("/mfa", methods=["GET", "POST"])
def mfa():
    u = session.get("pre_mfa")
    if not u:
        return redirect("/")
    error = None
    if request.method == "POST":
        if request.form.get("code", "") == _mfa_codes.get(u):
            _mfa_codes.pop(u, None)
            session.clear()
            session["user"] = u
            return redirect("/dashboard")
        error = "Invalid code."
    return render_template_string(MFA_PAGE, error=error)


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")
    return (f"<h2>Welcome, {session['user']}</h2>"
            f"<p>You are logged in.</p><a href='/logout'>Log out</a>")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    error = msg = None
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        if not u or not p:
            error = "Username and password are required."
        elif get_user(u):
            error = "That username is taken."
        elif SECURE_MODE and not policy_ok(p):
            error = ("Password does not meet requirements: at least 10 characters, "
                     "with an uppercase letter, a lowercase letter, and a digit, "
                     "and not a common password.")
        else:
            create_user(u, p)
            msg = "Registered! You can now log in."
    return render_template_string(REGISTER_PAGE, error=error, msg=msg, secure=SECURE_MODE)


@app.route("/reset", methods=["GET", "POST"])
def reset_request():
    message = None
    if request.method == "POST":
        u = request.form.get("username", "")
        row = get_user(u)
        if SECURE_MODE:
            # Random, expiring token; generic response that never reveals existence.
            if row:
                token = secrets.token_urlsafe(24)
                _resets[token] = {"user": u, "exp": time.time() + RESET_TTL}
            message = "If that account exists, a reset link has been sent."
        else:
            # Weak: predictable token derived from the username, no expiry,
            # leaked straight back in the response, and reveals existence.
            if row:
                token = hashlib.md5(u.encode()).hexdigest()[:12]
                _resets[token] = {"user": u, "exp": None}
                message = f"Reset link: /reset/{token}"
            else:
                message = "No account with that username."
    return render_template_string(RESET_PAGE, message=message, secure=SECURE_MODE)


@app.route("/reset/<token>", methods=["GET", "POST"])
def reset_token(token):
    rec = _resets.get(token)
    valid = rec is not None
    if valid and SECURE_MODE and rec["exp"] and time.time() > rec["exp"]:
        valid = False
    if not valid:
        return render_template_string(RESET_TOKEN_PAGE, invalid=True, done=False, error=None)
    error = None
    done = False
    if request.method == "POST":
        p = request.form.get("password", "")
        if SECURE_MODE and not policy_ok(p):
            error = "Password does not meet requirements."
        else:
            set_password(rec["user"], p)
            if SECURE_MODE:
                _resets.pop(token, None)   # single use
            done = True
    return render_template_string(RESET_TOKEN_PAGE, invalid=False, done=done, error=error)


if __name__ == "__main__":
    init_db()
    print(f"Target app starting. SECURE_MODE = {SECURE_MODE}")
    print("Seeded users: alice / bob / admin")
    # host=0.0.0.0 so the Kali box can reach it across pfSense.
    app.run(host="0.0.0.0", port=5000, debug=False)
