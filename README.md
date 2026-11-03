# Credential & Authentication Security Auditor

**IT 359-002 — Group 5** · Prof. Dmitry Zhdanov

A Python tool that audits a web app's login and account system for common
authentication weaknesses and produces an overall **authentication security
score** with plain-language, AI-assisted remediation notes.

This repo holds the **code** for the project only.

---

## What it is

The project is two programs that work together:

- **`target_app/`** — a small Flask + SQLite login app, built *deliberately
  weak*, with a single `SECURE_MODE` switch that hardens every flaw at once.
- **`auditor/`** — a command-line tool that tests the target app, scores what
  it finds, and renders a report.

The payoff is a repeatable before/after: run the auditor against the weak app
(low score), flip `SECURE_MODE` to `True`, run again (high score).

## Repo layout

```
auth-auditor/
├─ README.md
├─ requirements.txt
├─ target_app/
│  └─ app.py            # the deliberately-weak login app (+ SECURE_MODE switch)
├─ auditor/
│  ├─ core.py           # the Finding/Severity definitions every module shares
│  ├─ main.py           # CLI entry point — runs all checks end to end
│  ├─ scoring.py        # turns findings into a 0–100 score
│  ├─ ai_report.py      # sends findings to an LLM for plain-language fixes
│  ├─ report.py         # renders the findings + score to an HTML report
│  └─ checks/           # one module per test category
│     ├─ password_policy.py   # ← worked template; copy it for the rest
│     ├─ lockout.py
│     ├─ enumeration.py
│     ├─ storage.py
│     ├─ session.py
│     ├─ mfa.py
│     └─ password_reset.py
└─ screenshots/         # evidence captured from the lab machines
```

## Setup and run

```bash
python -m venv .venv
# Windows:  .venv\Scripts\activate     macOS/Linux:  source .venv/bin/activate
pip install -r requirements.txt
```

Start the target app (one terminal):

```bash
python target_app/app.py          # serves on http://127.0.0.1:5000
```

Run the auditor against it (second terminal):

```bash
python -m auditor.main --target http://127.0.0.1:5000 --out report.html
```

Seeded logins for testing: `alice / password123`, `bob / letmein`, `admin / admin`.

## How the code is organized

- **`core.py`** defines a `Finding` — the single shape every check returns
  (category, pass/fail, severity, finding, evidence, recommendation). Everything
  downstream reads `Finding`s, so this is the contract the whole tool is built on.
- **`checks/`** holds one module per weakness, all seven implemented. Each
  exposes `run(target_url)` and returns a `Finding`. `password_policy.py` is
  written as the clearest template for the four-step pattern the others follow.
- **`scoring.py`** starts at 100 and subtracts each failed finding's severity
  weight.
- **`ai_report.py`** takes the *structured* finding and asks an LLM only to
  explain it in plain language — the measurement stays in the Python, the AI
  just writes the "why it matters / how to fix." Falls back to a canned
  explanation if the API is unavailable.
- **`report.py`** renders the findings, score, and explanations to HTML.
- **`main.py`** ties it together: run every check → add AI explanations →
  score → write the report.

## The `SECURE_MODE` switch

One line at the top of `target_app/app.py`. It toggles all seven weaknesses at
once between vulnerable and hardened:

| Weakness | `False` (vulnerable) | `True` (hardened) |
|----------|----------------------|-------------------|
| Password storage | raw MD5 | salted PBKDF2 |
| Username enumeration | reveals which field was wrong | generic message |
| Account lockout | none | locks after 5 fails |
| Session cookie | no HttpOnly/Secure | HttpOnly + Secure |
| Password policy | accepts anything | length + complexity + common-list reject |
| Password reset | leaked, guessable token | random, single-use, expiring token |
| MFA | none | second factor enforced |

Against the vulnerable app the auditor scores **6/100 (Critical)**; flip the
switch and it scores **100/100 (Strong)**. That before/after is the demo.

## Scope

Authorized class exercise. The target app is ours and runs only inside our own
lab (local machine / course VMs). Nothing here is ever pointed at a system we
don't own.
