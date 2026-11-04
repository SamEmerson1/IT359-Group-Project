# CredentialGuard

**Authentication Security Auditor · Sentinel Security Solutions** · IT 359-002 Group 5 · Prof. Dmitry Zhdanov

CredentialGuard is a Python tool that audits a web app's login and account
system for common authentication weaknesses and produces an overall
**authentication security score** with plain-language, AI-assisted remediation
notes. The included demo target app stands in for a fictional client site
(Northstar Commerce) for testing.

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

### Running the auditor from a separate host (e.g. Kali)

For the realistic setup — app on Windows, auditor on Kali:

```bash
python -m auditor.main --target http://<app-host-ip>:5000 --db ./users.db --out report.html
```

- Point `--target` at the app host's IP (and open port 5000 in its firewall).
- Six checks run over the network. The storage check is **white-box** — it
  reads the database directly — so copy the app's `users.db` to the auditor
  host and pass it with `--db` (or set the `AUDITOR_DB` env var). Re-copy it
  whenever you flip `SECURE_MODE`, since the file is rewritten on each restart.

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

---

## Lab notes (for the team)

### How the pieces fit (the story)

We run this as a small *authorized* penetration test, not just a program on one machine:

- **Windows 11 VM** runs the target app — the "victim" with the weak login.
- **Kali VM** runs the auditor — the "tester" reaching the target over the network.
- **pfSense** is the network boundary between them.

That separation is deliberate: it mirrors a real remote assessment, where the tester only sees what is exposed over the network.

**Black-box vs white-box (why the storage check says "not reachable"):**

- *Black-box* = testing from outside with no inside access — what the Kali box does. From there you cannot read the target's files, so the auditor cannot open `users.db` to inspect how passwords are stored. That is correct and expected, not a bug.
- *White-box* = testing with host access. Run directly on the Windows box (as the app's owner), the same check would read `users.db` and confirm passwords are stored as unsalted **MD5** — a critical flaw. It is possible (`python -m auditor.checks.storage` on the Windows box, or pass a copied DB with `--db`), but we keep the remote run black-box for an authentic story.

So the remote score is **31/100**; password storage is simply out of scope for a remote test.

### Heads-up: in secure mode, browser login only works on localhost

In secure mode the session cookie is marked `Secure`, which browsers only send over HTTPS — with one exception: `localhost` / `127.0.0.1`. We serve plain HTTP, so:

- Browser login + MFA **works on the Windows box at `http://127.0.0.1:5000`**.
- Over the **LAN IP (192.168.1.x) the browser drops the Secure cookie**, so the MFA step loses its session and bounces back to the login page. This is the Secure flag working correctly, not a bug.
- The **auditor from Kali is unaffected** (it does not rely on the browser keeping that cookie), so the 100/100 hardened scan is valid.

For videos: do the secure-mode browser demo on `127.0.0.1` on the Windows box, and run the scan from Kali.

### Commands cheat-sheet

**Windows (target app):**

```powershell
py target_app\app.py
# flip to hardened:
(Get-Content target_app\app.py) -replace 'SECURE_MODE = False','SECURE_MODE = True' | Set-Content target_app\app.py
# flip back to vulnerable:
(Get-Content target_app\app.py) -replace 'SECURE_MODE = True','SECURE_MODE = False' | Set-Content target_app\app.py
# one-time firewall rule (admin PowerShell):
New-NetFirewallRule -DisplayName "IT359 lab 5000" -Direction Inbound -Protocol TCP -LocalPort 5000 -Action Allow
```

**Kali (auditor):**

```bash
source .venv/bin/activate        # each new terminal
python -m auditor.main --target http://192.168.1.101:5000 --db ./users.db --out report.html
# confirm the AI key is set:
python -c "from openai import OpenAI; print(OpenAI().chat.completions.create(model='gpt-4o-mini',messages=[{'role':'user','content':'say ok'}]).choices[0].message.content)"
```

Replace `192.168.1.101` with the Windows VM's current IP (`ipconfig`).
