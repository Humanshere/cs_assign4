# Web Server Security — Exploitation and Mitigation of Four Vulnerability Categories

IIIT Allahabad · Cyber Security (IT-30001) · Autumn 2026
Group assignment — SQL Injection, OS Command Injection, XSS, CSRF

## 1. Setup

```bash
git clone https://github.com/Humanshere/cs_assign4.git
cd cs_assign4
python -m venv venv && source venv/bin/activate   # optional
pip install -r requirements.txt
python init_db.py      # creates app.db with seed data
python app.py           # runs on http://127.0.0.1:5000
```

Run **only on localhost / your own machine**. Do not expose the vulnerable
routes on any shared or public server.

## 2. What's where

| Category | Variant | Vulnerable route | Safe route |
|---|---|---|---|
| SQL Injection | Authentication bypass | `/sql/vulnerable` | `/sql/safe` |
| OS Command Injection | In-band | `/cmd/vulnerable` | `/cmd/safe` |
| XSS | Stored | `/xss/vulnerable` | `/xss/safe` |
| CSRF | POST-based, auto-submitting form | `/csrf/vulnerable` (+ `/csrf/attacker`) | `/csrf/safe` |

## 3. Exploit payloads used in the demo

- **SQLi auth bypass:** username `admin' --`, any password.
- **Command injection (in-band):** host field `127.0.0.1; whoami` or `127.0.0.1 && cat /etc/hostname`.
- **Stored XSS:** comment body `<script>alert(document.cookie)</script>`.
- **CSRF:** open `/csrf/vulnerable` (acts as the logged-in victim), then in another tab open `/csrf/attacker`, which auto-submits a hidden form to the transfer endpoint and moves funds without the victim clicking anything on the real site.

## 4. Root cause (one line each)

- **SQLi:** user input is concatenated directly into the SQL query string, so injected quotes/operators change the query's logic.
- **Command injection:** user input is passed to a shell (`shell=True`) as part of a command string, so shell metacharacters (`;`, `&&`, `|`) chain in extra commands.
- **XSS:** stored user input is rendered back into the page as raw HTML (no output encoding), so a stored `<script>` tag executes in every visitor's browser.
- **CSRF:** the state-changing endpoint accepts a request based only on the ambient session cookie, with no proof the request was intentionally made by the user from the real site.

## 5. Mitigation implemented (one per vulnerability)

- **SQLi →** parameterised queries / prepared statements (`db.execute("... WHERE username=? AND password=?", (u, p))`). Input is always sent as data, never as SQL code.
- **Command injection →** allow-list input validation (regex restricting the host field to `[A-Za-z0-9.-]`) **and** no shell at all — the command is invoked as an argument vector (`subprocess.run(["ping","-c","1",host], shell=False)`).
- **XSS →** Jinja2's default auto-escaping left in place (no `| safe` filter) so `<`, `>`, `&`, `"` are rendered as text, not markup.
- **CSRF →** synchronizer (anti-CSRF) token: a per-session random token is embedded in the real form and verified server-side on submit; a cross-origin auto-submit cannot read or reproduce it.

## 6. Other mitigation options (theory only — required per instructions)

**SQL injection — also discussed in class:**
- *Input validation with allow-lists* — restrict input to expected characters/format (weaker alone than parameterisation, since it's easy to miss an edge case).
- *Least-privilege database accounts* — the app's DB user should only have the minimum rights it needs (e.g. no `DROP`, no access to other schemas), so a successful injection has limited blast radius.
- *Safe error handling* — never return raw database errors to the client; verbose errors leak schema/query structure that helps an attacker refine payloads.

**OS command injection — also discussed in class:**
- *Avoid the shell entirely wherever possible* — prefer a language/library API that does the job without spawning a shell subprocess.
- *Allow-list validation* of any input that must be passed to an external program (format, length, character set).
- *Least privilege* — run the process that executes system commands with a minimally privileged OS account, limiting what an injected command can actually do.

**XSS — also discussed in class:**
- *Context-aware output encoding* — encode differently depending on whether output lands in HTML body, an attribute, a URL, or a `<script>` block.
- *Framework auto-escaping* (what we used) — rely on the templating engine's default escaping rather than manually building HTML strings.
- *A sanitiser for rich HTML* (e.g. when limited formatting must be allowed) — strip dangerous tags/attributes while keeping safe markup.
- *Content Security Policy (CSP)* — a response header restricting which script sources the browser will execute, mitigating XSS even if a payload slips through.
- *HttpOnly cookies* — prevents JavaScript (including injected scripts) from reading session cookies via `document.cookie`.
- *Safe DOM sinks* — avoid `innerHTML`/`document.write` with untrusted data on the client side; use `textContent` or safe DOM APIs instead.

**CSRF — also discussed in class:**
- *SameSite cookies* (`Lax`/`Strict`) — the browser withholds the session cookie on cross-site requests, so the forged request arrives unauthenticated.
- *Re-authentication for sensitive actions* — require a password/OTP re-entry immediately before high-value actions (e.g. large transfers, changing email), limiting what a forged request alone can achieve.
- *Avoiding state-changing GET requests* — GET requests are trivially triggered by an `<img>`/`<a>` tag, so all state changes should require POST (or another non-idempotent-safe method) at minimum.

## 7. Ownership declaration (Table 3)

| Member name | Roll number | Category | Variant implemented |
|---|---|---|---|
| Himansh Arora | IIB2024025 | SQL Injection | Authentication bypass |
| Priti Yadav | IIT2024219 | OS Command Injection | In-band |
| Aaryan Degama | IIB2024023 | Cross-Site Scripting (XSS) | Stored XSS |
| Geethika Gorakala | IIB2024024 | Cross-Site Request Forgery (CSRF) | POST-based forged action |

## 8. Project structure

```
app.py                 # all Flask routes (vulnerable + safe, per category)
init_db.py              # creates app.db with seed users/comments/accounts
requirements.txt
templates/               # one vulnerable + one safe template per category
static/style.css
VOICEOVER_SCRIPT.md      # per-member narration script for the video (2-3 min each)
```
