"""
app.py — Web Server Security assignment demo app
IIIT Allahabad | IT-30001 Cyber Security

Four members, four categories, one variant each:
  1. SQL Injection        -> Authentication bypass        (/sql/vulnerable, /sql/safe)
  2. OS Command Injection -> In-band                       (/cmd/vulnerable, /cmd/safe)
  3. XSS                  -> Stored XSS                    (/xss/vulnerable, /xss/safe)
  4. CSRF                 -> POST-based forged action       (/csrf/vulnerable, /csrf/safe)

Run:
    python init_db.py
    python app.py
Then open http://127.0.0.1:5000/

IMPORTANT: This app is deliberately insecure in its "vulnerable" routes.
Run it ONLY on localhost / your own isolated test machine. Never deploy
the vulnerable routes to a public server or shared infrastructure.
"""

import os
import re
import secrets
import sqlite3
import subprocess

from flask import (Flask, g, redirect, render_template, request, session,
                    url_for, flash)

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
DB_PATH = os.path.join(os.path.dirname(__file__), "app.db")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


@app.route("/")
def index():
    return render_template("index.html")


# ----------------------------------------------------------------------
# 1. SQL INJECTION — Authentication bypass
# ----------------------------------------------------------------------
# ROOT CAUSE: user-supplied input is concatenated directly into the SQL
# query string, so an attacker can inject SQL syntax (e.g. `' OR '1'='1`
# or `admin'--`) that changes the query's logic and bypasses the
# password check entirely.

@app.route("/sql/vulnerable", methods=["GET", "POST"])
def sql_vulnerable():
    result = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        db = get_db()
        # VULNERABLE: raw string formatting straight into the query.
        query = (
            "SELECT * FROM users WHERE username = '"
            + username
            + "' AND password = '"
            + password
            + "'"
        )
        try:
            row = db.execute(query).fetchone()
        except sqlite3.Error as e:
            row = None
            result = f"DB error: {e}"
        if row:
            result = f"Logged in as '{row['username']}' (admin={row['is_admin']}) — AUTH BYPASSED"
        elif result is None:
            result = "Login failed."
        app.logger.info("SQLi vulnerable query executed: %s", query)
    return render_template("sql_vulnerable.html", result=result)


@app.route("/sql/safe", methods=["GET", "POST"])
def sql_safe():
    result = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        db = get_db()
        # MITIGATION: parameterised query (prepared statement). The
        # driver sends username/password as data, never as SQL code,
        # so injected quotes/operators cannot change the query logic.
        row = db.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, password),
        ).fetchone()
        if row:
            result = f"Logged in as '{row['username']}' (admin={row['is_admin']})"
        else:
            result = "Login failed."
    return render_template("sql_safe.html", result=result)


# ----------------------------------------------------------------------
# 2. OS COMMAND INJECTION — In-band (output returned to the user)
# ----------------------------------------------------------------------
# ROOT CAUSE: user input is passed to a shell (shell=True / os.popen)
# as part of a command string, so shell metacharacters (; & | &&)
# let the attacker chain in arbitrary commands, whose output is then
# shown back to them (hence "in-band").

@app.route("/cmd/vulnerable", methods=["GET", "POST"])
def cmd_vulnerable():
    output = None
    if request.method == "POST":
        host = request.form.get("host", "")
        # VULNERABLE: shell=True + string concatenation -> shell metacharacters
        # like ; && | are interpreted by the shell, not treated as data.
        cmd = f"ping -c 1 {host}"
        try:
            output = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=10
            ).stdout
        except Exception as e:
            output = str(e)
        app.logger.info("Command-injection vulnerable cmd executed: %s", cmd)
    return render_template("cmd_vulnerable.html", output=output)


@app.route("/cmd/safe", methods=["GET", "POST"])
def cmd_safe():
    output = None
    error = None
    if request.method == "POST":
        host = request.form.get("host", "")
        # MITIGATION 1: allow-list validation — only characters valid in a
        # hostname/IPv4 address are accepted; shell metacharacters are rejected.
        if not re.fullmatch(r"[A-Za-z0-9.\-]{1,253}", host):
            error = "Invalid host — only letters, digits, '.' and '-' are allowed."
        else:
            # MITIGATION 2: no shell at all — argument vector form, so even if
            # validation were imperfect, there is no shell to interpret ; & |.
            try:
                output = subprocess.run(
                    ["ping", "-c", "1", host],
                    shell=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                ).stdout
            except Exception as e:
                output = str(e)
    return render_template("cmd_safe.html", output=output, error=error)


# ----------------------------------------------------------------------
# 3. XSS — Stored XSS
# ----------------------------------------------------------------------
# ROOT CAUSE: a comment is stored as submitted, then rendered back into
# the page HTML without encoding (the vulnerable template marks it
# `| safe`), so a <script> payload saved by one user executes in every
# other user's browser when they view the comment board.

@app.route("/xss/vulnerable", methods=["GET", "POST"])
def xss_vulnerable():
    db = get_db()
    if request.method == "POST":
        author = request.form.get("author", "anonymous")
        body = request.form.get("body", "")
        db.execute("INSERT INTO comments (author, body) VALUES (?,?)", (author, body))
        db.commit()
    comments = db.execute("SELECT author, body FROM comments ORDER BY id DESC").fetchall()
    # VULNERABLE: template renders `comment.body | safe`, i.e. raw HTML,
    # so stored <script> tags execute for every visitor.
    return render_template("xss_vulnerable.html", comments=comments)


@app.route("/xss/safe", methods=["GET", "POST"])
def xss_safe():
    db = get_db()
    if request.method == "POST":
        author = request.form.get("author", "anonymous")
        body = request.form.get("body", "")
        db.execute("INSERT INTO comments (author, body) VALUES (?,?)", (author, body))
        db.commit()
    comments = db.execute("SELECT author, body FROM comments ORDER BY id DESC").fetchall()
    # MITIGATION: Jinja2's default auto-escaping is used (no `| safe` filter),
    # so <, >, &, " in stored content are rendered as inert text, not HTML/JS.
    return render_template("xss_safe.html", comments=comments)


# ----------------------------------------------------------------------
# 4. CSRF — POST-based forged action (auto-submitting form)
# ----------------------------------------------------------------------
# ROOT CAUSE: the /csrf/vulnerable/transfer endpoint changes state
# (moves money) based solely on the user's ambient session cookie, with
# no proof that the request was intentionally submitted by that user
# from the real site. A malicious page can auto-submit a hidden form to
# this URL and the browser will attach the victim's cookies for them.

VICTIM_USER = "alice"  # the "logged in" user for this demo


@app.route("/csrf/vulnerable", methods=["GET"])
def csrf_vulnerable():
    db = get_db()
    row = db.execute("SELECT balance FROM accounts WHERE username=?", (VICTIM_USER,)).fetchone()
    return render_template("csrf_vulnerable.html", balance=row["balance"], user=VICTIM_USER)


@app.route("/csrf/vulnerable/transfer", methods=["POST"])
def csrf_vulnerable_transfer():
    # VULNERABLE: no CSRF token is checked here — any site can submit this
    # form on the victim's behalf and the browser attaches their cookies.
    amount = int(request.form.get("amount", 0))
    to = request.form.get("to", "bob")
    db = get_db()
    db.execute("UPDATE accounts SET balance = balance - ? WHERE username=?", (amount, VICTIM_USER))
    db.execute("UPDATE accounts SET balance = balance + ? WHERE username=?", (amount, to))
    db.commit()
    return redirect(url_for("csrf_vulnerable"))


@app.route("/csrf/attacker")
def csrf_attacker():
    # A standalone page simulating an attacker's site: an auto-submitting
    # hidden form pointed at the vulnerable transfer endpoint.
    return render_template("csrf_attacker.html")


@app.route("/csrf/safe", methods=["GET"])
def csrf_safe():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    db = get_db()
    row = db.execute("SELECT balance FROM accounts WHERE username=?", (VICTIM_USER,)).fetchone()
    return render_template(
        "csrf_safe.html", balance=row["balance"], user=VICTIM_USER, csrf_token=session["csrf_token"]
    )


@app.route("/csrf/safe/transfer", methods=["POST"])
def csrf_safe_transfer():
    # MITIGATION: synchronizer token pattern — the form must submit the
    # same unpredictable token that was placed in the user's session when
    # the real page was rendered. A cross-site auto-submit cannot read or
    # reproduce this token, so the forged request is rejected.
    token = request.form.get("csrf_token", "")
    if not token or token != session.get("csrf_token"):
        flash("Request blocked: missing or invalid CSRF token.")
        return redirect(url_for("csrf_safe"))
    amount = int(request.form.get("amount", 0))
    to = request.form.get("to", "bob")
    db = get_db()
    db.execute("UPDATE accounts SET balance = balance - ? WHERE username=?", (amount, VICTIM_USER))
    db.execute("UPDATE accounts SET balance = balance + ? WHERE username=?", (amount, to))
    db.commit()
    # rotate token after use
    session["csrf_token"] = secrets.token_hex(16)
    return redirect(url_for("csrf_safe"))


if __name__ == "__main__":
    app.run(debug=True, port=5000)
