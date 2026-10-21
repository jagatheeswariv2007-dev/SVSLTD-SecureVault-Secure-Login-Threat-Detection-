"""
SecureVault: Secure Login and Threat Detection System
Educational cybersecurity project for IBM SkillsBuild Cyber Security Bootcamp.

Run:
    python -m pip install -r requirements.txt
    python app.py
Open http://127.0.0.1:5000
"""
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, flash, redirect, render_template_string, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.environ.get("SECUREVAULT_DB", os.path.join(APP_DIR, "securevault.db"))
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 10
MIN_PASSWORD_LENGTH = 10

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECUREVAULT_SECRET_KEY", "dev-only-change-this-secret-key"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SECUREVAULT_HTTPS", "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)


def utc_now():
    """Return a timezone-aware UTC timestamp as ISO text."""
    return datetime.now(timezone.utc).isoformat()


def connect_db():
    """Open a SQLite connection and return rows by column name."""
    connection = sqlite3.connect(DATABASE_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    """Create the application's tables if they do not already exist."""
    with connect_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                event_type TEXT NOT NULL,
                details TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        db.commit()


def log_event(username, event_type, details):
    """Record security events without storing passwords or password hashes."""
    safe_username = (username or "unknown")[:80]
    safe_details = (details or "")[:240]
    with connect_db() as db:
        db.execute(
            "INSERT INTO security_events (username, event_type, details, created_at) VALUES (?, ?, ?, ?)",
            (safe_username, event_type[:40], safe_details, utc_now()),
        )
        db.commit()


def password_is_strong(password):
    """Simple educational password policy; this is not a password-cracking tool."""
    return (
        len(password) >= MIN_PASSWORD_LENGTH
        and any(char.islower() for char in password)
        and any(char.isupper() for char in password)
        and any(char.isdigit() for char in password)
        and any(not char.isalnum() for char in password)
    )


def recent_failed_attempts(username):
    """Count failed logins for this username in the configured lockout window."""
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
    with connect_db() as db:
        row = db.execute(
            """SELECT COUNT(*) AS count FROM security_events
               WHERE username = ? AND event_type = 'login_failed' AND created_at >= ?""",
            (username, cutoff),
        ).fetchone()
    return int(row["count"])


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to view the dashboard.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


BASE_STYLE = """
:root { color-scheme: light; --navy:#12213a; --blue:#2864dc; --mint:#d9f7ed; --paper:#f5f7fb; --ink:#182337; }
* { box-sizing:border-box; }
body { margin:0; font-family:Inter,Segoe UI,Arial,sans-serif; background:var(--paper); color:var(--ink); }
nav { background:var(--navy); color:white; padding:16px max(5vw,20px); display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap; }
nav a { color:white; text-decoration:none; margin-left:16px; }
.brand { font-weight:800; letter-spacing:.2px; }
main { max-width:1000px; margin:36px auto; padding:0 18px; }
.hero { background:linear-gradient(135deg,#12213a,#204d83); color:white; padding:28px; border-radius:18px; margin-bottom:22px; }
.hero p { color:#e0eaf8; line-height:1.6; }
.cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); gap:14px; margin:20px 0; }
.card, .panel { background:white; border:1px solid #e2e8f0; border-radius:14px; padding:20px; box-shadow:0 6px 20px #14213a0a; }
.metric { font-size:28px; font-weight:800; color:var(--blue); margin-top:8px; }
form { display:grid; gap:12px; }
label { font-weight:650; }
input { width:100%; padding:12px; border:1px solid #cbd5e1; border-radius:9px; font-size:16px; margin-top:6px; }
button, .button { background:var(--blue); color:white; border:0; padding:12px 16px; border-radius:9px; font-weight:700; cursor:pointer; text-decoration:none; display:inline-block; }
button:hover, .button:hover { filter:brightness(.92); }
.muted { color:#64748b; font-size:14px; line-height:1.5; }
.flash { padding:12px 14px; border-radius:9px; margin:12px 0; background:#eaf1ff; }
.flash.success { background:#dcfce7; } .flash.danger { background:#fee2e2; } .flash.warning { background:#fef3c7; }
table { width:100%; border-collapse:collapse; background:white; border-radius:12px; overflow:hidden; }
th,td { text-align:left; padding:12px; border-bottom:1px solid #e2e8f0; font-size:14px; }
th { background:#edf2fa; }
.pill { display:inline-block; background:var(--mint); padding:5px 9px; border-radius:99px; font-size:12px; font-weight:700; }
footer { text-align:center; color:#64748b; padding:24px; font-size:13px; }
@media(max-width:600px){ main{margin:20px auto;} .hero{padding:22px;} nav a{margin-left:8px;} }
"""

def page(title, content, authenticated=False):
    nav_links = (
        '<a href="/">Home</a><a href="/dashboard">Dashboard</a><a href="/logout">Log out</a>'
        if authenticated else '<a href="/">Home</a><a href="/register">Register</a><a href="/login">Login</a>'
    )
    return render_template_string("""
    <!doctype html><html lang="en"><head><meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ title }} | SecureVault</title>
    <style>{{ style }}</style></head><body>
    <nav><div class="brand">🛡 SecureVault</div><div>{{ nav_links|safe }}</div></nav>
    <main>
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% for category, message in messages %}<div class="flash {{ category }}" role="status">{{ message }}</div>{% endfor %}
    {% endwith %}
    {{ content|safe }}
    </main><footer>SecureVault • Educational cybersecurity demo • Never use real passwords in a demo</footer>
    </body></html>
    """, title=title, style=BASE_STYLE, nav_links=nav_links, content=content)


@app.route("/")
def home():
    content = """
    <section class="hero">
      <span class="pill">CYBERSECURITY + SOFTWARE DEVELOPMENT</span>
      <h1>Protect accounts. Notice suspicious activity.</h1>
      <p>SecureVault is a beginner-friendly demonstration of safer password storage,
      login protection, security event logging, and automated testing.</p>
      <a class="button" href="/register">Create demo account</a>
      <a class="button" style="background:#ffffff;color:#12213a;margin-left:8px" href="/login">Log in</a>
    </section>
    <section class="cards">
      <div class="card"><strong>Safer password storage</strong><p class="muted">Passwords are hashed with Werkzeug's password-hashing utility; raw passwords are never stored.</p></div>
      <div class="card"><strong>Login protection</strong><p class="muted">Five recent failed attempts trigger a temporary username-based lockout.</p></div>
      <div class="card"><strong>Audit trail</strong><p class="muted">The dashboard displays security events without showing password values.</p></div>
    </section>
    <p class="muted">Learning project only. Use localhost and synthetic test accounts. Before deployment, configure a strong secret key, HTTPS, monitoring, and production-grade rate limiting.</p>
    """
    return page("Home", content, "user_id" in session)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or len(username) < 3 or len(username) > 30 or not username.replace("_", "").isalnum():
            flash("Username must be 3–30 characters and contain only letters, numbers, or underscores.", "danger")
            return redirect(url_for("register"))
        if not password_is_strong(password):
            flash("Use at least 10 characters with uppercase, lowercase, a number, and a symbol.", "danger")
            log_event(username, "registration_rejected", "Password did not meet the strength policy")
            return redirect(url_for("register"))
        try:
            with connect_db() as db:
                db.execute(
                    "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                    (username, generate_password_hash(password), utc_now()),
                )
                db.commit()
        except sqlite3.IntegrityError:
            flash("That username is already registered. Choose another.", "danger")
            log_event(username, "registration_rejected", "Duplicate username")
            return redirect(url_for("register"))
        log_event(username, "registration_success", "New demo account created")
        flash("Account created. You can now log in.", "success")
        return redirect(url_for("login"))
    content = """
    <section class="panel"><h1>Create a demo account</h1>
    <p class="muted">Use a unique test password, not a password you use elsewhere.</p>
    <form method="post">
      <label>Username<input name="username" minlength="3" maxlength="30" required autocomplete="username"></label>
      <label>Password<input name="password" type="password" minlength="10" required autocomplete="new-password"></label>
      <p class="muted">At least 10 characters, with uppercase, lowercase, a number, and a symbol.</p>
      <button type="submit">Register securely</button>
    </form></section>
    """
    return page("Register", content, "user_id" in session)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Enter both username and password.", "danger")
            return redirect(url_for("login"))
        if recent_failed_attempts(username) >= MAX_FAILED_ATTEMPTS:
            log_event(username, "login_blocked", f"Lockout active after repeated failed logins")
            flash(f"Too many failed attempts. Try again after {LOCKOUT_MINUTES} minutes.", "danger")
            return redirect(url_for("login"))
        with connect_db() as db:
            user = db.execute("SELECT id, username, password_hash FROM users WHERE username = ?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            log_event(username, "login_success", "Successful login")
            return redirect(url_for("dashboard"))
        log_event(username, "login_failed", "Invalid username or password")
        flash("Invalid username or password.", "danger")
        return redirect(url_for("login"))
    content = """
    <section class="panel"><h1>Log in</h1>
    <form method="post">
      <label>Username<input name="username" required autocomplete="username"></label>
      <label>Password<input name="password" type="password" required autocomplete="current-password"></label>
      <button type="submit">Log in</button>
    </form><p class="muted">Repeated failed attempts are recorded and can trigger a temporary lockout.</p></section>
    """
    return page("Login", content, "user_id" in session)


@app.route("/dashboard")
@login_required
def dashboard():
    username = session.get("username", "")
    with connect_db() as db:
        user_count = db.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
        event_count = db.execute("SELECT COUNT(*) AS n FROM security_events").fetchone()["n"]
        failed_count = db.execute("SELECT COUNT(*) AS n FROM security_events WHERE event_type IN ('login_failed','login_blocked')").fetchone()["n"]
        events = db.execute(
            "SELECT username, event_type, details, created_at FROM security_events ORDER BY id DESC LIMIT 20"
        ).fetchall()
    rows = "".join(
        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            # Escape all database content before inserting it into the page.
            __import__("html").escape(row["username"]),
            __import__("html").escape(row["event_type"]),
            __import__("html").escape(row["details"]),
            __import__("html").escape(row["created_at"][:19].replace("T", " ")),
        ) for row in events
    ) or '<tr><td colspan="4">No events recorded yet.</td></tr>'
    content = f"""
    <section class="hero"><span class="pill">SIGNED IN</span><h1>Welcome, {__import__("html").escape(username)}.</h1>
    <p>Review recent account and login events. This dashboard is for local learning and demonstration.</p></section>
    <section class="cards">
      <div class="card">Registered demo users<div class="metric">{user_count}</div></div>
      <div class="card">Security events<div class="metric">{event_count}</div></div>
      <div class="card">Failed / blocked logins<div class="metric">{failed_count}</div></div>
    </section>
    <section class="panel"><h2>Recent security events</h2>
    <div style="overflow-x:auto"><table><thead><tr><th>Username</th><th>Event</th><th>Details</th><th>Time (UTC)</th></tr></thead><tbody>{rows}</tbody></table></div>
    <p class="muted">The log intentionally does not contain submitted passwords.</p></section>
    """
    return page("Dashboard", content, True)


@app.route("/logout")
def logout():
    username = session.get("username", "unknown")
    session.clear()
    if username != "unknown":
        log_event(username, "logout", "User logged out")
    flash("You have been logged out.", "success")
    return redirect(url_for("home"))


@app.route("/health")
def health():
    """Simple health endpoint for local smoke tests."""
    return {"status": "ok", "app": "SecureVault"}


init_db()

if __name__ == "__main__":
    # Local development only. Do not expose the Flask development server publicly.
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
