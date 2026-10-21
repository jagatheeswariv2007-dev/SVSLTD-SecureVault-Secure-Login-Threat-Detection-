# SecureVault — Secure Login and Threat Detection System

**Author:** Jagatheeswari V  
**Purpose:** IBM SkillsBuild Cyber Security Bootcamp project and beginner software-development practice.

## Project overview

SecureVault is a local educational web application demonstrating safer password storage, basic password-strength validation, protection against repeated failed login attempts, security-event logging, and automated tests.

### Features
- User registration with username validation.
- Password hashing with Werkzeug's password-hashing utility (no plaintext passwords stored).
- Basic password-strength policy.
- Temporary username-based lockout after five failed login attempts within a ten-minute window.
- Security-event dashboard protected by login.
- SQLite database and parameterized SQL queries.
- Backend tests using pytest and optional browser UI tests using Playwright.

## Technology stack
- Python 3.10+
- Flask
- SQLite
- Werkzeug
- pytest
- Playwright (optional browser automation)

## Dataset / data source
This version does not require an external dataset. It generates synthetic security-event records as users register, log in, fail login attempts, and log out. Do not use real personal credentials or real user data in the demonstration.

## Project structure

```text
SecureVault_Project/
├── app.py
├── requirements.txt
├── README.md
├── JagatheeswariV_ProjectReport.docx
└── tests/
    ├── test_app.py
    └── test_ui.py
```

## Setup on Windows using VS Code

1. Install Python 3.10 or newer and VS Code.
2. Open this folder in VS Code.
3. Open **Terminal → New Terminal**.
4. Create a virtual environment:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

   If PowerShell blocks activation, use Command Prompt and run:
   ```bat
   .venv\Scripts\activate.bat
   ```

5. Install dependencies:

   ```powershell
   python -m pip install --upgrade pip
   python -m pip install -r requirements.txt
   ```

6. Start the web application:

   ```powershell
   python app.py
   ```

7. Open `http://127.0.0.1:5000` in your browser. Use a unique test username and a demo password that meets the policy. Do not use a password from another account.

## Run backend tests

Stop the app if needed, then run:

```powershell
python -m pytest tests/test_app.py -v
```

The tests use a temporary SQLite database and cover the home/health routes, registration, weak and duplicate passwords, login, protected dashboard access, lockout, and logout.

## Run browser automation tests (optional)

1. Keep the app running in one terminal with `python app.py`.
2. In a second terminal, install Playwright's Chromium browser once:

   ```powershell
   python -m playwright install chromium
   ```

3. Run:

   ```powershell
   python -m pytest tests/test_ui.py -v
   ```

## Security notes and limitations
- This is a learning demo, not production-ready authentication software.
- Change `SECRET_KEY` before any deployment. Set the environment variable `SECUREVAULT_SECRET_KEY` to a long random secret.
- Use HTTPS in deployment and set `SECUREVAULT_HTTPS=1` only when HTTPS is correctly configured.
- Use a production WSGI server, CSRF protection for state-changing forms, centralized rate limiting, account recovery, monitoring, secure deployment configuration, and a security review before production use.
- The lockout is keyed by username and is intentionally simple. A production system should combine controls carefully to reduce account-enumeration and denial-of-service risks.
- The built-in Flask development server must not be exposed to the public internet.

## Expected demonstration
1. Register a new demo account with a strong password.
2. Log in and inspect the dashboard.
3. Log out and confirm the dashboard redirects to login.
4. Enter an incorrect password five times and confirm a lockout message.
5. Run the pytest suite and (optionally) the Playwright UI tests.

## Author
Jagatheeswari V — B.Tech Artificial Intelligence and Data Science student
