# ISO 27001 Netcheck: Authentication with TOTP 2FA

Password login plus a mandatory second factor (time-based one-time passwords, RFC 6238) for the
Netcheck dashboard. Built with Flask; the only required dependency besides Flask is `cryptography`.

## Features

| Area | What it does |
|---|---|
| Passwords | scrypt hashing (Werkzeug), minimum length 12, timing-equalized login for unknown users |
| TOTP | Own RFC 6238 implementation (verified against the RFC test vectors), ±1 step drift window |
| Replay protection | A time step can be used only once; the check is an atomic `UPDATE ... WHERE last_step < ?` |
| Secrets at rest | TOTP secrets encrypted with Fernet (AES-128-CBC + HMAC); backup codes stored only as HMAC-SHA256 |
| Backup codes | 10 single-use codes (48 bit each), shown once, regenerate with password + code |
| Brute-force defense | Account lockout (5 failures → 15 min) across password *and* 2FA steps, plus per-IP throttle |
| Sessions | New session on login (no fixation), HttpOnly/Secure/SameSite cookies, 30 min idle + 8 h absolute timeout |
| Web security | CSRF tokens on every POST, strict CSP (no scripts), `X-Frame-Options`, HSTS, `no-store` |
| Audit log | Login, failure, lockout, 2FA enable/disable, backup-code events in the `audit_log` table |
| Policy | `REQUIRE_2FA = True` forces enrollment at first login and blocks disabling |

### ISO/IEC 27001:2022 mapping (Annex A)

- **A.5.17 Authentication information**: hashed passwords, encrypted TOTP secrets, hashed backup codes
- **A.8.5 Secure authentication**: MFA, lockout, session timeouts
- **A.8.15 Logging**: append-only audit log of authentication events (`python manage.py audit`)

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 1) Generate secrets and export them (keep them OUT of git)
python manage.py gen-keys          # prints three `export NETCHECK_...` lines
export NETCHECK_INSECURE_COOKIES=1 # local http only! remove behind HTTPS

# 2) Create a user (password is prompted)
python manage.py create-user alice

# 3) Run
flask --app netcheck_auth run
```

Open <http://127.0.0.1:5000>, sign in, scan the QR code with an authenticator app, confirm the code,
and store the backup codes.

> **Production:** run behind HTTPS (e.g. nginx + gunicorn), do **not** set `NETCHECK_INSECURE_COOKIES`,
> and keep the three secrets in a secret manager. Back up `NETCHECK_TOTP_KEY`: losing it means users
> must re-enroll. The per-IP throttle is in-memory (per process); use a shared store such as Redis
> if you run several workers.

## Protecting your own Netcheck views

```python
from netcheck_auth.routes import login_required

@bp.route("/scan")
@login_required
def scan():
    ...
```

## Tests

```bash
python -m unittest discover -s tests -v
```

Covers RFC 6238 vectors, replay rejection, backup-code single use, lockout, CSRF, enumeration-safe
errors, encryption at rest, pending-login expiry, and the fail-closed startup check.

## Project layout

```
netcheck_auth/
  __init__.py     app factory, CSRF, security headers
  config.py       policy and settings
  db.py           SQLite schema + audit helper
  security.py     TOTP, Fernet, hashing, backup codes
  routes.py       login, 2FA step, enrollment, management
  templates/ static/
manage.py         gen-keys, create-user, audit
tests/test_auth.py
```

## Known limitations / ideas

- TOTP can be phished in real-time attacks; WebAuthn/passkeys (e.g. via the `webauthn` package) would be the next step.
- No password reset flow (admin resets via CLI). Add one only together with identity verification.
- SQLite is fine for a portfolio/demo; use PostgreSQL for multi-user deployments.
