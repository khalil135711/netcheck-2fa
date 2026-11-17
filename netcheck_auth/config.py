"""Central configuration. Secrets come from the environment, never from code."""
import os
from datetime import timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


class Config:
    # --- secrets (required, see `python manage.py gen-keys`) -----------------
    SECRET_KEY = os.environ.get("NETCHECK_SECRET_KEY")        # signs session cookies
    TOTP_ENC_KEY = os.environ.get("NETCHECK_TOTP_KEY")        # Fernet key: TOTP secrets at rest
    BACKUP_PEPPER = os.environ.get("NETCHECK_PEPPER")         # HMAC key for backup-code hashes

    # --- storage -------------------------------------------------------------
    DATABASE = os.environ.get("NETCHECK_DB", str(BASE_DIR / "instance" / "netcheck.db"))

    # --- authentication policy ----------------------------------------------
    ISSUER = "ISO27001-Netcheck"          # label shown in the authenticator app
    REQUIRE_2FA = True                    # users without 2FA are forced into enrollment
    MIN_PASSWORD_LENGTH = 12
    MAX_FAILED_ATTEMPTS = 5               # per account, password and 2FA steps combined
    LOCKOUT_SECONDS = 15 * 60
    TOTP_WINDOW = 1                       # accept +/- 1 time step (30 s) for clock drift
    BACKUP_CODE_COUNT = 10
    PENDING_2FA_SECONDS = 5 * 60          # time allowed between password and code step

    # --- throttling per client IP (in-memory, per process) -------------------
    IP_LIMIT = 20
    IP_WINDOW_SECONDS = 5 * 60

    # --- sessions ------------------------------------------------------------
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)   # idle timeout
    ABSOLUTE_SESSION_SECONDS = 8 * 60 * 60               # hard limit regardless of activity
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    # Secure cookies need HTTPS. For local http testing only:
    #   export NETCHECK_INSECURE_COOKIES=1
    SESSION_COOKIE_SECURE = os.environ.get("NETCHECK_INSECURE_COOKIES") != "1"
    MAX_CONTENT_LENGTH = 16 * 1024
