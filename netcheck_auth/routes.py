"""Login, second factor, enrollment and 2FA management."""
import time
from functools import wraps

from flask import (Blueprint, abort, current_app, flash, g, redirect,
                   render_template, request, session, url_for)

from . import security as sec
from .db import audit, get_db

bp = Blueprint("auth", __name__)

GENERIC_LOGIN_ERROR = "Invalid credentials, or the account is temporarily locked."


# ============================================================ helper functions
def _cfg(key):
    return current_app.config[key]


def ip_rate_limited() -> bool:
    """Sliding-window throttle per client IP (in-memory, per process)."""
    hits = current_app.extensions["ip_hits"][request.remote_addr or "?"]
    now = time.time()
    while hits and hits[0] < now - _cfg("IP_WINDOW_SECONDS"):
        hits.popleft()
    if len(hits) >= _cfg("IP_LIMIT"):
        return True
    hits.append(now)
    return False


def is_locked(user) -> bool:
    return user["locked_until"] > time.time()


def register_failure(user, event: str) -> None:
    """Count a failed password/2FA attempt and lock the account when the limit is hit."""
    db = get_db()
    attempts = user["failed_attempts"] + 1
    locked_until = 0
    if attempts >= _cfg("MAX_FAILED_ATTEMPTS"):
        locked_until = int(time.time()) + _cfg("LOCKOUT_SECONDS")
        attempts = 0
        audit("account_locked", user)
    db.execute("UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?",
               (attempts, locked_until, user["id"]))
    db.commit()
    audit(event, user)


def get_user_by_id(uid):
    return get_db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()


def get_user_by_name(name):
    return get_db().execute("SELECT * FROM users WHERE username=?", (name,)).fetchone()


def current_user():
    """Return the fully authenticated user for this request, or None."""
    if "user" in g:
        return g.user
    g.user = None
    uid = session.get("uid")
    if uid:
        expired = time.time() - session.get("auth_time", 0) > _cfg("ABSOLUTE_SESSION_SECONDS")
        user = None if expired else get_user_by_id(uid)
        # A session without MFA is invalid once the account has 2FA enabled.
        if user is None or (user["totp_enabled"] and not session.get("mfa")):
            session.clear()
        else:
            g.user = user
    return g.user


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if user is None:
            return redirect(url_for("auth.login"))
        if (_cfg("REQUIRE_2FA") and not user["totp_enabled"]
                and request.endpoint not in ("auth.setup_2fa", "auth.logout")):
            flash("Two-factor authentication is mandatory. Please set it up first.", "info")
            return redirect(url_for("auth.setup_2fa"))
        return view(*args, **kwargs)
    return wrapped


def complete_login(user, mfa: bool) -> None:
    """Start a fresh session (prevents fixation) and reset the failure counter."""
    session.clear()
    session.permanent = True
    session["uid"] = user["id"]
    session["auth_time"] = int(time.time())
    session["mfa"] = mfa
    db = get_db()
    db.execute("UPDATE users SET failed_attempts=0, locked_until=0 WHERE id=?", (user["id"],))
    db.commit()
    audit("login_ok" if mfa else "login_ok_no_mfa", user)


def _issue_backup_codes(user_id: int) -> list[str]:
    db = get_db()
    codes = sec.generate_backup_codes(_cfg("BACKUP_CODE_COUNT"))
    db.execute("DELETE FROM backup_codes WHERE user_id=?", (user_id,))
    db.executemany(
        "INSERT INTO backup_codes (user_id, code_hash) VALUES (?,?)",
        [(user_id, sec.hash_backup_code(_cfg("BACKUP_PEPPER"),
                                        sec.normalize_backup_code(c))) for c in codes],
    )
    db.commit()
    return codes


def _verify_totp_for_user(user, code: str) -> bool:
    """Verify a TOTP code and atomically burn its time step (no replays)."""
    token = user["totp_secret_enc"]
    secret = sec.decrypt_secret(_cfg("TOTP_ENC_KEY"), token) if token else None
    if secret is None:
        return False
    step = sec.verify_totp(secret, code, user["totp_last_step"], _cfg("TOTP_WINDOW"))
    if step is None:
        return False
    db = get_db()
    cur = db.execute("UPDATE users SET totp_last_step=? WHERE id=? AND totp_last_step<?",
                     (step, user["id"], step))
    db.commit()
    return cur.rowcount == 1


def _use_backup_code(user, code: str) -> bool:
    normalized = sec.normalize_backup_code(code)
    if normalized is None:
        return False
    db = get_db()
    cur = db.execute(
        "UPDATE backup_codes SET used_at=? WHERE user_id=? AND code_hash=? AND used_at IS NULL",
        (int(time.time()), user["id"], sec.hash_backup_code(_cfg("BACKUP_PEPPER"), normalized)),
    )
    db.commit()
    return cur.rowcount == 1


def verify_second_factor(user, raw: str) -> str | None:
    """Returns 'totp', 'backup' or None."""
    compact = "".join(ch for ch in raw if not ch.isspace())
    if len(compact) == sec.TOTP_DIGITS and compact.isascii() and compact.isdigit():
        return "totp" if _verify_totp_for_user(user, compact) else None
    return "backup" if _use_backup_code(user, compact) else None


def reauthenticate(user, password: str, code: str) -> bool:
    """Password + current TOTP code, required for sensitive 2FA changes."""
    if is_locked(user):
        return False
    ok = sec.verify_password(user["password_hash"], password) and _verify_totp_for_user(user, code)
    if not ok:
        register_failure(user, "reauth_failed")
    return ok


# ==================================================================== routes
@bp.route("/")
@login_required
def dashboard():
    # >>> Your Netcheck / ISO 27001 views go here. Protect each one with @login_required. <<<
    return render_template("dashboard.html", user=g.user)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user():
        return redirect(url_for("auth.dashboard"))
    if request.method == "POST":
        if ip_rate_limited():
            abort(429, description="Too many attempts. Please wait a few minutes.")
        username = request.form.get("username", "").strip()[:64]
        password = request.form.get("password", "")[:256]
        user = get_user_by_name(username)

        # Always run one password hash, even for unknown users (timing equalization).
        hash_to_check = user["password_hash"] if user else sec.DUMMY_PASSWORD_HASH
        password_ok = sec.verify_password(hash_to_check, password)

        if user is None:
            audit("login_unknown_user", username=username)
        elif is_locked(user):
            audit("login_while_locked", user)
        elif not password_ok:
            register_failure(user, "login_bad_password")
        else:
            if user["totp_enabled"]:
                session.clear()
                session["pending_uid"] = user["id"]
                session["pending_exp"] = time.time() + _cfg("PENDING_2FA_SECONDS")
                return redirect(url_for("auth.login_2fa"))
            complete_login(user, mfa=False)
            return redirect(url_for("auth.dashboard"))
        flash(GENERIC_LOGIN_ERROR, "error")
    return render_template("login.html")


@bp.route("/login/2fa", methods=["GET", "POST"])
def login_2fa():
    uid = session.get("pending_uid")
    if not uid or session.get("pending_exp", 0) < time.time():
        session.clear()
        flash("Your login attempt expired. Please start again.", "error")
        return redirect(url_for("auth.login"))
    user = get_user_by_id(uid)
    if user is None:
        session.clear()
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        if ip_rate_limited():
            abort(429, description="Too many attempts. Please wait a few minutes.")
        if is_locked(user):
            audit("2fa_while_locked", user)
            flash(GENERIC_LOGIN_ERROR, "error")
        else:
            method = verify_second_factor(user, request.form.get("code", "")[:32])
            if method:
                if method == "backup":
                    audit("backup_code_used", user)
                complete_login(user, mfa=True)
                return redirect(url_for("auth.dashboard"))
            register_failure(user, "2fa_failed")
            flash("Invalid code.", "error")
    return render_template("login_2fa.html")


@bp.route("/logout", methods=["POST"])
def logout():
    user = current_user()
    if user:
        audit("logout", user)
    session.clear()
    return redirect(url_for("auth.login"))


# ------------------------------------------------------------------- 2FA setup
@bp.route("/2fa/setup", methods=["GET", "POST"])
@login_required
def setup_2fa():
    user = g.user
    if user["totp_enabled"]:
        return redirect(url_for("auth.security"))

    db = get_db()
    key = _cfg("TOTP_ENC_KEY")
    secret = sec.decrypt_secret(key, user["totp_pending_enc"]) if user["totp_pending_enc"] else None
    if secret is None:
        secret = sec.new_totp_secret()
        db.execute("UPDATE users SET totp_pending_enc=? WHERE id=?",
                   (sec.encrypt_secret(key, secret), user["id"]))
        db.commit()

    if request.method == "POST":
        if ip_rate_limited():
            abort(429, description="Too many attempts. Please wait a few minutes.")
        step = sec.verify_totp(secret, request.form.get("code", ""), 0, _cfg("TOTP_WINDOW"))
        if step is None:
            audit("2fa_enroll_bad_code", user)
            flash("That code is not valid. Check your phone's clock and try again.", "error")
        else:
            db.execute(
                "UPDATE users SET totp_enabled=1, totp_secret_enc=totp_pending_enc, "
                "totp_pending_enc=NULL, totp_last_step=? WHERE id=?", (step, user["id"]))
            db.commit()
            codes = _issue_backup_codes(user["id"])
            session["mfa"] = True
            audit("2fa_enabled", user)
            return render_template("backup_codes.html", codes=codes, first_time=True)

    uri = sec.provisioning_uri(secret, user["username"], _cfg("ISSUER"))
    return render_template("setup_2fa.html", secret=secret, qr=sec.qr_svg(uri))


# ------------------------------------------------------------- 2FA management
@bp.route("/2fa/security")
@login_required
def security():
    remaining = get_db().execute(
        "SELECT COUNT(*) FROM backup_codes WHERE user_id=? AND used_at IS NULL",
        (g.user["id"],)).fetchone()[0]
    return render_template("security.html", remaining=remaining, require=_cfg("REQUIRE_2FA"))


@bp.route("/2fa/backup-codes", methods=["POST"])
@login_required
def regenerate_backup_codes():
    user = g.user
    if not user["totp_enabled"]:
        return redirect(url_for("auth.setup_2fa"))
    if not reauthenticate(user, request.form.get("password", ""), request.form.get("code", "")):
        flash("Password or code incorrect.", "error")
        return redirect(url_for("auth.security"))
    codes = _issue_backup_codes(user["id"])
    audit("backup_codes_regenerated", user)
    return render_template("backup_codes.html", codes=codes, first_time=False)


@bp.route("/2fa/disable", methods=["POST"])
@login_required
def disable_2fa():
    user = g.user
    if _cfg("REQUIRE_2FA"):
        abort(400, description="2FA is mandatory and cannot be disabled.")
    if not reauthenticate(user, request.form.get("password", ""), request.form.get("code", "")):
        flash("Password or code incorrect.", "error")
        return redirect(url_for("auth.security"))
    db = get_db()
    db.execute("UPDATE users SET totp_enabled=0, totp_secret_enc=NULL, totp_pending_enc=NULL, "
               "totp_last_step=0 WHERE id=?", (user["id"],))
    db.execute("DELETE FROM backup_codes WHERE user_id=?", (user["id"],))
    db.commit()
    session["mfa"] = False
    audit("2fa_disabled", user)
    flash("Two-factor authentication disabled.", "info")
    return redirect(url_for("auth.security"))
