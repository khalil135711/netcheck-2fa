"""ISO 27001 Netcheck - authentication package (password + TOTP 2FA)."""
import hmac
import secrets
from collections import defaultdict, deque

from cryptography.fernet import Fernet
from flask import Flask, abort, render_template, request, session

from . import db
from .config import Config

REQUIRED_SECRETS = ("SECRET_KEY", "TOTP_ENC_KEY", "BACKUP_PEPPER")


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=False)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)

    # Fail closed: never start with missing or malformed secrets.
    missing = [k for k in REQUIRED_SECRETS if not app.config.get(k)]
    if missing:
        raise RuntimeError(
            f"Missing secrets: {', '.join(missing)}. Run `python manage.py gen-keys` "
            "and export the printed NETCHECK_* variables."
        )
    try:
        Fernet(app.config["TOTP_ENC_KEY"].encode("ascii"))
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError("NETCHECK_TOTP_KEY is not a valid Fernet key.") from exc

    app.extensions["ip_hits"] = defaultdict(deque)
    db.init_db(app)
    app.teardown_appcontext(db.close_db)

    from .routes import bp
    app.register_blueprint(bp)

    # ----------------------------------------------------------------- CSRF
    def csrf_token() -> str:
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        return session["csrf"]

    app.jinja_env.globals["csrf_token"] = csrf_token

    @app.before_request
    def check_csrf():
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            sent = request.form.get("csrf_token", "")
            expected = session.get("csrf", "")
            if not expected or not hmac.compare_digest(sent, expected):
                abort(400, description="Invalid or missing CSRF token.")

    # -------------------------------------------------------- security headers
    @app.after_request
    def security_headers(resp):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self'; "
            "script-src 'none'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'"
        )
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        if app.config["SESSION_COOKIE_SECURE"]:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return resp

    @app.errorhandler(400)
    @app.errorhandler(429)
    def simple_error(err):
        return render_template("error.html", err=err), err.code

    return app
