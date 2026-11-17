#!/usr/bin/env python3
"""Command line helper.

    python manage.py gen-keys              print fresh secrets (export them!)
    python manage.py create-user NAME      create a user (password is prompted)
    python manage.py audit [N]             show the last N audit-log entries
"""
import getpass
import sqlite3
import sys
import time

from cryptography.fernet import Fernet


def gen_keys() -> None:
    import secrets
    print(f"export NETCHECK_SECRET_KEY='{secrets.token_urlsafe(48)}'")
    print(f"export NETCHECK_TOTP_KEY='{Fernet.generate_key().decode()}'")
    print(f"export NETCHECK_PEPPER='{secrets.token_urlsafe(32)}'")
    print("\n# Keep these outside the repository. Losing NETCHECK_TOTP_KEY locks all users "
          "out of 2FA; changing NETCHECK_PEPPER invalidates all backup codes.", file=sys.stderr)


def create_user(username: str) -> None:
    from netcheck_auth import create_app
    from netcheck_auth import security as sec
    app = create_app()
    password = getpass.getpass("Password: ")
    if password != getpass.getpass("Repeat password: "):
        sys.exit("Passwords do not match.")
    error = sec.validate_password(password, username, app.config["MIN_PASSWORD_LENGTH"])
    if error:
        sys.exit(error)
    con = sqlite3.connect(app.config["DATABASE"])
    try:
        con.execute("INSERT INTO users (username, password_hash, created_at) VALUES (?,?,?)",
                    (username, sec.hash_password(password), int(time.time())))
        con.commit()
    except sqlite3.IntegrityError:
        sys.exit("That username already exists.")
    finally:
        con.close()
    print(f"User '{username}' created. 2FA enrollment happens at first login.")


def show_audit(limit: int) -> None:
    from netcheck_auth import create_app
    app = create_app()
    con = sqlite3.connect(app.config["DATABASE"])
    for ts, user, event, ip in con.execute(
            "SELECT ts, username, event, ip FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)):
        print(f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))}  "
              f"{(user or '-'):<16} {event:<24} {ip or '-'}")
    con.close()


if __name__ == "__main__":
    args = sys.argv[1:]
    if args[:1] == ["gen-keys"]:
        gen_keys()
    elif args[:1] == ["create-user"] and len(args) == 2:
        create_user(args[1])
    elif args[:1] == ["audit"]:
        show_audit(int(args[1]) if len(args) > 1 else 30)
    else:
        print(__doc__)
