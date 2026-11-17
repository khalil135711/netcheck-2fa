"""Tiny SQLite layer (standard library only)."""
import sqlite3
import time
from pathlib import Path

from flask import g, current_app, request

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    username         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash    TEXT NOT NULL,
    totp_enabled     INTEGER NOT NULL DEFAULT 0,
    totp_secret_enc  TEXT,            -- Fernet-encrypted base32 secret (active)
    totp_pending_enc TEXT,            -- secret generated during enrollment, not yet confirmed
    totp_last_step   INTEGER NOT NULL DEFAULT 0,   -- replay protection
    failed_attempts  INTEGER NOT NULL DEFAULT 0,
    locked_until     INTEGER NOT NULL DEFAULT 0,
    created_at       INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS backup_codes (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,          -- HMAC-SHA256(pepper, code); the code itself is never stored
    used_at   INTEGER
);
CREATE INDEX IF NOT EXISTS idx_backup_user ON backup_codes(user_id, code_hash);

CREATE TABLE IF NOT EXISTS audit_log (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       INTEGER NOT NULL,
    user_id  INTEGER,
    username TEXT,
    event    TEXT NOT NULL,
    ip       TEXT
);
"""


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_exc=None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(app) -> None:
    path = Path(app.config["DATABASE"])
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    con.executescript(SCHEMA)
    con.commit()
    con.close()


def audit(event: str, user=None, username: str | None = None) -> None:
    """Append-only security log (ISO 27001:2022 A.8.15)."""
    db = get_db()
    ip = request.remote_addr if request else None
    uid = user["id"] if user is not None else None
    name = user["username"] if user is not None else username
    db.execute(
        "INSERT INTO audit_log (ts, user_id, username, event, ip) VALUES (?,?,?,?,?)",
        (int(time.time()), uid, name, event, ip),
    )
    db.commit()
