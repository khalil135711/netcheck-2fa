import os
import re
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.fernet import Fernet  # noqa: E402

from netcheck_auth import create_app  # noqa: E402
from netcheck_auth import security as sec  # noqa: E402

PASSWORD = "correct-horse-battery-staple"


class TotpVectors(unittest.TestCase):
    """RFC 6238 Appendix B (SHA-1 secret '12345678901234567890'); 6-digit = last 6 of the 8-digit value."""
    SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

    def test_rfc6238_vectors(self):
        for ts, expected in [(59, "287082"), (1111111109, "081804"),
                             (1111111111, "050471"), (1234567890, "005924"),
                             (2000000000, "279037")]:
            self.assertEqual(sec.totp_at(self.SECRET, ts), expected)

    def test_replay_and_window(self):
        code = sec.totp_at(self.SECRET, 1000)
        step = sec.verify_totp(self.SECRET, code, 0, 1, now=1000)
        self.assertEqual(step, 1000 // 30)
        self.assertIsNone(sec.verify_totp(self.SECRET, code, step, 1, now=1000))   # replay
        self.assertIsNone(sec.verify_totp(self.SECRET, code, 0, 1, now=1000 + 300))  # too old
        self.assertIsNotNone(sec.verify_totp(self.SECRET, " ".join([code[:3], code[3:]]), 0, 1, now=1000))

    def test_backup_code_format(self):
        codes = sec.generate_backup_codes(10)
        self.assertEqual(len(set(codes)), 10)
        for c in codes:
            self.assertRegex(c, r"^[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}$")
            self.assertEqual(len(sec.normalize_backup_code(c)), 12)


class AppTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.app = create_app({
            "TESTING": True,
            "DATABASE": self.tmp.name,
            "SECRET_KEY": "test-secret",
            "TOTP_ENC_KEY": Fernet.generate_key().decode(),
            "BACKUP_PEPPER": "test-pepper",
            "SESSION_COOKIE_SECURE": False,
            "IP_LIMIT": 1000,
        })
        self.client = self.app.test_client()
        con = __import__("sqlite3").connect(self.tmp.name)
        con.execute("INSERT INTO users (username, password_hash, created_at) VALUES (?,?,?)",
                    ("alice", sec.hash_password(PASSWORD), int(time.time())))
        con.commit()
        con.close()

    def tearDown(self):
        os.unlink(self.tmp.name)

    # -- helpers
    def token(self, path="/login"):
        html = self.client.get(path).get_data(as_text=True)
        return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)

    def post(self, path, data, form_page=None):
        data = dict(data)
        data["csrf_token"] = self.token(form_page or path)
        return self.client.post(path, data=data)

    def password_login(self, password=PASSWORD):
        return self.post("/login", {"username": "alice", "password": password})

    def enroll(self):
        """Log in, enroll TOTP, return (secret, backup_codes)."""
        self.password_login()
        page = self.client.get("/2fa/setup").get_data(as_text=True)
        secret = re.search(r'class="secret">([A-Z2-7]+)<', page).group(1)
        resp = self.post("/2fa/setup", {"code": sec.totp_at(secret, time.time())})
        html = resp.get_data(as_text=True)
        codes = re.findall(r"<code>([0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4})</code>", html)
        self.assertEqual(len(codes), 10)
        self.client.post("/logout", data={"csrf_token": self.token("/2fa/security")})
        return secret, codes

    def fresh_client(self):
        self.client = self.app.test_client()

    def db_row(self, sql, *args):
        con = __import__("sqlite3").connect(self.tmp.name)
        row = con.execute(sql, args).fetchone()
        con.close()
        return row


class FlowTests(AppTestCase):
    def test_csrf_required(self):
        self.assertEqual(self.client.post("/login", data={"username": "a", "password": "b"}).status_code, 400)

    def test_dashboard_requires_login(self):
        self.assertEqual(self.client.get("/").status_code, 302)

    def test_enrollment_is_forced_then_login_needs_second_factor(self):
        self.password_login()
        r = self.client.get("/")
        self.assertIn("/2fa/setup", r.headers["Location"])           # mandatory 2FA
        self.fresh_client()
        secret, _ = self.enroll()

        self.fresh_client()
        r = self.password_login()
        self.assertIn("/login/2fa", r.headers["Location"])
        self.assertEqual(self.client.get("/").status_code, 302)       # password alone is not enough
        code = sec.totp_at(secret, time.time() + 30)                   # next step (enrollment burned the current one)
        r = self.post("/login/2fa", {"code": code})
        self.assertEqual(r.headers["Location"], "/")
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_totp_replay_rejected(self):
        secret, _ = self.enroll()
        code = sec.totp_at(secret, time.time() + 30)
        self.fresh_client(); self.password_login()
        self.assertEqual(self.post("/login/2fa", {"code": code}).headers["Location"], "/")
        self.fresh_client(); self.password_login()
        r = self.post("/login/2fa", {"code": code})                    # same code again
        self.assertEqual(r.status_code, 200)
        self.assertIn("Invalid code", r.get_data(as_text=True))

    def test_backup_code_works_once(self):
        _, codes = self.enroll()
        self.fresh_client(); self.password_login()
        self.assertEqual(self.post("/login/2fa", {"code": codes[0]}).headers["Location"], "/")
        self.fresh_client(); self.password_login()
        r = self.post("/login/2fa", {"code": codes[0]})
        self.assertIn("Invalid code", r.get_data(as_text=True))
        self.assertEqual(self.db_row("SELECT COUNT(*) FROM backup_codes WHERE used_at IS NULL")[0], 9)

    def test_lockout_after_repeated_failures(self):
        self.enroll()
        for _ in range(5):
            self.fresh_client(); self.password_login()
            self.post("/login/2fa", {"code": "000000"})
        self.fresh_client()
        r = self.password_login()                                      # correct password, but locked
        self.assertEqual(r.status_code, 200)
        self.assertIn("temporarily locked", r.get_data(as_text=True))
        self.assertIsNotNone(self.db_row("SELECT 1 FROM audit_log WHERE event='account_locked'"))

    def test_wrong_password_and_unknown_user_look_identical(self):
        a = self.password_login("wrong-password-123").get_data(as_text=True)
        self.fresh_client()
        b = self.post("/login", {"username": "nobody", "password": "wrong-password-123"}).get_data(as_text=True)
        strip = lambda s: re.sub(r'name="csrf_token" value="[^"]+"', "", s)
        self.assertEqual(strip(a), strip(b))

    def test_secret_encrypted_at_rest(self):
        secret, _ = self.enroll()
        stored = self.db_row("SELECT totp_secret_enc FROM users WHERE username='alice'")[0]
        self.assertNotIn(secret, stored)
        con = __import__("sqlite3").connect(self.tmp.name)
        hashes = con.execute("SELECT code_hash FROM backup_codes").fetchall()
        con.close()
        self.assertEqual(len(hashes), 10)
        self.assertTrue(all(len(h[0]) == 64 for h in hashes))

    def test_pending_2fa_expires(self):
        self.enroll()
        self.fresh_client(); self.password_login()
        with self.client.session_transaction() as s:
            s["pending_exp"] = time.time() - 1
        r = self.client.get("/login/2fa")
        self.assertIn("/login", r.headers["Location"])

    def test_disabling_blocked_when_mandatory(self):
        secret, _ = self.enroll()
        self.fresh_client(); self.password_login()
        self.post("/login/2fa", {"code": sec.totp_at(secret, time.time() + 30)})
        r = self.post("/2fa/disable", {"password": PASSWORD, "code": "123456"}, form_page="/2fa/security")
        self.assertEqual(r.status_code, 400)

    def test_regenerate_backup_codes_invalidates_old(self):
        secret, old = self.enroll()
        self.fresh_client(); self.password_login()
        self.post("/login/2fa", {"code": sec.totp_at(secret, time.time() + 30)})
        # Simulate 30+ s passing: the login code's step must not block a fresh, newer code.
        con = __import__("sqlite3").connect(self.tmp.name)
        con.execute("UPDATE users SET totp_last_step = totp_last_step - 2")
        con.commit(); con.close()
        r = self.post("/2fa/backup-codes",
                      {"password": PASSWORD, "code": sec.totp_at(secret, time.time())},
                      form_page="/2fa/security")
        new = re.findall(r"<code>([0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4})</code>", r.get_data(as_text=True))
        self.assertEqual(len(new), 10)
        self.assertFalse(set(new) & set(old))
        self.fresh_client(); self.password_login()
        self.assertIn("Invalid code", self.post("/login/2fa", {"code": old[1]}).get_data(as_text=True))

    def test_security_headers(self):
        h = self.client.get("/login").headers
        self.assertIn("frame-ancestors 'none'", h["Content-Security-Policy"])
        self.assertEqual(h["X-Content-Type-Options"], "nosniff")


class ConfigTests(unittest.TestCase):
    def test_refuses_to_start_without_secrets(self):
        with self.assertRaises(RuntimeError):
            create_app({"SECRET_KEY": None, "TOTP_ENC_KEY": None, "BACKUP_PEPPER": None})


if __name__ == "__main__":
    unittest.main()
