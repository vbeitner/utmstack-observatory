# Copyright (c) 2026 Victor Beitner. All rights reserved. See LICENSE.
"""Invited users, email sign-in links, sessions and roles; tested against the real server and a fake SMTP server.
Run: python3 -m unittest discover -s tests -v"""
import json
import os
import re
import socket
import socketserver
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_hardening import start_server, get  # noqa: E402
import users_store  # noqa: E402
import mailer  # noqa: E402


class FakeSMTP(socketserver.ThreadingTCPServer):
    """Just enough SMTP for smtplib without TLS or login; keeps every message it is given."""
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self):
        self.messages = []
        super().__init__(("127.0.0.1", 0), _SMTPHandler)
        threading.Thread(target=self.serve_forever, daemon=True).start()

    def wait(self, n, timeout=10):
        end = time.time() + timeout
        while len(self.messages) < n and time.time() < end:
            time.sleep(0.05)
        return self.messages


class _SMTPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        w = lambda s: self.wfile.write(s.encode() + b"\r\n")
        w("220 fake")
        rcpt = []
        while True:
            line = self.rfile.readline().decode(errors="replace").strip()
            cmd = line[:4].upper()
            if not line or cmd == "QUIT":
                w("221 bye")
                return
            if cmd == "EHLO":
                w("250-fake")
                w("250 8BITMIME")
            elif cmd == "RCPT":
                rcpt.append(line.split(":", 1)[1].strip(" <>"))
                w("250 ok")
            elif cmd == "DATA":
                w("354 go")
                body = []
                while True:
                    l = self.rfile.readline()
                    if l in (b".\r\n", b".\n", b""):
                        break
                    body.append(l.decode(errors="replace"))
                self.server.messages.append({"to": rcpt, "body": "".join(body)})
                rcpt = []
                w("250 queued")
            else:
                w("250 ok")


def req(port, method, path, body=None, cookie=None, auth=None, origin=True):
    r = urllib.request.Request("http://127.0.0.1:%d%s" % (port, path), method=method,
                               data=json.dumps(body).encode() if body is not None else None)
    if body is not None:
        r.add_header("Content-Type", "application/json")
        r.add_header("X-Observatory", "1")
    if cookie:
        r.add_header("Cookie", "obs_session=" + cookie)
    if auth:
        import base64
        r.add_header("Authorization", "Basic " + base64.b64encode(auth.encode()).decode())

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    try:
        with urllib.request.build_opener(NoRedirect).open(r, timeout=15) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def cookie_of(headers):
    m = re.search(r"obs_session=([^;]*)", headers.get("Set-Cookie", ""))
    return m.group(1) if m else None


ADMIN = "admin:Right-Pass-1"


class Store(unittest.TestCase):
    def setUp(self):
        users_store.reset_cache()
        self.d = tempfile.mkdtemp()

    def test_users_roles_and_removal_end_sessions(self):
        users_store.set_user(self.d, "Ann@Example.com", "viewer")
        self.assertEqual(users_store.get_user(self.d, "ann@example.com")["role"], "viewer")
        tok = users_store.new_session(self.d, "ann@example.com", "link", 1)
        self.assertEqual(users_store.get_session(self.d, tok)["role"], "viewer")
        users_store.set_user(self.d, "ann@example.com", "admin")
        self.assertEqual(users_store.get_session(self.d, tok)["role"], "admin")      # role is read live
        users_store.remove_user(self.d, "ann@example.com")
        self.assertIsNone(users_store.get_session(self.d, tok))

    def test_tokens_are_not_stored(self):
        users_store.set_user(self.d, "ann@example.com", "viewer")
        tok = users_store.new_session(self.d, "ann@example.com", "link", 1)
        with open(os.path.join(self.d, users_store.FILE)) as f:
            raw = f.read()
        self.assertNotIn(tok, raw)
        self.assertEqual(os.stat(os.path.join(self.d, users_store.FILE)).st_mode & 0o777, 0o600)

    def test_link_works_once_and_expires(self):
        users_store.set_user(self.d, "ann@example.com", "viewer")
        t = users_store.new_link("ann@example.com", 15)
        self.assertEqual(users_store.use_link(self.d, t)["email"], "ann@example.com")
        self.assertIsNone(users_store.use_link(self.d, t))
        t = users_store.new_link("ann@example.com", -1)
        self.assertIsNone(users_store.use_link(self.d, t))

    def test_password_session_ends_with_password_change(self):
        tok = users_store.new_session(self.d, None, "password", 1, cred_tag="aaa")
        self.assertEqual(users_store.get_session(self.d, tok, "aaa")["role"], "admin")
        self.assertIsNone(users_store.get_session(self.d, tok, "bbb"))

    def test_expired_session(self):
        users_store.set_user(self.d, "ann@example.com", "viewer")
        tok = users_store.new_session(self.d, "ann@example.com", "link", -1)
        self.assertIsNone(users_store.get_session(self.d, tok))

    def test_bad_emails(self):
        for bad in ("", "x", "a@b", "a b@c.com", "a@b.com\nBcc: x@y.com", "<a@b.com>", None, 5):
            with self.assertRaises(ValueError):
                users_store.norm_email(bad)

    def test_mailer_configured(self):
        self.assertTrue(mailer.configured({"method": ""}))
        self.assertTrue(mailer.configured({"method": "smtp", "from": "a@b.com"}))
        self.assertIsNone(mailer.configured({"method": "smtp", "from": "a@b.com", "smtp_host": "h"}))
        self.assertIn("client secret", mailer.configured({"method": "graph", "from": "a@b.com", "graph_tenant": "t",
                                                          "graph_client_id": "c"}))


class Graph(unittest.TestCase):
    def test_token_then_sendmail(self):
        calls = []

        def fake(url, data, headers):
            calls.append((url, data, headers))
            return 200, ({"access_token": "tok", "expires_in": 3600} if "oauth2" in url else {})
        cfg = {"method": "graph", "from": "alerts@contoso.com", "graph_tenant": "contoso.onmicrosoft.com",
               "graph_client_id": "cid", "graph_secret": "sec"}
        real, mailer._http = mailer._http, fake
        try:
            mailer.send(cfg, "ann@example.com", "Hi", "text", "<p>html</p>")
            mailer.send(cfg, "bob@example.com", "Hi", "text")
        finally:
            mailer._http = real
            mailer._token.update(key=None, value=None, until=0)
        self.assertEqual(len(calls), 3)                          # the token is fetched once and reused
        self.assertEqual(calls[0][0], "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token")
        self.assertIn(b"client_credentials", calls[0][1])
        self.assertEqual(calls[1][0], "https://graph.microsoft.com/v1.0/users/alerts@contoso.com/sendMail")
        self.assertEqual(calls[1][2]["Authorization"], "Bearer tok")
        msg = json.loads(calls[1][1])["message"]
        self.assertEqual(msg["toRecipients"], [{"emailAddress": {"address": "ann@example.com"}}])
        self.assertEqual(msg["body"]["contentType"], "HTML")


class Flow(unittest.TestCase):
    def setUp(self):
        self.smtp = FakeSMTP()
        self.p, self.port = start_server(ADMIN_EMAIL="boss@example.com")
        mail = {"public_url": "https://observatory.example.com", "mail_method": "smtp", "mail_from": "obs@example.com",
                "smtp_host": "127.0.0.1", "smtp_port": str(self.smtp.server_address[1]), "smtp_security": "none",
                "current_password": "Right-Pass-1"}
        self.assertEqual(req(self.port, "PUT", "/api/settings", mail, auth=ADMIN)[0], 200)

    def tearDown(self):
        self.p.kill()
        self.p.wait()
        self.smtp.shutdown()
        self.smtp.server_close()

    def sign_in(self, email, n):
        self.assertEqual(req(self.port, "POST", "/auth/request", {"email": email})[0], 200)
        msg = self.smtp.wait(n)[n - 1]
        self.assertEqual(msg["to"], [email])
        body = msg["body"].replace("=\r\n", "").replace("=\n", "").replace("=3D", "=")
        token = re.search(r"https://observatory\.example\.com/login#t=([A-Za-z0-9_-]+)", body).group(1)
        code, h, _ = req(self.port, "POST", "/auth/verify", {"token": token})
        self.assertEqual(code, 200)
        self.assertIn("HttpOnly", h["Set-Cookie"])
        self.assertIn("SameSite=Strict", h["Set-Cookie"])
        return cookie_of(h), token

    def test_status_and_pages_are_public(self):
        st = json.loads(req(self.port, "GET", "/auth/status")[2])
        self.assertEqual(st, {"link": True, "password": True, "login": True})
        self.assertEqual(req(self.port, "GET", "/login")[0], 200)
        code, h, _ = req(self.port, "GET", "/")
        self.assertEqual((code, h.get("Location")), (302, "/login"))
        code, h, _ = req(self.port, "GET", "/api/data")
        self.assertEqual(code, 401)
        self.assertNotIn("WWW-Authenticate", h)               # no browser password pop-up over the sign-in page

    def test_seeded_admin_signs_in_and_manages_a_viewer(self):
        boss, token = self.sign_in("boss@example.com", 1)
        self.assertEqual(req(self.port, "POST", "/auth/verify", {"token": token})[0], 403)   # used once
        me = json.loads(req(self.port, "GET", "/api/me", cookie=boss)[2])
        self.assertEqual((me["email"], me["role"], me["method"]), ("boss@example.com", "admin", "link"))
        code, _, body = req(self.port, "POST", "/api/users", {"action": "add", "email": "Viewer@Example.com",
                                                             "role": "viewer", "invite": True}, cookie=boss)
        self.assertEqual(code, 200, body)
        self.assertIn("viewer@example.com", [u["email"] for u in json.loads(body)["users"]])
        invite = self.smtp.wait(2)[1]
        self.assertEqual(invite["to"], ["viewer@example.com"])

        viewer, _ = self.sign_in("viewer@example.com", 3)
        self.assertEqual(req(self.port, "GET", "/api/support", cookie=viewer)[0], 200)
        self.assertEqual(req(self.port, "GET", "/api/settings", cookie=viewer)[0], 403)
        self.assertEqual(req(self.port, "GET", "/api/users", cookie=viewer)[0], 403)
        self.assertEqual(req(self.port, "PUT", "/api/settings", {"home": "1,2"}, cookie=viewer)[0], 403)
        self.assertEqual(req(self.port, "POST", "/api/users", {"action": "add", "email": "x@example.com"}, cookie=viewer)[0], 403)
        self.assertEqual(req(self.port, "POST", "/api/cluster/fix", {}, cookie=viewer)[0], 403)

        # removal signs them out at once
        self.assertEqual(req(self.port, "POST", "/api/users", {"action": "remove", "email": "viewer@example.com"}, cookie=boss)[0], 200)
        self.assertEqual(req(self.port, "GET", "/api/support", cookie=viewer)[0], 401)

    def test_admin_cannot_remove_or_demote_self(self):
        boss, _ = self.sign_in("boss@example.com", 1)
        for body in ({"action": "remove", "email": "boss@example.com"},
                     {"action": "add", "email": "boss@example.com", "role": "viewer"}):
            self.assertEqual(req(self.port, "POST", "/api/users", body, cookie=boss)[0], 400)

    def test_unknown_address_gets_the_same_answer_and_no_email(self):
        code, _, body = req(self.port, "POST", "/auth/request", {"email": "stranger@example.com"})
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body)["ok"], True)
        time.sleep(1)
        self.assertEqual(self.smtp.messages, [])

    def test_link_requests_are_rate_limited(self):
        for _ in range(5):
            req(self.port, "POST", "/auth/request", {"email": "boss@example.com"})
        time.sleep(1.5)
        self.assertEqual(len(self.smtp.messages), 3)            # LINK_PER_EMAIL

    def test_wrong_tokens_lock_the_address(self):
        codes = [req(self.port, "POST", "/auth/verify", {"token": "x" * 43})[0] for _ in range(7)]
        self.assertEqual(codes[:5], [403] * 5)
        self.assertEqual(codes[-1], 429)

    def test_logout_ends_the_session(self):
        boss, _ = self.sign_in("boss@example.com", 1)
        code, h, _ = req(self.port, "POST", "/auth/logout", {}, cookie=boss)
        self.assertEqual(code, 200)
        self.assertIn("Max-Age=0", h["Set-Cookie"])
        self.assertEqual(req(self.port, "GET", "/api/me", cookie=boss)[0], 401)

    def test_password_sign_in_is_break_glass_admin(self):
        self.assertEqual(req(self.port, "POST", "/auth/password", {"user": "admin", "password": "nope"})[0], 403)
        code, h, _ = req(self.port, "POST", "/auth/password", {"user": "admin", "password": "Right-Pass-1"})
        self.assertEqual(code, 200)
        sess = cookie_of(h)
        me = json.loads(req(self.port, "GET", "/api/me", cookie=sess)[2])
        self.assertEqual((me["role"], me["method"]), ("admin", "password"))
        # user changes from a password session need the password again
        self.assertEqual(req(self.port, "POST", "/api/users", {"action": "add", "email": "a@example.com"}, cookie=sess)[0], 403)
        self.assertEqual(req(self.port, "POST", "/api/users", {"action": "add", "email": "a@example.com",
                                                              "current_password": "Right-Pass-1"}, cookie=sess)[0], 200)
        # a new password ends sessions opened with the old one
        self.assertEqual(req(self.port, "PUT", "/api/settings", {"dash_pass": "Another-Pass-22", "current_password": "Right-Pass-1"},
                             cookie=sess)[0], 200)
        self.assertEqual(req(self.port, "GET", "/api/me", cookie=sess)[0], 401)

    def test_basic_auth_still_works_for_scripts(self):
        self.assertEqual(get(self.port, "/api/support")[0], 200)

    def test_mail_settings_need_confirmation_and_validation(self):
        self.assertEqual(req(self.port, "PUT", "/api/settings", {"public_url": "https://evil.example.com"}, auth=ADMIN)[0], 403)
        for bad in ({"public_url": "https://x.example.com/path"}, {"public_url": "javascript:alert(1)"},
                    {"mail_method": "fax"}, {"smtp_port": "99999"}, {"mail_from": "a@b.com, c@d.com"}):
            bad["current_password"] = "Right-Pass-1"
            self.assertEqual(req(self.port, "PUT", "/api/settings", bad, auth=ADMIN)[0], 400, bad)
        # re-sending unchanged values needs no password (the Save button sends the whole form)
        self.assertEqual(req(self.port, "PUT", "/api/settings", {"public_url": "https://observatory.example.com",
                                                                 "mail_method": "smtp"}, auth=ADMIN)[0], 200)
        s = json.loads(req(self.port, "GET", "/api/settings", auth=ADMIN)[2])
        self.assertEqual(s["mail_status"], "")
        self.assertNotIn("smtp_pass", s)

    def test_test_email(self):
        boss, _ = self.sign_in("boss@example.com", 1)
        code, _, body = req(self.port, "POST", "/api/mail/test", {}, cookie=boss)
        self.assertEqual(json.loads(body), {"ok": True, "to": "boss@example.com"})
        self.assertEqual(self.smtp.wait(2)[1]["to"], ["boss@example.com"])

    def test_cookie_writes_still_need_csrf_header(self):
        boss, _ = self.sign_in("boss@example.com", 1)
        r = urllib.request.Request("http://127.0.0.1:%d/api/users" % self.port, method="POST",
                                   data=b'{"action":"add","email":"x@example.com"}',
                                   headers={"Content-Type": "application/json", "Cookie": "obs_session=" + boss})
        with self.assertRaises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(r, timeout=10)
        self.assertEqual(e.exception.code, 403)


class StaleSession(unittest.TestCase):
    def test_sensitive_change_needs_a_recent_sign_in(self):
        smtp = FakeSMTP()
        p, port = start_server(ADMIN_EMAIL="boss@example.com", REAUTH_MINUTES="0")
        try:
            mail = {"public_url": "https://o.example.com", "mail_method": "smtp", "mail_from": "obs@example.com",
                    "smtp_host": "127.0.0.1", "smtp_port": str(smtp.server_address[1]), "smtp_security": "none",
                    "current_password": "Right-Pass-1"}
            req(port, "PUT", "/api/settings", mail, auth=ADMIN)
            req(port, "POST", "/auth/request", {"email": "boss@example.com"})
            body = smtp.wait(1)[0]["body"].replace("=\r\n", "").replace("=3D", "=")
            token = re.search(r"/login#t=([A-Za-z0-9_-]+)", body).group(1)
            boss = cookie_of(req(port, "POST", "/auth/verify", {"token": token})[1])
            time.sleep(1.1)
            code, _, body = req(port, "POST", "/api/users", {"action": "add", "email": "x@example.com"}, cookie=boss)
            self.assertEqual(code, 403)
            self.assertTrue(json.loads(body)["reauth"])
            self.assertEqual(req(port, "GET", "/api/support", cookie=boss)[0], 200)   # reading is fine
        finally:
            p.kill()
            p.wait()
            smtp.shutdown()
            smtp.server_close()


if __name__ == "__main__":
    unittest.main()
