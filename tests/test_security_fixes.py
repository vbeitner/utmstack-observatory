"""Regression tests for the 1.16.0 security assessment fixes (docs/security/SECURITY-ASSESSMENT.md).
Each test names the finding it covers. Run: python3 -m unittest discover -s tests -v"""
import base64
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_hardening import ROOT, get, start_server  # noqa: E402

AUTH = "Basic " + base64.b64encode(b"admin:Right-Pass-1").decode()


def put_settings(port, body, auth=AUTH, host=None):
    h = {"Content-Type": "application/json", "X-Observatory": "1"}
    if auth:
        h["Authorization"] = auth
    if host:
        h["Host"] = host
    r = urllib.request.Request("http://127.0.0.1:%d/api/settings" % port, method="PUT",
                               data=json.dumps(body).encode(), headers=h)
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        b = e.read()
        try:
            return e.code, json.loads(b or b"{}")
        except ValueError:
            return e.code, {"text": b.decode("utf-8", "replace")}


def raw(port, data, wait=1.0):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(data)
    time.sleep(wait)
    out = b""
    try:
        while True:
            b = s.recv(65536)
            if not b:
                break
            out += b
    except socket.timeout:
        pass
    s.close()
    return out


class WithLogin(unittest.TestCase):
    def setUp(self):
        self.data = tempfile.mkdtemp()
        self.p, self.port = start_server(DATA_DIR=self.data, HEADER_DEADLINE_S="2")

    def tearDown(self):
        self.p.kill()
        self.p.wait()

    def test_obs05_sensitive_settings_need_the_current_password(self):
        code, j = put_settings(self.port, {"support": "Evil|x@attacker.example||https://attacker.example"})
        self.assertEqual(code, 403, j)
        code, j = put_settings(self.port, {"dash_pass": "a-whole-new-password"})
        self.assertEqual(code, 403, j)
        self.assertEqual(get(self.port, "/api/support")[0], 200)          # old password still works
        code, _ = put_settings(self.port, {"home": "45.42,-75.70,Ottawa"})  # harmless settings do not need it
        self.assertEqual(code, 200)

    def test_obs10_password_saved_from_settings_is_hashed(self):
        code, j = put_settings(self.port, {"dash_pass": "a-whole-new-password", "current_password": "Right-Pass-1"})
        self.assertEqual(code, 200, j)
        with open(os.path.join(self.data, "settings.json")) as f:
            stored = json.load(f)["dash_pass"]
        self.assertTrue(stored.startswith("pbkdf2_sha256$"), stored[:20])
        self.assertNotIn("a-whole-new-password", stored)
        self.assertEqual(get(self.port, "/api/support", pw="a-whole-new-password")[0], 200)
        self.assertEqual(get(self.port, "/api/support")[0], 401)

    def test_obs11_new_passwords_need_twelve_characters(self):
        code, j = put_settings(self.port, {"dash_pass": "short-pw-1", "current_password": "Right-Pass-1"})
        self.assertEqual(code, 400, j)

    def test_obs03_csp_has_no_inline_script_and_the_page_has_no_inline_script(self):
        code, headers, body = get(self.port, "/")
        csp = headers["Content-Security-Policy"]
        script_src = [d for d in csp.split(";") if d.strip().startswith("script-src")][0]
        self.assertNotIn("unsafe-inline", script_src)
        self.assertIn("object-src 'none'", csp)
        self.assertNotIn(b"<script>", body)
        self.assertEqual(get(self.port, "/app.js")[0], 200)

    def test_obs14_head_and_unknown_methods_carry_the_security_headers(self):
        out = raw(self.port, b"HEAD / HTTP/1.1\r\nHost: x\r\nAuthorization: " + AUTH.encode() + b"\r\nConnection: close\r\n\r\n")
        head, _, body = out.partition(b"\r\n\r\n")
        self.assertIn(b"200", head.split(b"\r\n")[0])
        self.assertIn(b"Content-Security-Policy", head)
        self.assertEqual(body, b"")
        out = raw(self.port, b"DELETE /api/settings HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        self.assertIn(b" 405 ", out.split(b"\r\n")[0])
        self.assertIn(b"X-Frame-Options: DENY", out)
        out = raw(self.port, b"GARBAGE\r\n\r\n")
        self.assertIn(b"X-Content-Type-Options: nosniff", out)
        for h in (b"Permissions-Policy", b"Cross-Origin-Opener-Policy", b"Cross-Origin-Resource-Policy"):
            self.assertIn(h, raw(self.port, b"GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))

    def test_obs02_slow_headers_are_cut_off_at_the_deadline(self):
        s = socket.create_connection(("127.0.0.1", self.port), timeout=10)
        s.sendall(b"GET /healthz HTTP/1.1\r\n")
        t0, closed = time.time(), False
        while time.time() - t0 < 8:
            try:
                s.sendall(b"X-Slow: 1\r\n")
            except OSError:
                closed = True
                break
            s.settimeout(1)
            try:
                if s.recv(1) == b"":
                    closed = True
                    break
            except socket.timeout:
                pass
        s.close()
        self.assertTrue(closed, "a client trickling headers was never disconnected")
        self.assertLess(time.time() - t0, 6)

    def test_obs12_ip_with_a_zone_id_is_refused(self):
        code, _, body = get(self.port, "/api/whois?ip=2606:4700::1%25z%3Ffoo%3Dbar")
        self.assertEqual(json.loads(body).get("error"), "not a valid IP address")
        code, _, body = get(self.port, "/api/reputation?ip=2606:4700::1%25x%26verbose")
        self.assertEqual(json.loads(body).get("error"), "not a valid IP address")

    def test_obs17_internal_errors_are_not_echoed(self):
        code, _, body = get(self.port, "/api/alerts?size=abc")
        err = json.loads(body).get("error", "")
        self.assertNotIn("invalid literal", err)
        self.assertIn("ref ", err)


class WithoutLogin(unittest.TestCase):
    def setUp(self):
        self.p, self.port = start_server(DASH_PASS="")

    def tearDown(self):
        self.p.kill()
        self.p.wait()

    def test_obs07_dns_rebinding_host_is_refused(self):
        code, _ = put_settings(self.port, {"support": "Evil|x@attacker.example"}, auth=None,
                               host="rebind.attacker.example:%d" % self.port)
        self.assertEqual(code, 403)
        self.assertEqual(get(self.port, "/api/support", user=None)[0], 200)   # Host 127.0.0.1 is fine


class ConnectionCaps(unittest.TestCase):
    def test_obs02_one_address_cannot_take_every_connection(self):
        p, port = start_server(MAX_CONNECTIONS_PER_IP="3", HEADER_DEADLINE_S="30", REQUEST_TIMEOUT_S="30")
        try:
            held = [socket.create_connection(("127.0.0.1", port)) for _ in range(3)]
            for s in held:
                s.sendall(b"GET / HTTP/1.1\r\n")
            time.sleep(0.3)
            s4 = socket.create_connection(("127.0.0.1", port), timeout=3)
            s4.sendall(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
            try:
                got = s4.recv(100)
            except ConnectionResetError:
                got = b""
            self.assertEqual(got, b"", "fourth connection from the same address should be closed")
            for s in held:
                s.close()
            time.sleep(0.5)
            self.assertEqual(get(port, "/healthz")[0], 200)                    # slots come back
        finally:
            p.kill()
            p.wait()


class InstallerHelpers(unittest.TestCase):
    def test_obs06_installer_can_clear_a_password_saved_in_settings(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "settings.json"), "w") as f:
            json.dump({"dash_pass": "pbkdf2_sha256$1$00$00", "home": "1,2"}, f)
        out = subprocess.run([sys.executable, "-I", os.path.join(ROOT, "app", "settings_store.py"), d,
                              "--clear", "dash_pass"], capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)
        with open(os.path.join(d, "settings.json")) as f:
            self.assertEqual(json.load(f), {"home": "1,2"})


if __name__ == "__main__":
    unittest.main()
