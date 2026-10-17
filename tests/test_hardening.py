"""Security hardening of the HTTP server, tested against the real server started like the container (python3 -I).
Run: python3 -m unittest discover -s tests -v"""
import base64
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def start_server(**extra):
    port = free_port()
    env = {"PATH": os.environ.get("PATH", ""), "OS_URL": "http://127.0.0.1:9", "DATA_DIR": tempfile.mkdtemp(),
           "BIND": "127.0.0.1", "PORT": str(port), "DASH_USER": "admin", "DASH_PASS": "Right-Pass-1"}
    env.update(extra)
    p = subprocess.Popen([sys.executable, "-I", os.path.join(ROOT, "app", "server.py")], env=env,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return p, port
        except OSError:
            time.sleep(0.05)
    p.kill()
    raise RuntimeError("server did not start")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def get(port, path, user="admin", pw="Right-Pass-1"):
    r = urllib.request.Request("http://127.0.0.1:%d%s" % (port, path))
    if user is not None:
        r.add_header("Authorization", "Basic " + base64.b64encode(("%s:%s" % (user, pw)).encode()).decode())
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


class Hardening(unittest.TestCase):
    def setUp(self):
        self.p, self.port = start_server(REQUEST_TIMEOUT_S="2")

    def tearDown(self):
        self.p.kill()
        self.p.wait()

    def test_idle_half_open_connection_is_closed_by_the_server(self):
        s = socket.create_connection(("127.0.0.1", self.port))
        s.sendall(b"GET /healthz HTTP/1.1\r\nHost: x\r\n")      # never finishes the request
        s.settimeout(6)
        t = time.time()
        try:
            data = s.recv(100)
        except socket.timeout:
            data = None
        s.close()
        self.assertIsNotNone(data, "server kept the half-open connection for 6 s")
        self.assertLess(time.time() - t, 5)

    def test_server_header_does_not_reveal_python_version(self):
        _, h, _ = get(self.port, "/healthz", user=None)
        self.assertNotIn("Python", h.get("Server", ""))
        self.assertNotIn("BaseHTTP", h.get("Server", ""))



class LoginLockout(unittest.TestCase):
    def setUp(self):
        self.p, self.port = start_server(LOGIN_MAX_FAILURES="5", LOGIN_LOCK_S="3")

    def tearDown(self):
        self.p.kill()
        self.p.wait()

    def test_ip_is_locked_after_repeated_failures_even_with_the_right_password(self):
        for _ in range(5):
            self.assertEqual(get(self.port, "/api/support", pw="wrong")[0], 401)
        st, h, body = get(self.port, "/api/support")              # right password, but locked
        self.assertEqual(st, 429)
        self.assertTrue(int(h.get("Retry-After", "0")) > 0)
        time.sleep(3.2)
        self.assertEqual(get(self.port, "/api/support")[0], 200)   # lock expires

    def test_parallel_guessing_is_capped(self):
        import threading
        codes = []
        ths = [threading.Thread(target=lambda: codes.append(get(self.port, "/api/support", pw="guess")[0])) for _ in range(30)]
        [t.start() for t in ths]
        [t.join() for t in ths]
        self.assertLessEqual(codes.count(401), 5, codes)            # at most LOGIN_MAX_FAILURES real password checks
        self.assertGreaterEqual(codes.count(429), 25)

    def test_parallel_correct_logins_are_never_refused(self):
        import threading
        codes = []
        ths = [threading.Thread(target=lambda: codes.append(get(self.port, "/api/support")[0])) for _ in range(40)]
        [t.start() for t in ths]
        [t.join() for t in ths]
        self.assertEqual(set(codes), {200}, codes)

    def test_success_resets_the_counter(self):
        for _ in range(4):
            get(self.port, "/api/support", pw="wrong")
        self.assertEqual(get(self.port, "/api/support")[0], 200)
        for _ in range(4):
            get(self.port, "/api/support", pw="wrong")
        self.assertEqual(get(self.port, "/api/support")[0], 200)   # 4 + 4 failures, but a success in between

    def test_healthz_is_never_locked(self):
        for _ in range(6):
            get(self.port, "/api/support", pw="wrong")
        self.assertEqual(get(self.port, "/healthz", user=None)[0], 200)


class ConnectionLimits(unittest.TestCase):
    def test_connections_over_the_cap_are_refused_not_queued_as_threads(self):
        p, port = start_server(MAX_CONNECTIONS="10", REQUEST_TIMEOUT_S="3")
        try:
            socks = [socket.create_connection(("127.0.0.1", port)) for _ in range(30)]
            closed = 0
            live = []
            for s_ in socks:                           # a refused connection can RST on this send, not just on the read below
                try:
                    s_.sendall(b"GET /healthz HTTP/1.1\r\nHost: x\r\n")
                    live.append(s_)
                except OSError:
                    closed += 1
            time.sleep(0.5)
            for s_ in live:
                s_.settimeout(0.3)
                try:
                    closed += s_.recv(10) == b""
                except socket.timeout:
                    pass
                except OSError:
                    closed += 1
            self.assertGreaterEqual(closed, 20, "only %d of 30 connections over a cap of 10 were refused" % closed)
            for s_ in socks:
                s_.close()
            time.sleep(0.3)
            self.assertEqual(get(port, "/healthz", user=None)[0], 200)   # capacity comes back once they go
        finally:
            p.kill(); p.wait()


class Tls(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost",
                        "-keyout", os.path.join(self.d, "k.pem"), "-out", os.path.join(self.d, "c.pem")],
                       check=True, capture_output=True)
        self.p, self.port = start_server(TLS_CERT=os.path.join(self.d, "c.pem"), TLS_KEY=os.path.join(self.d, "k.pem"),
                                         REQUEST_TIMEOUT_S="3")

    def tearDown(self):
        self.p.kill(); self.p.wait()

    def https(self, path):
        import ssl
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        r = urllib.request.Request("https://127.0.0.1:%d%s" % (self.port, path))
        with urllib.request.urlopen(r, timeout=5, context=ctx) as resp:
            return resp.status, dict(resp.headers)

    def test_an_idle_tcp_connection_does_not_block_other_clients(self):
        idle = socket.create_connection(("127.0.0.1", self.port))      # never starts the TLS handshake
        try:
            t = time.time()
            st, _ = self.https("/healthz")
            self.assertEqual(st, 200)
            self.assertLess(time.time() - t, 2.5)
        finally:
            idle.close()

    def test_hsts_is_sent_over_tls(self):
        _, h = self.https("/healthz")
        self.assertIn("max-age=", h.get("Strict-Transport-Security", ""))

if __name__ == "__main__":
    unittest.main()
