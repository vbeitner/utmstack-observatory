"""1.21.0: login surge slow-down, MapLibre 6 module serving, report branding and copyright.
Run: python3 -m unittest discover -s tests -v"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_geo_and_range import ROOT, load_server  # noqa: E402
from test_hardening import get, start_server  # noqa: E402

sys.path.insert(0, os.path.join(ROOT, "app"))
import reports as rp  # noqa: E402


class LoginSurge(unittest.TestCase):
    def test_failures_from_many_addresses_trigger_the_slow_down(self):
        s = load_server(LOGIN_SURGE_PER_MIN="5")
        self.assertFalse(s.login_surge())
        for i in range(6):
            s.login_attempt("10.0.0.%d" % i, lambda: False)
        self.assertTrue(s.login_surge())
        self.assertFalse(any(v["until"] for v in s._logins.values()))   # nobody locked out by it

    def test_off_when_zero(self):
        s = load_server(LOGIN_SURGE_PER_MIN="0")
        for i in range(50):
            s.login_attempt("10.0.1.%d" % i, lambda: False)
        self.assertFalse(s.login_surge())


class MapModules(unittest.TestCase):
    def test_modules_are_served_with_versioned_imports_and_csp_allows_the_worker(self):
        p, port = start_server()
        try:
            code, headers, page = get(port, "/")
            self.assertIn(b'<script type="module" src="/maplibre-loader.mjs?v=', page)
            self.assertNotIn(b"maplibre-gl.js", page)
            self.assertIn("worker-src 'self' blob:", headers["Content-Security-Policy"])
            code, headers, loader = get(port, "/maplibre-loader.mjs")
            self.assertEqual(code, 200)
            self.assertIn("javascript", headers["Content-Type"])
            self.assertNotIn(b"__VERSION__", loader)
            self.assertIn(b"maplibre-gl-worker.mjs?v=", loader)
            code, _, main = get(port, "/maplibre-gl.mjs")
            self.assertIn(b'"./maplibre-gl-shared.mjs?v=', main)
            code, _, worker = get(port, "/maplibre-gl-worker.mjs")
            self.assertIn(b'"./maplibre-gl-shared.mjs?v=', worker)
            self.assertEqual(get(port, "/maplibre-gl-shared.mjs")[0], 200)
            self.assertEqual(get(port, "/maplibre-gl.js")[0], 404)       # 4.7.1 is gone
        finally:
            p.kill(); p.wait()


class ReportBranding(unittest.TestCase):
    def data(self):
        from test_reports import sample_data
        d = sample_data()
        d["connections"] = {"hours": 24, "denied_inbound": 900, "attackers": 40, "denied_total": 1000, "denied_replies": 50,
                            "denied_ports": [{"port": 22, "proto": "TCP", "count": 500, "sources": 30}],
                            "top_attackers": [{"ip": "45.1.2.3", "country": "Germany", "count": 400, "net": "hosting", "ports": [22], "sites": ["HQ"]}],
                            "allowed_total": 5000, "allowed_ports": [], "allowed_flows": [],
                            "allowed_inbound": [{"ip": "45.9.9.9", "country": "Canada", "site": "HQ", "count": 7, "net": None, "dst": ["10.0.0.5"], "ports": [3389]}]}
        return d

    def test_key_findings_flag_risky_inbound_and_high_alerts(self):
        f = rp.key_findings(self.data())
        text = " ".join(t for _, t in f)
        self.assertIn("RDP (3389)", text)
        self.assertIn("high-severity", text)
        self.assertIn("22/tcp (SSH)", text)
        self.assertTrue(any(level == "warn" for level, _ in f))

    def test_html_has_logo_findings_and_copyright(self):
        h = rp.render_html(self.data())
        self.assertIn("data:image/png;base64,", h)
        self.assertIn("Key findings", h)
        self.assertIn("© 2026 Victor Beitner. All rights reserved.", h)

    def test_pdf_has_copyright_on_every_page(self):
        pdf = rp.render_pdf(self.data())
        self.assertTrue(pdf.startswith(b"%PDF"))
        pages = pdf.count(b"/Type /Page\n") or pdf.count(b"/Type /Page ")
        import zlib, re
        text = b""
        for m in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", pdf, re.S):
            try:
                text += zlib.decompress(m.group(1))
            except zlib.error:
                pass
        self.assertGreaterEqual(text.count(b"Victor Beitner"), 2)       # footer on each page, plus the closing line
        self.assertIn(b"/Subtype /Image", pdf)                           # the logo


class Copyright(unittest.TestCase):
    def test_license_and_headers(self):
        with open(os.path.join(ROOT, "LICENSE")) as f:
            self.assertIn("Copyright (c) 2026 Victor Beitner. All rights reserved.", f.read())
        for rel in ("app/server.py", "app/app.js", "app/reports.py", "install.sh"):
            with open(os.path.join(ROOT, rel)) as f:
                self.assertIn("Victor Beitner", "".join(f.readlines()[:3]), rel)


if __name__ == "__main__":
    unittest.main()
