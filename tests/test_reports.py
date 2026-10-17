"""PDF/HTML report generation, scheduling settings, and the download routes.
Run: python3 -m unittest discover -s tests -v"""
import base64
import importlib
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "app"))
import reports as rp  # noqa: E402


def sample_data():
    return {
        "generated_at": "2026-10-17T20:00:00+00:00", "range_h": 24, "host": "utmstack-test",
        "kpi": {"events_24h": 1000, "alerts_24h": 12, "sev": {"High": 1, "Medium": 2, "Low": 9},
                "sources_online": 4, "sources_total": 5, "sources_stale": ["old-fw"], "eps_5m": 1.1, "lag_s": 0.5},
        "rules": [{"name": "Known Malicious IP Detected", "count": 9, "sev": "Low"}],
        "alerts": [{"t": "2026-10-17T10:00:00Z", "sev": "High", "name": "Audit Log Tampering Detection",
                    "source": "dependable", "ip": "::1", "technique": "T1070.001 - Indicator Removal"}],
        "geo": {"per_min": 5, "denied": 20, "total": 50, "window_s": 86400,
                "countries": [{"country": "Russia", "cc": "RU", "count": 10, "denied": 8}]},
        "storage": {"disk_free": 10 * 1024**3, "disk_total": 100 * 1024**3, "days_left": 30.0, "avg_daily_total": 1024**3},
    }


class ReportsModule(unittest.TestCase):
    def test_generate_writes_both_formats(self):
        d = tempfile.mkdtemp()
        meta = rp.generate(d, sample_data())
        self.assertTrue(os.path.exists(rp.safe_path(d, meta["pdf"])))
        self.assertTrue(os.path.exists(rp.safe_path(d, meta["html"])))
        with open(rp.safe_path(d, meta["pdf"]), "rb") as f:
            self.assertTrue(f.read(5).startswith(b"%PDF"))
        with open(rp.safe_path(d, meta["html"])) as f:
            html = f.read()
        self.assertIn("Audit Log Tampering", html)
        self.assertIn("T1070.001", html)

    def test_list_reports_sorted_newest_first(self):
        d = tempfile.mkdtemp()
        for ts in ("2026-10-15T00:00:00+00:00", "2026-10-17T00:00:00+00:00", "2026-10-16T00:00:00+00:00"):
            data = sample_data(); data["generated_at"] = ts
            rp.generate(d, data)
        stamps = [e["stamp"] for e in rp.list_reports(d)]
        self.assertEqual(stamps, sorted(stamps, reverse=True))

    def test_prune_keeps_only_the_newest(self):
        d = tempfile.mkdtemp()
        for i in range(5):
            data = sample_data(); data["generated_at"] = "2026-10-%02dT00:00:00+00:00" % (10 + i)
            rp.generate(d, data)
        rp.prune(d, keep=2)
        self.assertEqual(len(rp.list_reports(d)), 2)
        files = os.listdir(rp.reports_dir(d))
        self.assertEqual(len(files), 4)   # 2 kept reports x (.pdf + .html)

    def test_safe_path_rejects_anything_not_our_own_filename(self):
        d = tempfile.mkdtemp()
        for bad in ("../../etc/passwd", "report-20261017T200000Z.txt", "/etc/passwd", "", "report-bad.pdf"):
            self.assertIsNone(rp.safe_path(d, bad), bad)


class BuildReportData(unittest.TestCase):
    def setUp(self):
        os.environ.update(OS_URL="http://127.0.0.1:9", DATA_DIR=tempfile.mkdtemp(), DASH_PASS="", BIND="127.0.0.1")
        import server
        self.s = importlib.reload(server)
        self.s.data_for = lambda hours: {"kpi": {"events_24h": 42, "sev": {}}, "rules": [], "alerts": []}
        self.s.build_geo = lambda window: {"per_min": 1, "denied": 0, "total": 0, "window_s": window, "countries": []}
        self.s.api_storage = lambda: {"disk_free": 1, "disk_total": 2, "days_left": 3, "avg_daily_total": 4}

    def test_assembles_the_three_sources_into_one_dict(self):
        d = self.s.build_report_data(24)
        self.assertEqual(d["kpi"]["events_24h"], 42)
        self.assertEqual(d["storage"]["days_left"], 3)
        self.assertEqual(d["host"], self.s.HOST_NAME)

    def test_out_of_range_hours_falls_back_to_24(self):
        d = self.s.build_report_data(99)
        self.assertEqual(d["range_h"], 24)


class HttpRoutes(unittest.TestCase):
    def setUp(self):
        os.environ.update(OS_URL="http://127.0.0.1:9", DATA_DIR=tempfile.mkdtemp(), DASH_PASS="", BIND="127.0.0.1")
        for k in ("ABUSEIPDB_KEY", "VIRUSTOTAL_KEY", "DASH_USER"):
            os.environ.pop(k, None)
        import server
        self.s = importlib.reload(server)
        self.s.build_report_data = lambda hours=24: sample_data()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), self.s.Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = "http://127.0.0.1:%d" % self.httpd.server_address[1]

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    JSON = {"Content-Type": "application/json", "X-Observatory": "1"}

    def req(self, method, path, body=None, headers=None, raw=False):
        r = urllib.request.Request(self.base + path, method=method,
                                   data=json.dumps(body).encode() if body is not None else (b"" if method == "POST" else None),
                                   headers=headers or {})
        try:
            with urllib.request.urlopen(r) as resp:
                return resp.status, dict(resp.headers), (resp.read() if raw else json.loads(resp.read()))
        except urllib.error.HTTPError as e:
            body_bytes = e.read()
            try:
                return e.code, dict(e.headers), json.loads(body_bytes or b"{}")
            except ValueError:
                return e.code, dict(e.headers), body_bytes

    def test_list_is_empty_initially(self):
        st, _, got = self.req("GET", "/api/reports")
        self.assertEqual((st, got["reports"], got["report_hour"]), (200, [], None))

    def test_generate_requires_csrf(self):
        st, _, _ = self.req("POST", "/api/reports/generate", headers={"Content-Type": "application/json"})
        self.assertEqual(st, 403)

    def test_generate_then_list_then_download(self):
        st, _, meta = self.req("POST", "/api/reports/generate", headers=self.JSON)
        self.assertEqual(st, 200)
        st, _, got = self.req("GET", "/api/reports")
        self.assertEqual(len(got["reports"]), 1)
        st, headers, pdf_bytes = self.req("GET", "/api/reports/" + meta["pdf"], raw=True)
        self.assertEqual(st, 200)
        self.assertTrue(pdf_bytes.startswith(b"%PDF"))
        self.assertIn("attachment", headers.get("Content-Disposition", ""))

    def test_download_path_traversal_is_404(self):
        st, _, _ = self.req("GET", "/api/reports/..%2f..%2fetc%2fpasswd", raw=True)
        self.assertEqual(st, 404)

    def test_report_hour_validated_and_reflected_in_list(self):
        st, _, err = self.req("PUT", "/api/settings", {"report_hour": "25"}, self.JSON)
        self.assertEqual(st, 400)
        st, _, _ = self.req("PUT", "/api/settings", {"report_hour": "6"}, self.JSON)
        self.assertEqual(st, 200)
        st, _, got = self.req("GET", "/api/reports")
        self.assertEqual(got["report_hour"], 6)


if __name__ == "__main__":
    unittest.main()
