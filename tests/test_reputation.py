"""Tests for /api/reputation (live AbuseIPDB / VirusTotal lookups on an alert's IP).

Run from the repo root:  python3 -m unittest discover -s tests -v
No network: AbuseIPDB/VirusTotal calls are stubbed or skipped via the configured-key gate.
"""
import importlib
import io
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "app"))


def load_server(**env):
    base = {"OS_URL": "http://127.0.0.1:9", "DATA_DIR": tempfile.mkdtemp(), "ABUSEIPDB_KEY": "", "VIRUSTOTAL_KEY": ""}
    for k in ("ABUSEIPDB_KEY", "VIRUSTOTAL_KEY"):
        os.environ.pop(k, None)
    os.environ.update(base, **env)
    import server
    return importlib.reload(server)


def fake_response(payload):
    class R(io.BytesIO):
        def __enter__(self): return self
        def __exit__(self, *a): return False
    return R(json.dumps(payload).encode())


class InputValidation(unittest.TestCase):
    def setUp(self):
        self.s = load_server()

    def test_bad_ip_is_an_error(self):
        self.assertIn("error", self.s.api_reputation("not-an-ip"))

    def test_private_ip_is_reported_without_a_lookup(self):
        res = self.s.api_reputation("10.0.0.5")
        self.assertTrue(res["private"])
        self.assertNotIn("abuseipdb", res)


class NoKeysConfigured(unittest.TestCase):
    def setUp(self):
        self.s = load_server()

    def test_public_ip_reports_both_providers_unconfigured(self):
        res = self.s.api_reputation("8.8.8.8")
        self.assertEqual(res["abuseipdb"], {"configured": False})
        self.assertEqual(res["virustotal"], {"configured": False})

    def test_result_is_cached_for_the_same_ip(self):
        a = self.s.api_reputation("8.8.8.8")
        self.s.ABUSEIPDB_KEY = "would-change-the-result-if-not-cached"
        b = self.s.api_reputation("8.8.8.8")
        self.assertEqual(a, b)


class KeysConfigured(unittest.TestCase):
    def setUp(self):
        self.s = load_server(ABUSEIPDB_KEY="fake-abuseipdb-key", VIRUSTOTAL_KEY="fake-virustotal-key")

    def test_abuseipdb_response_is_parsed(self):
        payload = {"data": {"abuseConfidenceScore": 82, "totalReports": 40, "numDistinctUsers": 12,
                             "lastReportedAt": "2026-10-01T00:00:00Z", "usageType": "Data Center/Web Hosting",
                             "isp": "Example ISP", "domain": "example.com", "isWhitelisted": False}}
        with patch("urllib.request.urlopen", side_effect=lambda *a, **kw: fake_response(payload)):
            res = self.s.api_reputation("1.2.3.4")
        self.assertEqual(res["abuseipdb"]["score"], 82)
        self.assertEqual(res["abuseipdb"]["reports"], 40)

    def test_virustotal_response_is_parsed(self):
        payload = {"data": {"attributes": {
            "last_analysis_stats": {"malicious": 12, "suspicious": 2, "harmless": 70, "undetected": 5},
            "last_analysis_results": {"VendorA": {"category": "malicious", "result": "phishing"},
                                      "VendorB": {"category": "harmless", "result": "clean"}},
            "reputation": -15, "as_owner": "Example Networks", "country": "US"}}}
        with patch("urllib.request.urlopen", side_effect=lambda *a, **kw: fake_response(payload)):
            res = self.s.api_reputation("1.2.3.4")
        self.assertEqual(res["virustotal"]["malicious"], 12)
        self.assertEqual(res["virustotal"]["flagged_by"], ["phishing"])

    def test_provider_failure_does_not_take_down_the_other(self):
        def side_effect(req, timeout=10):
            if "abuseipdb" in req.full_url:
                raise OSError("boom")
            return fake_response({"data": {"attributes": {"last_analysis_stats": {}}}})
        with patch("urllib.request.urlopen", side_effect=side_effect):
            res = self.s.api_reputation("1.2.3.4")
        self.assertIn("error", res["abuseipdb"])
        self.assertNotIn("error", res["virustotal"])


if __name__ == "__main__":
    unittest.main()
