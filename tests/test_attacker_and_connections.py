"""Attacker detail (/api/attacker) and the report's denied/allowed connection sections (1.16.2).
Run: python3 -m unittest discover -s tests -v"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_geo_and_range import ROOT, load_server  # noqa: E402

sys.path.insert(0, os.path.join(ROOT, "app"))
import reports as rp  # noqa: E402


def terms(*pairs, **sub):
    return {"buckets": [dict({"key": k, "doc_count": n}, **sub) for k, n in pairs]}


def outcome(denied=0, success=0, failed=0):
    return terms(*[(k, v) for k, v in (("denied", denied), ("success", success), ("failed", failed)) if v])


class Attacker(unittest.TestCase):
    def setUp(self):
        self.s = load_server()
        self.s.fw_sites = lambda: [{"id": "70.28.96.178", "name": "Dependable_HQ"}]
        self.calls = []
        main = {"hits": {"total": {"value": 120}}, "aggregations": {
            "first": {"value_as_string": "2026-10-19T01:00:00.000Z"}, "last": {"value_as_string": "2026-10-19T04:00:00.000Z"},
            "out": outcome(denied=100, success=20),
            "types": terms(("firewall-sophos-xg", 120)),
            "replies": {"doc_count": 30, "src": terms((443, 30))},
            "tries": {"port_count": {"value": 2}, "ports": {"buckets": [
                {"key": 3389, "doc_count": 60, "out": outcome(denied=60), "proto": terms(("TCP", 60))},
                {"key": 443, "doc_count": 30, "out": outcome(denied=10, success=20), "proto": terms(("TCP", 30))}]}},
            "reasons": terms(("Could not associate packet to any connection.", 30)),
            "sites": {"buckets": [{"key": "70.28.96.178", "doc_count": 120, "out": outcome(denied=100, success=20),
                                   "name": terms(("Dependable_HQ", 120)), "host": terms()}]},
            "targets": {"buckets": [{"key": "10.0.0.5", "doc_count": 60, "out": outcome(denied=60), "ports": terms((3389, 60))}]}}}
        syslog = {"hits": {"hits": [
            {"_source": {"@timestamp": "2026-10-19T04:30:00Z", "log": {"message": "Failed password for root from 45.1.2.3 port 51234 ssh2"},
                         "dataSource": "web01", "origin": {"process": "sshd[123]", "host": "web01"}}},
            {"_source": {"@timestamp": "2026-10-19T04:31:00Z", "log": {"message": "Failed password for root from 45.1.2.30 port 1 ssh2"},
                         "dataSource": "web01", "origin": {"process": "sshd[124]"}}}]}}

        def os_call(path, body=None, method="GET"):
            self.calls.append((path, body))
            return syslog if "syslog" in path else main
        self.s.os_call = os_call

    def test_ports_replies_sites_and_syslog_ssh(self):
        d = self.s.api_attacker("45.1.2.3")
        self.assertEqual(d["replies"], 30)
        self.assertEqual(d["reply_ports"], [443])
        ports = {x["port"]: x for x in d["ports"]}
        self.assertEqual(ports[3389]["denied"], 60)
        self.assertEqual(ports[443]["allowed"], 20)
        self.assertEqual(ports[22]["denied"], 1)           # one sshd line for this exact address, not 45.1.2.30
        self.assertEqual(d["syslog_ssh"], 1)
        self.assertEqual(d["sites"][0]["name"], "Dependable_HQ")
        self.assertEqual(d["last"], "2026-10-19T04:30:00Z")
        self.assertEqual(d["ports"][0]["port"], 3389)      # most denied first
        q = json.dumps(self.calls[0][1])
        self.assertIn('"origin.ip.keyword": "45.1.2.3"', q)  # term query, value as JSON

    def test_bad_private_and_cached(self):
        self.assertEqual(self.s.api_attacker("not-an-ip")["error"], "not a valid IP address")
        self.assertEqual(self.s.api_attacker("fe80::1%eth0")["error"], "not a valid IP address")
        self.assertTrue(self.s.api_attacker("192.168.1.5")["private"])
        self.assertEqual(self.calls, [])                    # nothing was queried for those
        self.s.api_attacker("45.1.2.3"); n = len(self.calls); self.s.api_attacker("45.1.2.3")
        self.assertEqual(len(self.calls), n)                # second answer from the 60 s cache

    def test_wall_screens_get_no_site_names_or_targets(self):
        d = self.s.api_attacker("45.1.2.3", anon=True)
        self.assertEqual(d["targets"], [])
        self.assertTrue(all(x["name"].startswith("Site ") and not x["site"] for x in d["sites"]))
        self.assertNotIn("Dependable_HQ", json.dumps(d))


class Connections(unittest.TestCase):
    def setUp(self):
        self.s = load_server()
        denied = {"hits": {"total": {"value": 500}}, "aggregations": {"replies": {"doc_count": 50}, "inbound": {
            "doc_count": 300, "attackers": {"value": 40},
            "ports": {"buckets": [{"key": 22, "doc_count": 200, "src": {"value": 30}, "proto": terms(("TCP", 200))}]},
            "top": {"buckets": [{"key": "45.1.2.3", "doc_count": 150, "country": terms(("Germany", 150)),
                                 "ports": terms((22, 150)), "sites": terms(("Dependable_HQ", 150))}]}}}}
        ok = {"hits": {"total": {"value": 9000}}, "aggregations": {
            "ports": {"buckets": [{"key": 443, "doc_count": 8000, "src": {"value": 12}, "dst": {"value": 300}, "proto": terms(("TCP", 8000))}]},
            "inbound": {"top": {"buckets": [{"key": "45.9.9.9", "doc_count": 7, "country": terms(("Canada", 7)), "site": terms(("Dependable_HQ", 7)),
                                             "dst": terms(("10.0.0.5", 7)), "ports": terms((3389, 7))}]}},
            "flows": {"buckets": [{"key": "10.0.0.8", "doc_count": 900, "country": terms(), "site": terms(("Dependable_HQ", 900)),
                                   "dst": {"buckets": [{"key": "52.1.1.1", "doc_count": 800, "country": terms(("United States", 800)),
                                                        "ports": terms((443, 800))},
                                                       {"key": "10.0.0.9", "doc_count": 100, "country": terms(), "ports": terms((445, 100))}]}}]}}}
        self.s.os_call = lambda path, body=None, method="GET": denied if "denied" in json.dumps(body) else ok

    def test_report_connections_shapes_and_directions(self):
        c = self.s.report_connections(24)
        self.assertEqual((c["denied_total"], c["denied_inbound"], c["denied_replies"], c["attackers"]), (500, 300, 50, 40))
        self.assertEqual(c["denied_ports"][0], {"port": 22, "proto": "TCP", "count": 200, "sources": 30})
        self.assertEqual(c["top_attackers"][0]["ports"], [22])
        self.assertEqual(c["allowed_inbound"][0]["ports"], [3389])
        self.assertEqual([f["dir"] for f in c["allowed_flows"]], ["outbound", "internal"])

    def test_report_renders_both_sections_in_html_and_pdf(self):
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from test_reports import sample_data
        data = dict(sample_data(), connections=self.s.report_connections(24))
        html = rp.render_html(data)
        for text in ("Denied connections", "Ports attackers tried", "22/tcp", "SSH", "Top attackers", "45.1.2.3",
                     "Successful connections", "Allowed in from the internet", "3389 (RDP)", "who to whom", "52.1.1.1 (United States)"):
            self.assertIn(text, html)
        pdf = rp.render_pdf(data)
        self.assertTrue(pdf.startswith(b"%PDF"))
        self.assertGreater(len(pdf), 3000)

    def test_report_still_builds_when_the_connection_queries_fail(self):
        def boom(*a, **k):
            raise RuntimeError("OpenSearch HTTP 500")
        self.s.os_call = boom
        self.assertIsNone(self.s._report_connections_safe(24))
        self.assertNotIn("Denied connections", rp.render_html({"connections": None}))


class DemoAndCache(unittest.TestCase):
    def test_demo_attacker_and_versioned_script_urls(self):
        from test_hardening import get, start_server
        p, port = start_server(DEMO="1", DASH_PASS="", ALLOW_NO_AUTH="1")
        try:
            code, _, body = get(port, "/api/attacker?ip=203.0.113.40", user=None)
            d = json.loads(body)
            self.assertGreater(d["total"], 0, d)
            self.assertTrue(d["ports"])
            code, _, page = get(port, "/", user=None)
            self.assertIn(b'/app.js?v=', page)
            self.assertIn(b'/maplibre-gl.css?v=', page)
            self.assertEqual(get(port, "/app.js?v=1", user=None)[0], 200)
        finally:
            p.kill(); p.wait()


if __name__ == "__main__":
    unittest.main()
