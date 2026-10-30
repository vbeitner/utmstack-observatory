"""Tests for the Firewall Ports widget (/api/ports): blocked and allowed ports per time range and source selection.

Run from the repo root:  python3 -m unittest discover -s tests -v
OpenSearch is stubbed: no network, no UTMStack needed.
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_geo_and_range import load_server  # noqa: E402
from test_source_filter import filters  # noqa: E402


def port_bucket(port, count, inbound, ips, proto="TCP"):
    return {"key": port, "doc_count": count, "proto": {"buckets": [{"key": proto, "doc_count": count}]},
            "inbound": {"doc_count": inbound, "src": {"value": ips}}}


ANSWER = {"hits": {"total": {"value": 1500}}, "aggregations": {
    "denied": {"doc_count": 1000, "replies": {"doc_count": 200}, "tries": {"doc_count": 800, "ports": {"buckets": [
        port_bucket(22, 500, 500, 41), port_bucket(6881, 300, 300, 12, "UDP")]}}},
    "allowed": {"doc_count": 500, "ports": {"buckets": [port_bucket(443, 450, 0, 0), port_bucket(3389, 50, 50, 3)]}}}}


class Ports(unittest.TestCase):
    def setUp(self):
        self.s = load_server()
        self.calls = []

        def call(path, body=None, method="POST"):
            self.calls.append((path, body))
            return ANSWER
        self.s.os_call = call

    def test_rows_totals_services_and_exposed_risky_ports(self):
        p = self.s.build_ports(24)
        self.assertEqual((p["denied_total"], p["denied_replies"], p["allowed_total"]), (1000, 200, 500))
        self.assertEqual(p["denied"][0], {"port": 22, "service": "SSH", "count": 500, "proto": "TCP", "inbound": 500,
                                          "remote_ips": 41, "risky": True})
        self.assertEqual(p["denied"][1]["service"], "BitTorrent")
        rdp = next(x for x in p["allowed"] if x["port"] == 3389)
        self.assertTrue(rdp["risky"] and rdp["inbound"] == 50)
        self.assertFalse(p["allowed"][0]["risky"])

    def test_query_reads_firewall_logs_for_the_window_and_leaves_replies_out_of_attempts(self):
        self.s.build_ports(6)
        path, body = self.calls[0]
        self.assertTrue(path.startswith(self.s.FW_SEARCH))
        self.assertIn('"gte": "now-6h"', json.dumps(body))
        self.assertEqual(body["aggs"]["denied"]["aggs"]["tries"]["filter"], {"bool": {"must_not": [self.s.REPLY_TRAFFIC]}})
        self.assertNotIn("dataSource.keyword", json.dumps(filters(body)))

    def test_only_the_selected_sources_are_counted(self):
        p = self.s.build_ports(24, ("142.176.165.186", "70.28.96.178"))
        self.assertEqual(p["sources"], ["142.176.165.186", "70.28.96.178"])
        self.assertIn({"terms": {"dataSource.keyword": ["142.176.165.186", "70.28.96.178"]}}, filters(self.calls[0][1]))

    def test_cached_per_range_and_selection_and_bad_range_means_24h(self):
        self.s.api_ports(24, ("a",))
        self.s.api_ports(24, ("a",))
        self.assertEqual(len(self.calls), 1)
        self.s.api_ports(24, ("b",))
        self.s.api_ports(6)
        self.assertEqual(len(self.calls), 3)
        self.assertEqual(self.s.api_ports(5)["hours"], 24)

    def test_no_firewall_index_gives_empty_lists(self):
        self.s.os_call = lambda *a, **k: {"hits": {"total": {"value": 0}, "hits": []}}
        p = self.s.build_ports(1)
        self.assertEqual((p["denied"], p["allowed"], p["denied_total"]), ([], [], 0))


class Widget(unittest.TestCase):
    def test_catalogue_default_layout_and_page(self):
        import layout_store
        self.assertIn("ports", layout_store.WIDGET_TYPES)
        overview = layout_store.default_layout()["screens"][0]["widgets"]
        self.assertIn("ports", [w["type"] for w in overview])
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "app", "index.html")) as f:
            html = f.read()
        with open(os.path.join(root, "app", "app.js")) as f:
            js = f.read()
        self.assertIn('data-widget="ports"', html)
        self.assertIn("'/api/ports?range='+RANGE+srcQuery()", js)

    def test_demo_server_ports_follow_the_source_filter(self):
        from test_hardening import get, start_server
        p, port = start_server(DEMO="1", DASH_PASS="", ALLOW_NO_AUTH="1")
        try:
            all_ = json.loads(get(port, "/api/ports?range=24", user=None)[2])
            self.assertTrue(all_["denied"] and all_["allowed"])
            one = json.loads(get(port, "/api/ports?range=24&src=Branch-Ottawa", user=None)[2])
            self.assertEqual(one["sources"], ["Branch-Ottawa"])
            self.assertLess(one["denied_total"], all_["denied_total"])
            none = json.loads(get(port, "/api/ports?range=1&src=web01.example.lan", user=None)[2])
            self.assertEqual((none["hours"], none["denied"], none["allowed"]), (1, [], []))   # a server, not a firewall
        finally:
            p.kill(); p.wait()


if __name__ == "__main__":
    unittest.main()
