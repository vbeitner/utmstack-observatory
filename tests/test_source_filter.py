"""Tests for the source filter: /api/source-list, ?src= on /api/data and /api/geo, and demo mode.

Run from the repo root:  python3 -m unittest discover -s tests -v
OpenSearch is stubbed: no network, no UTMStack needed.
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_geo_and_range import fake_os_call, load_server  # noqa: E402

SRC = {"terms": {"dataSource.keyword": ["142.176.165.186", "web01"]}}


def filters(body):
    """Every clause in a query's bool filters, nested ones included."""
    out = []

    def walk(q):
        if isinstance(q, dict):
            for clause in (q.get("bool") or {}).get("filter", []):
                out.append(clause)
                walk(clause)
    walk((body or {}).get("query"))
    return out


class ParseSources(unittest.TestCase):
    def setUp(self):
        self.s = load_server()

    def test_empty_means_all_sources(self):
        self.assertEqual(self.s.parse_sources(None), ())
        self.assertEqual(self.s.parse_sources(["", "  "]), ())
        self.assertEqual(self.s.src_filter(()), [])
        self.assertEqual(self.s.scoped({"match_all": {}}, ()), {"match_all": {}})

    def test_values_are_trimmed_deduplicated_sorted_and_capped(self):
        self.assertEqual(self.s.parse_sources([" web01 ", "142.176.165.186", "web01"]), ("142.176.165.186", "web01"))
        many = ["src%02d" % i for i in range(40)]
        self.assertEqual(len(self.s.parse_sources(many)), self.s.MAX_SOURCES)

    def test_overlong_and_control_character_values_are_dropped(self):
        self.assertEqual(self.s.parse_sources(["x" * 201, "a\nb", "ok"]), ("ok",))

    def test_filter_is_an_exact_terms_clause(self):
        self.assertEqual(self.s.src_filter(("142.176.165.186", "web01")), [SRC])


class FilteredDashboard(unittest.TestCase):
    def setUp(self):
        self.s = load_server()
        self.calls = []

        def call(path, body=None, method="POST"):
            self.calls.append((path, body))
            if path.endswith("_count"):
                return {"count": 5}
            if path == "/_cluster/health":
                return {"status": "green"}
            return {"hits": {"total": {"value": 7}, "hits": []}, "aggregations": {
                "types": {"buckets": []}, "recent": {"h": {"buckets": []}}, "latest": {"value": None},
                "sev": {"buckets": []}, "rules": {"buckets": []},
                "ds": {"buckets": [{"key": "web01", "doc_count": 7, "last": {"value": 1}, "types": {"buckets": [{"key": "linux"}]}}]}}}
        self.s.os_call = call
        self.s.host_stats = lambda: {}
        self.s.current_ai_hosts = lambda: {}

    def test_every_log_and_alert_query_is_scoped(self):
        d = self.s.collect(6, ("142.176.165.186", "web01"))
        self.assertEqual(d["sources"], ["142.176.165.186", "web01"])
        data_calls = [(p, b) for p, b in self.calls if p.startswith("/v11-")]
        self.assertEqual(len(data_calls), 3)                                    # logs, previous window, alerts
        for p, b in data_calls:
            self.assertIn(SRC, filters(b), p)
        self.assertEqual(d["kpi"]["sources_total"], 1)

    def test_unfiltered_queries_are_unchanged_and_keep_the_drilldown_list(self):
        self.s._state["ds"] = None
        d = self.s.collect(24)
        self.assertEqual(d["sources"], [])
        self.assertNotIn("dataSource.keyword", json.dumps([filters(b) for _, b in self.calls if b and "query" in b]))
        self.assertEqual(self.s._state["ds"][0]["name"], "web01")

    def test_a_filtered_24h_view_never_overwrites_the_drilldown_source_list(self):
        self.s._state["ds"] = [{"name": "all-of-them"}]
        self.s.collect(24, ("web01",))
        self.assertEqual(self.s._state["ds"], [{"name": "all-of-them"}])

    def test_ai_traffic_is_scoped_to_the_selected_firewalls(self):
        self.s.current_ai_hosts = lambda: {"gx10": "10.0.2.34"}
        try:
            self.s.ai_traffic(("142.176.165.186",))
        except Exception:
            pass                                                                # the stub's answer has no AI aggregations
        body = next(b for p, b in self.calls if p.startswith("/v11-log-firewall"))
        self.assertIn({"terms": {"dataSource.keyword": ["142.176.165.186"]}}, body["query"]["bool"]["filter"])

    def test_data_for_caches_each_selection_apart_and_24h_all_comes_from_refresher(self):
        self.s._state["data"] = {"marker": "live-24h"}
        self.assertEqual(self.s.data_for(24), {"marker": "live-24h"})
        a = self.s.data_for(24, ("web01",))
        self.assertEqual(a["sources"], ["web01"])
        n = len(self.calls)
        self.s.data_for(24, ("web01",))
        self.assertEqual(len(self.calls), n)                                    # cached
        self.s.data_for(24, ("142.176.165.186",))
        self.assertGreater(len(self.calls), n)                                  # another selection: its own query


class FilteredMap(unittest.TestCase):
    def setUp(self):
        self.s = load_server()
        self.calls = []
        self.s.os_call = fake_os_call(self.calls)

    def test_every_map_query_is_scoped_and_only_selected_firewalls_get_a_pin(self):
        g = self.s.build_geo(60, "firewall-sophos-xg", sources=("142.176.165.186",))
        self.assertEqual(g["sources"], ["142.176.165.186"])
        flt = {"terms": {"dataSource.keyword": ["142.176.165.186"]}}
        main = next(b for p, b in self.calls if "per_fw" in (b or {}).get("aggs", {}))
        ticker = next(b for p, b in self.calls if "sort" in (b or {}))
        self.assertIn(flt, filters(main))
        self.assertIn(flt, filters(ticker))
        self.assertEqual({x["id"] for x in g["sites"]}, {"142.176.165.186"})

    def test_attacker_queries_for_servers_are_scoped(self):
        def call(path, body=None, method="POST"):
            self.calls.append((path, body))
            return {"hits": {"hits": []}}
        self.s.os_call = call
        for t in ("syslog", "linux"):
            self.s.attacker_rows(60, t, sources=("web01",))
        bodies = [b for p, b in self.calls]
        self.assertEqual(len(bodies), 2)
        for b in bodies:
            self.assertIn({"terms": {"dataSource.keyword": ["web01"]}}, filters(b))

    def test_map_cache_is_per_selection(self):
        self.s.api_geo(60, sources=("142.176.165.186",))
        n = len(self.calls)
        self.s.api_geo(60, sources=("142.176.165.186",))
        self.assertEqual(len(self.calls), n)
        self.s.api_geo(60)
        self.assertGreater(len(self.calls), n)


class SourceList(unittest.TestCase):
    def setUp(self):
        self.s = load_server()
        self.calls = []

        def call(path, body=None, method="POST"):
            self.calls.append((path, body))
            return {"aggregations": {"ds": {"buckets": [
                {"key": "142.176.165.186", "doc_count": 900, "last": {"value": 2e12},
                 "types": {"buckets": [{"key": "firewall-sophos-xg"}]}, "dn": {"buckets": [{"key": '"NS_435_Higney"'}]}},
                {"key": "web01", "doc_count": 50, "last": {"value": 1e12},
                 "types": {"buckets": [{"key": "linux"}]}, "dn": {"buckets": []}}]}}}
        self.s.os_call = call

    def test_lists_ids_names_types_and_is_cached(self):
        d = self.s.api_source_list()
        self.assertEqual(d["sources"], [
            {"id": "142.176.165.186", "name": "NS_435_Higney", "type": "firewall-sophos-xg", "events": 900, "last": 2e12},
            {"id": "web01", "name": "web01", "type": "linux", "events": 50, "last": 1e12}])
        self.assertIn('"gte": "now-24h"', json.dumps(self.calls[0][1]))
        self.s.api_source_list()
        self.assertEqual(len(self.calls), 1)


class DemoAndHttp(unittest.TestCase):
    def test_demo_server_filters_by_source_over_http(self):
        from test_hardening import get, start_server
        p, port = start_server(DEMO="1", DASH_PASS="", ALLOW_NO_AUTH="1")
        try:
            code, _, body = get(port, "/api/source-list", user=None)
            ids = [x["id"] for x in json.loads(body)["sources"]]
            self.assertIn("HQ-Toronto", ids)
            self.assertIn("web01.example.lan", ids)
            all_ = json.loads(get(port, "/api/data?range=1", user=None)[2])
            one = json.loads(get(port, "/api/data?range=1&src=web01.example.lan", user=None)[2])
            self.assertEqual(one["sources"], ["web01.example.lan"])
            self.assertLess(one["kpi"]["events_24h"], all_["kpi"]["events_24h"])
            self.assertEqual([t["name"] for t in one["types"]], ["linux"])
            g = json.loads(get(port, "/api/geo?window=900&src=HQ-Toronto&src=Branch-Ottawa", user=None)[2])
            self.assertEqual(g["sources"], ["Branch-Ottawa", "HQ-Toronto"])
            self.assertTrue(g["arcs"])
            self.assertEqual({a["site"] for a in g["arcs"]} - {"HQ-Toronto", "Branch-Ottawa"}, set())
            self.assertEqual({s["id"] for s in g["sites"]} - {"HQ-Toronto", "Branch-Ottawa"}, set())
        finally:
            p.kill(); p.wait()


class Frontend(unittest.TestCase):
    def test_page_has_the_picker_and_the_filter_is_sent_and_remembered(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "app", "index.html")) as f:
            html = f.read()
        with open(os.path.join(root, "app", "app.js")) as f:
            js = f.read()
        for el in ('id="srcBtn"', 'id="srcStrip"', 'id="srcDrawer"', 'id="srcList"', 'id="srcClear"'):
            self.assertIn(el, html)
        self.assertIn("'/api/data?range='+RANGE+srcQuery()", js)
        self.assertIn("srcQuery(), {cache:'no-store'}", js)                     # /api/geo
        self.assertIn("localStorage.setItem('obsSources'", js)
        self.assertIn("localStorage.getItem('obsSources'", js)


if __name__ == "__main__":
    unittest.main()
