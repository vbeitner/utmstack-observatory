"""Tests for the live firewall map (/api/geo) and the dashboard time-range picker.

Run from the repo root:  python3 -m unittest discover -s tests -v
OpenSearch is stubbed: no network, no UTMStack needed.
"""
import importlib
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "app"))


def load_server(**env):
    os.environ.update({"OS_URL": "http://127.0.0.1:9", "DATA_DIR": tempfile.mkdtemp(),
                       "SITE_LOCATIONS": "", "HOME_LOCATION": ""}, **env)
    import server
    return importlib.reload(server)


def city(name, cc, country, lat, lon, count, denied=0):
    outs = [{"key": "success", "doc_count": count - denied}] + ([{"key": "denied", "doc_count": denied}] if denied else [])
    return {"key": name, "doc_count": count, "lat": {"value": lat}, "lon": {"value": lon},
            "country": {"buckets": [{"key": country, "doc_count": count}]}, "out": {"buckets": outs}}


def fw_bucket(ip, *cities_by_cc):
    return {"key": ip, "doc_count": sum(c["doc_count"] for cc in cities_by_cc for c in cc[1]),
            "cc": {"buckets": [{"key": cc, "doc_count": sum(c["doc_count"] for c in cs), "city": {"buckets": cs}}
                               for cc, cs in cities_by_cc]}}


FIREWALLS = [("70.28.96.178", "Dependable_HQ"), ("153.67.45.72", "Keltic_North"), ("142.176.165.186", "NS_435_Higney")]
GEOIP = {"70.28.96.178": {"latitude": 43.78, "longitude": -79.37, "city": "North York"},
         "142.176.165.186": {"latitude": 44.62, "longitude": -63.59, "city": "Halifax"}}


def fake_os_call(calls):
    def call(path, body=None, method="POST"):
        calls.append((path, body))
        aggs = (body or {}).get("aggs", {})
        if "fw" in aggs and "dn" in aggs["fw"].get("aggs", {}):              # firewall list for fw_sites()
            return {"aggregations": {"fw": {"buckets": [
                {"key": ip, "doc_count": 10, "dn": {"buckets": [{"key": '"%s"' % name, "doc_count": 10}]}}
                for ip, name in FIREWALLS]}}}
        if path.startswith("/v11-*/"):                                       # GeoIP lookup of a firewall WAN IP
            f = body["query"]["bool"]["filter"]
            side = next(iter(f[1]["exists"]["field"].split(".")[:1]))
            ip = f[0]["term"][side + ".ip.keyword"]
            g = GEOIP.get(ip)
            return {"hits": {"hits": [{"_source": {side: {"geolocation": g}}}] if g else []}}
        if "per_fw" in aggs:                                                 # the main map aggregation
            return {"hits": {"total": {"value": 1000}}, "aggregations": {
                "newest": {"value": 1.7e12},
                "outcome": {"buckets": [{"key": "success", "doc_count": 800}, {"key": "denied", "doc_count": 190},
                                        {"key": "failed", "doc_count": 10}]},
                "per_fw": {"buckets": [{"key": "70.28.96.178", "doc_count": 600, "out": {"buckets": [{"key": "denied", "doc_count": 100}]}},
                                       {"key": "142.176.165.186", "doc_count": 400, "out": {"buckets": [{"key": "denied", "doc_count": 90}]}}]},
                "in": {"doc_count": 120, "fw": {"buckets": [
                    fw_bucket("142.176.165.186", ("BG", [city("Sofia", "BG", "Bulgaria", 42.7, 23.3, 60, 60)]))]}},
                "out": {"doc_count": 500, "fw": {"buckets": [
                    fw_bucket("70.28.96.178", ("US", [city("Ashburn", "US", "United States", 39.0, -77.5, 300),
                                                      city("", "US", "United States", 37.75, -97.8, 50)]),
                              ("CA", [city("Toronto", "CA", "Canada", 43.7, -79.4, 40, 5)]))]}},
            }}
        if "sort" in (body or {}):                                           # blocked-inbound ticker
            return {"hits": {"hits": [{"_source": {"@timestamp": "2026-10-17T14:35:58Z", "dataSource": "142.176.165.186",
                                                   "origin": {"ip": "91.92.42.10", "geolocation": {"city": "Sofia", "country": "Bulgaria", "countryCode": "BG"}},
                                                   "target": {"port": 443}, "protocol": "TCP"}}]}}
        raise AssertionError("unexpected OpenSearch call: %s %s" % (path, json.dumps(body)[:200]))
    return call


class LocationParsing(unittest.TestCase):
    def setUp(self):
        self.s = load_server()

    def test_parse_loc(self):
        self.assertEqual(self.s.parse_loc("43.65, -79.38, Toronto"), {"lat": 43.65, "lon": -79.38, "city": "Toronto"})
        self.assertEqual(self.s.parse_loc("1,2")["city"], None)
        for bad in ("", "abc", "91,0", "0,200", "43.6"):
            self.assertIsNone(self.s.parse_loc(bad), bad)

    def test_parse_sites_skips_bad_entries(self):
        sites = self.s.parse_sites("Keltic_North=43.13,-80.75,Woodstock; 1.2.3.4=45,-75 ;broken=x,y;=1,2")
        self.assertEqual(set(sites), {"Keltic_North", "1.2.3.4"})
        self.assertEqual(sites["Keltic_North"]["city"], "Woodstock")


class GeoMap(unittest.TestCase):
    def setUp(self):
        self.s = load_server(SITE_LOCATIONS="Keltic_North=43.13,-80.75,Woodstock")
        self.calls = []
        self.s.os_call = fake_os_call(self.calls)

    def test_site_location_precedence(self):
        sites = {x["name"]: x for x in self.s.fw_sites()}
        self.assertEqual(sites["Keltic_North"]["loc_source"], "configured")     # override wins
        self.assertEqual(sites["Dependable_HQ"]["city"], "North York")         # UTMStack GeoIP
        self.assertEqual(sites["Dependable_HQ"]["loc_source"], "geoip")

    def test_unknown_location_falls_back_to_home(self):
        self.s.SITE_OVERRIDES = {}
        sites = {x["name"]: x for x in self.s.fw_sites()}
        self.assertEqual(sites["Keltic_North"]["loc_source"], "home")
        self.assertEqual((sites["Keltic_North"]["lat"], sites["Keltic_North"]["lon"]), (self.s.HOME["lat"], self.s.HOME["lon"]))

    def test_build_geo_aggregates_arcs_countries_and_totals(self):
        g = self.s.build_geo(60)
        self.assertEqual((g["total"], g["denied"], g["failed"], g["per_min"]), (1000, 190, 10, 1000))
        self.assertEqual(g["arcs"][0]["city"], "Ashburn")                       # busiest first
        sofia = next(a for a in g["arcs"] if a["city"] == "Sofia")
        self.assertEqual((sofia["dir"], sofia["denied"], sofia["site"]), ("in", 60, "142.176.165.186"))
        cc = {c["cc"]: c for c in g["countries"]}
        self.assertEqual(cc["US"]["count"], 350)
        self.assertEqual(cc["BG"]["denied"], 60)
        per = {x["name"]: x for x in g["sites"]}
        self.assertEqual((per["Dependable_HQ"]["total"], per["Dependable_HQ"]["denied"]), (600, 100))
        self.assertEqual(per["Keltic_North"]["total"], 0)                       # quiet in this window

    def test_window_is_clamped_and_cached(self):
        self.s.api_geo(60)
        n = len(self.calls)
        self.s.api_geo(60)                                                       # second viewer: no new queries
        self.assertEqual(len(self.calls), n)
        self.assertEqual(self.s.api_geo(12345)["window_s"], 60)

    def test_anonymized_output_has_no_client_names_or_wan_ips(self):
        self.s.api_geo(60)                                                       # fill the cache with real names first
        anon = json.dumps(self.s.api_geo(60, anon=True))
        for ip, name in FIREWALLS:
            self.assertNotIn(name, anon)
            self.assertNotIn(ip, anon)
        self.assertIn("Site A", anon)
        real = self.s.api_geo(60)                                                # and the cache was not altered
        self.assertEqual(real["ticker"][0]["site"], "NS_435_Higney")
        self.assertIn("Dependable_HQ", json.dumps(real))


class RangePicker(unittest.TestCase):
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
                "types": {"buckets": []}, "ds": {"buckets": []}, "recent": {"h": {"buckets": []}},
                "latest": {"value": None}, "sev": {"buckets": []}, "rules": {"buckets": []}}}
        self.s.os_call = call
        self.s.ai_traffic = lambda: {"configured": False}
        self.s.host_stats = lambda: {}

    def test_collect_uses_requested_window_and_previous_window(self):
        d = self.s.collect(6)
        self.assertEqual(d["range_h"], 6)
        bodies = json.dumps([b for _, b in self.calls])
        self.assertIn('"gte": "now-6h"', bodies)
        self.assertIn('"gte": "now-12h", "lt": "now-6h"', bodies)
        self.assertNotIn("now-24h", bodies)

    def test_non_default_range_is_cached_and_24h_comes_from_refresher(self):
        self.s._state["data"] = {"marker": "live-24h"}
        self.assertEqual(self.s.data_for(24), {"marker": "live-24h"})
        self.s.data_for(1)
        n = len(self.calls)
        self.s.data_for(1)
        self.assertEqual(len(self.calls), n)



class Packaging(unittest.TestCase):
    def test_version_file_matches_server(self):
        s = load_server()
        with open(os.path.join(ROOT, "VERSION")) as f:
            self.assertEqual(f.read().strip(), s.VERSION)

    def test_land_outline_is_shipped(self):
        with open(os.path.join(ROOT, "app", "land.json")) as f:
            self.assertGreater(len(json.load(f)["rings"]), 100)

if __name__ == "__main__":
    unittest.main()
