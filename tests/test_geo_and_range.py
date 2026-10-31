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

    def test_type_scopes_the_index_and_filter(self):
        g = self.s.build_geo(60, "o365")
        main = next(b for p, b in self.calls if "per_fw" in (b or {}).get("aggs", {}))
        path = next(p for p, b in self.calls if "per_fw" in (b or {}).get("aggs", {}))
        self.assertEqual(path, "/v11-log-o365*/_search")
        self.assertIn({"term": {"dataType.keyword": "o365"}}, main["query"]["bool"]["filter"])
        self.assertEqual(g["type"], "o365")
        self.assertNotIn("Keltic_North", [x["name"] for x in g["sites"]])     # idle firewalls only on firewall/all views
        ticker = next(b for p, b in self.calls if "sort" in (b or {}))
        self.assertIn({"terms": {"actionResult.keyword": ["denied", "failed"]}}, ticker["query"]["bool"]["filter"])

    def test_all_covers_every_geo_type_and_unknown_type_means_all(self):
        g = self.s.api_geo(60, dtype="nonsense")
        self.assertEqual(g["type"], "all")
        main = next(b for p, b in self.calls if "per_fw" in (b or {}).get("aggs", {}))
        self.assertIn({"terms": {"dataType.keyword": list(self.s.NET_TYPES)}}, main["query"]["bool"]["filter"])

    def test_type_with_no_index_gives_an_empty_map(self):
        self.s.os_call = lambda path, body=None, method="POST": {"hits": {"total": {"value": 0}, "hits": []}}
        g = self.s.build_geo(60, "google")
        self.assertEqual((g["type"], g["total"], g["arcs"], g["ticker"]), ("google", 0, [], []))

    def test_syslog_attackers_are_located_and_counted_as_blocked(self):
        hits = [{"_source": {"@timestamp": "2026-10-18T20:00:0%dZ" % i, "dataSource": "10.0.2.3", "origin": {"host": "truenas"},
                             "log": {"message": m}}} for i, m in enumerate([
            "Invalid user firedancer from 2.57.122.238 port 54456",
            "Failed password for root from 2.57.122.238 port 1022 ssh2",
            "Accepted publickey for admin from 10.0.2.50 port 5000",     # private: ignored
            "Accepted password for victor from 81.2.69.160 port 6000"])]
        self.s.os_call = lambda path, body=None, method="POST": {"hits": {"hits": hits}}
        self.s.GEO.lookup = lambda ip: {"2.57.122.238": {"lat": 52.37, "lon": 4.9, "city": "Amsterdam", "country": "Netherlands",
                                                         "cc": "NL", "net": "hosting"},
                                        "81.2.69.160": {"lat": 51.5, "lon": -0.1, "city": "London", "country": "United Kingdom",
                                                        "cc": "GB", "net": None}}.get(ip)
        g = self.s.build_geo(60, "syslog")
        ams = next(a for a in g["arcs"] if a["city"] == "Amsterdam")
        self.assertEqual((ams["count"], ams["denied"], ams["hosting"], ams["vpn"], ams["dir"], ams["site"]), (2, 2, 2, 0, "in", "10.0.2.3"))
        lon = next(a for a in g["arcs"] if a["city"] == "London")
        self.assertEqual(lon["denied"], 0)                                      # a successful login is not blocked
        self.assertEqual((g["total"], g["denied"]), (3, 2))
        self.assertEqual([x["ip"] for x in g["ticker"]], ["2.57.122.238", "2.57.122.238"])   # different seconds: both kept
        self.assertEqual(g["ticker"][0]["net"], "hosting")
        self.assertEqual(next(x for x in g["sites"] if x["id"] == "10.0.2.3")["name"], "truenas")

    def test_firewall_arcs_count_vpn_tor_and_hosting_from_their_busiest_ips(self):
        kinds = {"1.1.1.1": "vpn", "2.2.2.2": "tor", "3.3.3.3": "hosting"}
        self.s.GEO.net_kind = lambda ip: kinds.get(ip)
        b = [{"key": ip, "doc_count": n} for ip, n in (("1.1.1.1", 5), ("2.2.2.2", 3), ("3.3.3.3", 7), ("4.4.4.4", 9))]
        self.assertEqual(self.s.net_counts(b), {"vpn": 5, "tor": 3, "hosting": 7})

    def test_port_filters_every_query_and_bad_ports_are_ignored(self):
        g = self.s.api_geo(60, dtype="firewall-sophos-xg", port=3389)
        self.assertEqual(g["port"], 3389)
        main = next(b for p, b in self.calls if "per_fw" in (b or {}).get("aggs", {}))
        self.assertIn({"term": {"target.port": 3389}}, main["query"]["bool"]["filter"])
        ticker = next(b for p, b in self.calls if "sort" in (b or {}))
        self.assertIn({"term": {"target.port": 3389}}, ticker["query"]["bool"]["filter"][0]["bool"]["filter"])
        self.assertIsNone(self.s.api_geo(60, dtype="firewall-sophos-xg", port=70000)["port"])

    def test_syslog_counts_only_ssh_for_port_22_and_nothing_for_other_ports(self):
        hits = [{"_source": {"@timestamp": "2026-10-18T20:00:00Z", "dataSource": "10.0.2.3", "origin": {"process": p},
                             "log": {"message": "Failed password for x from 2.57.122.238 port 1"}}} for p in ("sshd-session", "sudo")]
        self.s.os_call = lambda path, body=None, method="POST": {"hits": {"hits": hits}}
        self.assertEqual(len(self.s.attacker_rows(60, "syslog", 22)[0]), 1)
        self.assertEqual(self.s.attacker_rows(60, "syslog", 443), ([], [], None))

    def test_same_attempt_logged_twice_shows_once(self):
        hits = [{"_source": {"@timestamp": t, "dataSource": "10.0.2.3", "log": {"message": m}}}
                for t, m in (("2026-10-18T20:00:00.120Z", "Invalid user x from 2.57.122.238 port 1"),
                             ("2026-10-18T20:00:00.870Z", "Connection closed by invalid user x 2.57.122.238 port 1 [preauth]"))]
        self.s.os_call = lambda path, body=None, method="POST": {"hits": {"hits": hits}}
        self.s.GEO.lookup = lambda ip: None
        self.assertEqual(len(self.s.build_geo(60, "syslog")["ticker"]), 1)

    def test_syslog_ip_extraction_skips_private_addresses(self):
        self.assertEqual(self.s.syslog_ip("Connection closed by invalid user x 2.57.122.238 port 1 [preauth]"), "2.57.122.238")
        self.assertIsNone(self.s.syslog_ip("Accepted publickey for a from 192.168.1.5 port 22"))
        self.assertIsNone(self.s.syslog_ip("from 100.123.152.25 port 22"))      # CGNAT (NetBird)
        self.assertIsNone(self.s.syslog_ip("version 1.2.3.4.5 build"))

    def test_one_failing_attacker_source_does_not_blank_the_map(self):
        g = self.s.build_geo(60, "all")                                          # fake rejects the attacker queries
        self.assertEqual(g["total"], 1000)

    def test_cache_is_per_type(self):
        self.s.api_geo(60, dtype="all")
        n = len(self.calls)
        self.s.api_geo(60, dtype="firewall-sophos-xg")
        self.assertGreater(len(self.calls), n)                                  # different type: its own query

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




class SupportInfo(unittest.TestCase):
    def test_default_contact_is_cyber_security_canada(self):
        s = load_server(SUPPORT_CONTACT="")
        self.assertEqual(s.SUPPORT, {"name": "Cyber Security Canada", "email": "info@cybersecuritycanada.com",
                                     "url": "https://cybersecuritycanada.com"})

    def test_parse_support_fills_scheme_and_drops_blanks(self):
        s = load_server()
        self.assertEqual(s.parse_support("Acme| help@acme.test |+1 613 555 0100|acme.test"),
                         {"name": "Acme", "email": "help@acme.test", "phone": "+1 613 555 0100", "url": "https://acme.test"})

    def test_wall_version_has_contact_and_version_only(self):
        s = load_server()
        self.assertEqual(set(s.api_support(anon=True)), {"contact", "version", "installed", "copyright"})

    def test_full_version_never_contains_secrets(self):
        s = load_server(DASH_PASS="dash-secret-123", OS_PASS="os-secret-456")
        s._state["data"] = {"kpi": {"lag_s": 1.5, "sources_online": 20, "sources_total": 22}, "cluster": {"status": "yellow"}}
        out = json.dumps(s.api_support())
        self.assertNotIn("dash-secret-123", out)
        self.assertNotIn("os-secret-456", out)
        self.assertIn('"opensearch": "yellow"', out)

class Packaging(unittest.TestCase):
    def test_version_file_matches_server(self):
        s = load_server()
        with open(os.path.join(ROOT, "VERSION")) as f:
            self.assertEqual(f.read().strip(), s.VERSION)

    def test_land_outline_is_shipped(self):
        with open(os.path.join(ROOT, "app", "land.json")) as f:
            self.assertGreater(len(json.load(f)["rings"]), 100)

    def test_vpn_ranges_and_tor_take_priority_and_private_ips_are_never_looked_up(self):
        import tempfile, geoip
        gi = geoip.GeoIP(tempfile.mkdtemp(), online_daily=0)
        for kind, text in (("vpn", "5.6.7.0/24\n# comment\n2001:db8::/32\n"), ("hosting", "5.6.0.0/16\n"), ("tor", "5.6.7.8\n")):
            r = geoip.parse_ranges(text); gi.ranges[kind] = (r, [a for a, _ in r])
        self.assertEqual(gi.net_kind("5.6.7.8"), "tor")
        self.assertEqual(gi.net_kind("5.6.7.9"), "vpn")
        self.assertEqual(gi.net_kind("5.6.9.1"), "hosting")
        self.assertIsNone(gi.net_kind("8.8.8.8"))
        self.assertIsNone(gi.lookup("10.1.2.3"))
        self.assertTrue(gi._q.empty())                                         # private: no online lookup queued either

    def test_street_map_assets_are_shipped_and_only_the_tile_host_is_allowed(self):
        s = load_server()
        for path in s.STATIC_FILES:
            self.assertTrue(os.path.getsize(os.path.join(ROOT, "app", path[1:])) > 10000, path)
        with open(os.path.join(ROOT, "app", "app.js")) as f:
            page = f.read()
        self.assertIn(s.TILE_HOST + "/styles/", page)
        self.assertEqual(s.TILE_HOST, "https://tiles.openfreemap.org")

if __name__ == "__main__":
    unittest.main()
