# tests/test_layout_store.py
"""Shared layout storage and validation. Run: python3 -m unittest discover -s tests -v"""
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "app"))
import layout_store as ls  # noqa: E402


def one_screen(widgets, **extra):
    s = {"id": "main", "name": "Main", "wall": False, "widgets": widgets}
    s.update(extra)
    return {"schema": 1, "version": 0, "screens": [s]}


class Defaults(unittest.TestCase):
    def test_default_layout_is_valid_and_has_the_three_screens(self):
        lay, notes = ls.validate_layout(ls.default_layout())
        self.assertEqual(notes, [])
        self.assertEqual([s["name"] for s in lay["screens"]], ["Overview", "Live map", "Activity"])
        self.assertEqual([s["wall"] for s in lay["screens"]], [False, True, True])
        self.assertEqual({w["type"] for w in lay["screens"][0]["widgets"]}, set(ls.WIDGET_TYPES))


class Validation(unittest.TestCase):
    def test_unknown_widget_type_is_dropped_with_a_note(self):
        lay, notes = ls.validate_layout(one_screen([{"type": "map", "x": 0, "y": 0, "w": 6, "h": 8},
                                                    {"type": "future-widget", "x": 6, "y": 0, "w": 6, "h": 8}]))
        self.assertEqual([w["type"] for w in lay["screens"][0]["widgets"]], ["map"])
        self.assertTrue(any("future-widget" in n for n in notes))

    def test_geometry_is_clamped_to_the_grid(self):
        lay, _ = ls.validate_layout(one_screen([{"type": "map", "x": 10, "y": -3, "w": 9, "h": 999}]))
        w = lay["screens"][0]["widgets"][0]
        self.assertEqual((w["x"], w["y"], w["w"], w["h"]), (3, 0, 9, 40))   # x pulled left so x+w <= 12

    def test_minimum_sizes_are_enforced(self):
        lay, _ = ls.validate_layout(one_screen([{"type": "map", "x": 0, "y": 0, "w": 1, "h": 1}]))
        w = lay["screens"][0]["widgets"][0]
        self.assertEqual((w["w"], w["h"]), (ls.WIDGET_TYPES["map"]["min_w"], ls.WIDGET_TYPES["map"]["min_h"]))

    def test_duplicate_type_on_one_screen_keeps_the_first(self):
        lay, notes = ls.validate_layout(one_screen([{"type": "map", "x": 0, "y": 0, "w": 6, "h": 8},
                                                    {"type": "map", "x": 6, "y": 0, "w": 6, "h": 8}]))
        self.assertEqual(len(lay["screens"][0]["widgets"]), 1)
        self.assertTrue(notes)

    def test_missing_fields_get_defaults_and_bad_names_are_cleaned(self):
        lay, _ = ls.validate_layout({"schema": 1, "screens": [{"name": "  <b>Ops</b>  ", "widgets": []}]})
        s = lay["screens"][0]
        self.assertEqual(s["name"], "<b>Ops</b>")          # trimmed; escaping is the browser's job
        self.assertRegex(s["id"], r"^[a-z0-9-]{1,24}$")
        self.assertIs(s["wall"], False)
        self.assertEqual(lay["version"], 0)

    def test_structural_errors_raise(self):
        for bad in (None, [], {"schema": 2, "screens": []}, {"schema": 1, "screens": []},
                    {"schema": 1, "screens": [{"widgets": "x"}]},
                    {"schema": 1, "screens": [one_screen([])["screens"][0]] * 13}):
            with self.assertRaises(ValueError, msg=repr(bad)[:60]):
                ls.validate_layout(bad)

    def test_too_many_widgets_raise(self):
        many = [{"type": t, "x": 0, "y": i, "w": 12, "h": 4} for i, t in enumerate(list(ls.WIDGET_TYPES) * 3)]
        with self.assertRaises(ValueError):
            ls.validate_layout(one_screen(many))


class Storage(unittest.TestCase):
    def test_load_returns_default_when_nothing_stored(self):
        d = tempfile.mkdtemp()
        self.assertEqual(ls.load(d)["screens"][0]["name"], "Overview")

    def test_save_bumps_version_and_survives_reload(self):
        d = tempfile.mkdtemp()
        first = ls.save(d, ls.default_layout())
        second = ls.save(d, first)
        self.assertEqual((first["version"], second["version"]), (1, 2))
        self.assertEqual(ls.load(d)["version"], 2)
        self.assertIn("saved_at", ls.load(d))

    def test_corrupt_file_falls_back_to_default(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "layout.json"), "w") as f:
            f.write("{not json")
        self.assertEqual(ls.load(d)["screens"][0]["name"], "Overview")

    def test_oversized_layout_is_rejected(self):
        lay = ls.default_layout()
        lay["screens"][0]["name"] = "x" * 70000
        with self.assertRaises(ValueError):
            ls.save(tempfile.mkdtemp(), lay)


class StoredFileProblems(unittest.TestCase):
    def write(self, d, obj):
        with open(os.path.join(d, "layout.json"), "w") as f:
            f.write(obj if isinstance(obj, str) else json.dumps(obj))

    def test_notes_about_dropped_widgets_are_returned(self):
        d = tempfile.mkdtemp()
        self.write(d, one_screen([{"type": "map", "x": 0, "y": 0, "w": 6, "h": 8},
                                  {"type": "future-widget", "x": 6, "y": 0, "w": 6, "h": 8}]))
        lay, notes = ls.load_with_notes(d)
        self.assertEqual([w["type"] for w in lay["screens"][0]["widgets"]], ["map"])
        self.assertTrue(any("future-widget" in n for n in notes))

    def test_unusable_file_is_reported_and_kept_aside_on_next_save(self):
        d = tempfile.mkdtemp()
        self.write(d, {"schema": 2, "version": 7, "screens": []})          # e.g. from a newer build
        lay, notes = ls.load_with_notes(d)
        self.assertEqual(lay["screens"][0]["name"], "Overview")
        self.assertTrue(any("could not be read" in n for n in notes))
        ls.save(d, ls.default_layout())
        kept = [f for f in os.listdir(d) if f.startswith("layout.json.bad-")]
        self.assertEqual(len(kept), 1)                                     # the unreadable file is preserved, not clobbered
        with open(os.path.join(d, kept[0])) as f:
            self.assertEqual(json.load(f)["version"], 7)


class Csrf(unittest.TestCase):
    def test_requires_json_custom_header_and_same_origin(self):
        ok = {"Content-Type": "application/json", "X-Observatory": "1", "Host": "utm:8765", "Origin": "http://utm:8765"}
        self.assertTrue(ls.csrf_ok(ok))
        self.assertTrue(ls.csrf_ok({k: v for k, v in ok.items() if k != "Origin"}))   # same-origin fetch may omit it
        for k, v in (("Content-Type", "text/plain"), ("X-Observatory", ""), ("Origin", "http://evil.test")):
            self.assertFalse(ls.csrf_ok(dict(ok, **{k: v})), k)


class HttpRoutes(unittest.TestCase):
    def setUp(self):
        import importlib, threading
        from http.server import ThreadingHTTPServer
        os.environ.update(OS_URL="http://127.0.0.1:9", DATA_DIR=tempfile.mkdtemp(), DASH_PASS="", BIND="127.0.0.1")
        import server
        self.server = importlib.reload(server)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), self.server.Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = "http://127.0.0.1:%d" % self.httpd.server_address[1]

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def req(self, method, path, body=None, headers=None):
        import urllib.request, urllib.error
        r = urllib.request.Request(self.base + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                   headers=headers or {})
        try:
            with urllib.request.urlopen(r) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def test_get_put_and_conflict(self):
        st, got = self.req("GET", "/api/layout")
        self.assertEqual((st, got["layout"]["version"]), (200, 0))
        h = {"Content-Type": "application/json", "X-Observatory": "1"}
        st, put = self.req("PUT", "/api/layout", {"layout": got["layout"], "base_version": 0}, h)
        self.assertEqual((st, put["layout"]["version"]), (200, 1))
        st, conflict = self.req("PUT", "/api/layout", {"layout": got["layout"], "base_version": 0}, h)
        self.assertEqual((st, conflict["error"], conflict["layout"]["version"]), (409, "conflict", 1))

    def test_put_without_custom_header_is_forbidden(self):
        st, _ = self.req("PUT", "/api/layout", {"layout": {}, "base_version": 0}, {"Content-Type": "application/json"})
        self.assertEqual(st, 403)

    def test_non_object_body_is_400_not_a_crash(self):
        h = {"Content-Type": "application/json", "X-Observatory": "1"}
        st, err = self.req("PUT", "/api/layout", [1, 2], h)
        self.assertEqual(st, 400)

    def test_get_passes_notes_through(self):
        with open(os.path.join(os.environ["DATA_DIR"], "layout.json"), "w") as f:
            json.dump(one_screen([{"type": "hologram", "x": 0, "y": 0, "w": 4, "h": 4}]), f)
        st, got = self.req("GET", "/api/layout")
        self.assertTrue(any("hologram" in n for n in got["notes"]))

    def test_bad_layout_is_400(self):
        h = {"Content-Type": "application/json", "X-Observatory": "1"}
        st, err = self.req("PUT", "/api/layout", {"layout": {"schema": 9}, "base_version": 0}, h)
        self.assertEqual(st, 400)
        self.assertIn("schema", err["error"])

if __name__ == "__main__":
    unittest.main()
