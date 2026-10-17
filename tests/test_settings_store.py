"""Live-editable settings (dashboard login, API keys, support contact, map home/sites, AI hosts).
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
import settings_store as ss  # noqa: E402


class Store(unittest.TestCase):
    def test_load_returns_empty_when_nothing_stored(self):
        self.assertEqual(ss.load(tempfile.mkdtemp()), {})

    def test_save_merges_and_get_prefers_stored_over_default(self):
        d = tempfile.mkdtemp()
        ss.save(d, {"support": "Acme|help@acme.test"})
        ss.save(d, {"home": "43.6,-79.4,Toronto"})
        self.assertEqual(ss.load(d), {"support": "Acme|help@acme.test", "home": "43.6,-79.4,Toronto"})
        self.assertEqual(ss.get(d, "home", "default"), "43.6,-79.4,Toronto")
        self.assertEqual(ss.get(d, "sites", "default"), "default")

    def test_empty_string_clears_a_key_back_to_the_default(self):
        d = tempfile.mkdtemp()
        ss.save(d, {"home": "43.6,-79.4,Toronto"})
        ss.save(d, {"home": ""})
        self.assertEqual(ss.get(d, "home", "default"), "default")   # explicitly cleared, same as never set

    def test_unknown_key_is_rejected(self):
        with self.assertRaises(ValueError):
            ss.save(tempfile.mkdtemp(), {"not_a_real_setting": "x"})

    def test_non_string_value_is_rejected(self):
        with self.assertRaises(ValueError):
            ss.save(tempfile.mkdtemp(), {"support": 123})

    def test_oversized_value_is_rejected(self):
        with self.assertRaises(ValueError):
            ss.save(tempfile.mkdtemp(), {"support": "x" * (ss.MAX_VALUE_CHARS + 1)})

    def test_corrupt_file_behaves_like_nothing_stored(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, ss.FILE), "w") as f:
            f.write("{not json")
        self.assertEqual(ss.load(d), {})

    def test_public_state_masks_secrets_but_not_plain_settings(self):
        d = tempfile.mkdtemp()
        ss.save(d, {"abuseipdb_key": "secret-key", "dash_pass": "hunter2hunter", "support": "Acme|help@acme.test"})
        state = ss.public_state(d)
        self.assertEqual(state["support"], "Acme|help@acme.test")
        self.assertNotIn("abuseipdb_key", state)
        self.assertNotIn("dash_pass", state)
        self.assertTrue(state["abuseipdb_key_configured"])
        self.assertTrue(state["dash_pass_configured"])
        self.assertFalse(state["virustotal_key_configured"])

    def test_configured_helper(self):
        d = tempfile.mkdtemp()
        self.assertFalse(ss.configured(d, "virustotal_key"))
        ss.save(d, {"virustotal_key": "k"})
        self.assertTrue(ss.configured(d, "virustotal_key"))


class HttpRoutes(unittest.TestCase):
    def setUp(self):
        os.environ.update(OS_URL="http://127.0.0.1:9", DATA_DIR=tempfile.mkdtemp(), DASH_PASS="", BIND="127.0.0.1")
        for k in ("ABUSEIPDB_KEY", "VIRUSTOTAL_KEY", "DASH_USER", "SUPPORT_CONTACT", "HOME_LOCATION", "SITE_LOCATIONS", "AI_HOSTS"):
            os.environ.pop(k, None)
        import server
        self.server = importlib.reload(server)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), self.server.Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = "http://127.0.0.1:%d" % self.httpd.server_address[1]

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def req(self, method, path, body=None, headers=None, user=None, pw=None):
        h = dict(headers or {})
        if user is not None:
            h["Authorization"] = "Basic " + base64.b64encode(("%s:%s" % (user, pw)).encode()).decode()
        r = urllib.request.Request(self.base + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                   headers=h)
        try:
            with urllib.request.urlopen(r) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read() or b"{}")
            except ValueError:
                return e.code, {}

    JSON = {"Content-Type": "application/json", "X-Observatory": "1"}

    def test_get_defaults_to_nothing_configured(self):
        st, got = self.req("GET", "/api/settings")
        self.assertEqual(st, 200)
        self.assertFalse(got["abuseipdb_key_configured"])
        self.assertFalse(got["virustotal_key_configured"])
        self.assertEqual(got["support"], "")

    def test_put_unknown_key_is_400(self):
        st, err = self.req("PUT", "/api/settings", {"made_up": "x"}, self.JSON)
        self.assertEqual(st, 400)
        self.assertIn("made_up", err["error"])

    def test_put_without_csrf_header_is_forbidden(self):
        st, _ = self.req("PUT", "/api/settings", {"support": "Acme|a@b.c"}, {"Content-Type": "application/json"})
        self.assertEqual(st, 403)

    def test_put_then_get_round_trips_a_plain_setting(self):
        st, _ = self.req("PUT", "/api/settings", {"support": "Acme|help@acme.test"}, self.JSON)
        self.assertEqual(st, 200)
        st, got = self.req("GET", "/api/settings")
        self.assertEqual(got["support"], "Acme|help@acme.test")

    def test_put_api_key_shows_as_configured_not_as_its_value(self):
        st, put = self.req("PUT", "/api/settings", {"abuseipdb_key": "sk-abc123"}, self.JSON)
        self.assertEqual(st, 200)
        self.assertTrue(put["abuseipdb_key_configured"])
        self.assertNotIn("sk-abc123", json.dumps(put))

    def test_bad_home_is_400(self):
        st, err = self.req("PUT", "/api/settings", {"home": "not-a-location"}, self.JSON)
        self.assertEqual(st, 400)

    def test_bad_sites_entry_is_400(self):
        st, err = self.req("PUT", "/api/settings", {"sites": "FW1=not-a-location"}, self.JSON)
        self.assertEqual(st, 400)

    def test_bad_ai_hosts_is_400(self):
        st, err = self.req("PUT", "/api/settings", {"ai_hosts": "just-a-name-no-ip"}, self.JSON)
        self.assertEqual(st, 400)

    def test_empty_dash_user_is_400(self):
        st, err = self.req("PUT", "/api/settings", {"dash_user": "  "}, self.JSON)
        self.assertEqual(st, 400)

    def test_short_dash_pass_is_400_and_cannot_be_cleared(self):
        st, err = self.req("PUT", "/api/settings", {"dash_pass": "short"}, self.JSON)
        self.assertEqual(st, 400)
        st, err = self.req("PUT", "/api/settings", {"dash_pass": ""}, self.JSON)
        self.assertEqual(st, 400)


class EnvDefaults(unittest.TestCase):
    """GET /api/settings shows the install.sh-set value for a field nobody has overridden live yet."""
    def setUp(self):
        os.environ.update(OS_URL="http://127.0.0.1:9", DATA_DIR=tempfile.mkdtemp(), DASH_PASS="", BIND="127.0.0.1",
                          DASH_USER="custom-admin", SUPPORT_CONTACT="Acme|help@acme.test", HOME_LOCATION="1,2,Nowhere")
        for k in ("ABUSEIPDB_KEY", "VIRUSTOTAL_KEY"):
            os.environ.pop(k, None)
        import server
        self.server = importlib.reload(server)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), self.server.Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = "http://127.0.0.1:%d" % self.httpd.server_address[1]

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        for k in ("DASH_USER", "SUPPORT_CONTACT", "HOME_LOCATION"):
            os.environ.pop(k, None)

    def test_env_values_show_until_overridden(self):
        r = urllib.request.Request(self.base + "/api/settings")
        with urllib.request.urlopen(r) as resp:
            got = json.loads(resp.read())
        self.assertEqual((got["dash_user"], got["support"], got["home"]),
                         ("custom-admin", "Acme|help@acme.test", "1,2,Nowhere"))


class LivePasswordChange(unittest.TestCase):
    """Changing the dashboard password via Settings must take effect on the very next request, no restart."""
    def setUp(self):
        os.environ.update(OS_URL="http://127.0.0.1:9", DATA_DIR=tempfile.mkdtemp(), DASH_PASS="initial-pw-123",
                          DASH_USER="admin", BIND="127.0.0.1")
        for k in ("ABUSEIPDB_KEY", "VIRUSTOTAL_KEY"):
            os.environ.pop(k, None)
        import server
        self.server = importlib.reload(server)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), self.server.Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = "http://127.0.0.1:%d" % self.httpd.server_address[1]

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def get(self, path, user, pw):
        h = {"Authorization": "Basic " + base64.b64encode(("%s:%s" % (user, pw)).encode()).decode()}
        r = urllib.request.Request(self.base + path, headers=h)
        try:
            with urllib.request.urlopen(r) as resp:
                return resp.status
        except urllib.error.HTTPError as e:
            return e.code

    def test_new_password_works_and_old_one_stops_working(self):
        self.assertEqual(self.get("/api/settings", "admin", "initial-pw-123"), 200)
        h = {"Content-Type": "application/json", "X-Observatory": "1",
             "Authorization": "Basic " + base64.b64encode(b"admin:initial-pw-123").decode()}
        r = urllib.request.Request(self.base + "/api/settings", method="PUT",
                                   data=json.dumps({"dash_pass": "brand-new-password-1"}).encode(), headers=h)
        with urllib.request.urlopen(r) as resp:
            self.assertEqual(resp.status, 200)
        self.assertEqual(self.get("/api/settings", "admin", "initial-pw-123"), 401)
        self.assertEqual(self.get("/api/settings", "admin", "brand-new-password-1"), 200)


if __name__ == "__main__":
    unittest.main()
