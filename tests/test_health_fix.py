"""The SIEM-health "Apply fix" button (POST /api/cluster/fix). Run: python3 -m unittest discover -s tests -v"""
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

UNASSIGNED = ["v11-alert-2026.10.19", ".opendistro-ism-managed-index-history-2026.10.19-000093", "security-auditlog-2026.10.19"]


class FakeCluster:
    """Yellow until the replica settings arrive; protected security-auditlog answers 403 like the real plugin."""
    def __init__(self):
        self.fixed, self.writes = set(), []

    def read(self, path, body=None, method="POST"):
        left = [i for i in UNASSIGNED if i not in self.fixed]
        if path.startswith("/_cluster/health"):
            return {"status": "yellow" if left else "green", "number_of_data_nodes": 1, "active_primary_shards": 9, "active_shards": 9}
        if path.startswith("/_cat/shards"):
            return [{"index": i, "shard": "0", "prirep": "r", "state": "UNASSIGNED", "unassigned.reason": "INDEX_CREATED"} for i in left]
        if path.startswith("/_cat/indices"):
            return [{"index": i, "health": "yellow", "pri": "1", "rep": "1", "pri.store.size": "10"} for i in left]
        if path.startswith("/_cluster/allocation/explain"):
            if not left:
                raise RuntimeError("no unassigned shards")
            return {"index": left[0], "shard": 0, "primary": False, "allocate_explanation": "x", "node_allocation_decisions": []}
        raise AssertionError(path)

    def write(self, path, body, method, creds=None):
        self.writes.append((method, path, body, creds))
        if path.startswith("/security-auditlog"):
            return {"error": {"reason": "no permissions for [indices:admin/settings/update]"}, "status": 403}
        for i in UNASSIGNED:
            fam = i.rsplit("-", 2)[0] if i.startswith("v11") else i
            if path.startswith("/" + i.split("-2026")[0]) or i.split("-2026")[0] in path:
                self.fixed.add(i)
        return {"acknowledged": True}


def load(**env):
    os.environ.update({"OS_URL": "http://127.0.0.1:9", "DATA_DIR": tempfile.mkdtemp(), "BIND": "127.0.0.1",
                       "DASH_PASS": "Right-Pass-123", "DASH_USER": "admin", "OS_USER": "observatory_reader",
                       "OS_FIX_USER": "observatory_fixer", "OS_FIX_PASS": "fixer-pw"}, **env)
    import server
    s = importlib.reload(server)
    c = FakeCluster()
    s.os_call = c.read
    s._call_http = c.write
    s.FIX_SETTLE_S = 0
    return s, c


class Unit(unittest.TestCase):
    def test_fix_runs_the_derived_steps_with_the_fix_account(self):
        s, c = load()
        out = s.apply_cluster_fix("1.2.3.4")
        titles = {r["title"]: r for r in out["results"]}
        self.assertTrue(any("data indices" in t and r["ok"] for t, r in titles.items()))
        self.assertTrue(any("index-management history" in t and r["ok"] for t, r in titles.items()))
        prot = next(r for t, r in titles.items() if "security-auditlog" in t)
        self.assertFalse(prot["ok"])
        self.assertIn("protected", prot["text"])
        self.assertTrue(all(w[3] == ("observatory_fixer", "fixer-pw") for w in c.writes))
        self.assertIn({"persistent": {"plugins.index_state_management.history.number_of_replicas": 0}}, [w[2] for w in c.writes])
        self.assertEqual(out["cluster"]["unassigned"], 1)           # only the protected one is left

    def test_only_allowed_request_shapes(self):
        s, _ = load()
        ok = s._fix_op_allowed
        self.assertTrue(ok({"method": "PUT", "path": "/v11-alert-*/_settings", "body": {"index": {"number_of_replicas": 0}}}))
        self.assertFalse(ok({"method": "PUT", "path": "/v11-alert-*/_settings", "body": {"index": {"blocks.read_only": True}}}))
        self.assertFalse(ok({"method": "DELETE", "path": "/v11-alert-*", "body": {}}))
        self.assertFalse(ok({"method": "PUT", "path": "/_cluster/settings", "body": {"persistent": {"cluster.routing.allocation.enable": "none"}}}))
        self.assertFalse(ok({"method": "PUT", "path": "/_plugins/_security/api/roles/x/_settings", "body": {"index": {"number_of_replicas": 0}}}))
        self.assertFalse(ok({"method": "PUT", "path": "/_template/other", "body": {}}))

    def test_read_only_installs_do_not_offer_the_button(self):
        s, _ = load(OS_FIX_USER="")
        self.assertFalse(s.can_fix())
        self.assertFalse(s.api_cluster()["can_fix"])
        s, _ = load()
        self.assertTrue(s.api_cluster()["can_fix"])


class Http(unittest.TestCase):
    def setUp(self):
        self.s, self.c = load()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), self.s.Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = "http://127.0.0.1:%d" % self.httpd.server_address[1]

    def tearDown(self):
        self.httpd.shutdown(); self.httpd.server_close()

    def post(self, body, csrf=True):
        h = {"Authorization": "Basic " + base64.b64encode(b"admin:Right-Pass-123").decode(), "Content-Type": "application/json"}
        if csrf:
            h["X-Observatory"] = "1"
        r = urllib.request.Request(self.base + "/api/cluster/fix", data=json.dumps(body).encode(), method="POST", headers=h)
        try:
            with urllib.request.urlopen(r, timeout=10) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def test_needs_csrf_header_and_the_current_password(self):
        self.assertEqual(self.post({"current_password": "Right-Pass-123"}, csrf=False)[0], 403)
        code, j = self.post({})
        self.assertEqual(code, 403)
        self.assertIn("password", j["error"])
        self.assertEqual(self.c.writes, [])
        code, j = self.post({"current_password": "Right-Pass-123"})
        self.assertEqual(code, 200, j)
        self.assertTrue(j["results"])
        self.assertTrue(self.c.writes)


if __name__ == "__main__":
    unittest.main()
