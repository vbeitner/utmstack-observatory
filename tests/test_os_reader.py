"""OBS-08: install.sh gives the dashboard a dedicated read-only OpenSearch user instead of UTMStack's administrator.

The installer's functions are sourced into bash and pointed at a stub of the OpenSearch security REST API, so this
runs without Docker or OpenSearch. Run: python3 -m unittest discover -s tests -v"""
import base64
import fnmatch
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INSTALL = os.path.join(ROOT, "install.sh")


def read(path):
    with open(path) as f:
        return f.read()


ADMIN, ADMIN_PASS = "admin", 'Adm"in\\Pass-1'      # quote and backslash: the curl config must escape them


class StubOpenSearch:
    """Just enough of the security REST API: health, roles, internal users, and a few read endpoints."""

    def __init__(self, security="_plugins", role_code=None, reader_denied=(), user_code=None):
        self.security, self.role_code, self.user_code = security, role_code, user_code
        self.reader_denied = reader_denied               # path prefixes the reader gets 403 on
        self.roles, self.users, self.log = {}, {}, []
        stub = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _go(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n).decode() if n else ""
                user, pw = None, None
                auth = self.headers.get("Authorization", "")
                if auth.startswith("Basic "):
                    user, _, pw = base64.b64decode(auth[6:]).decode().partition(":")
                stub.log.append((self.command, self.path, user, body))
                code, out = stub.answer(self.command, self.path, user, pw, body)
                data = json.dumps(out).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_PUT = do_POST = _go

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def answer(self, method, path, user, pw, body):
        if user == ADMIN and pw == ADMIN_PASS:
            who = "admin"
        elif user in self.users and self.users[user]["password"] == pw:
            who = "reader"
        else:
            return 401, {"error": "unauthorized"}
        sec = "/%s/_security" % self.security if self.security else None
        if sec and path == sec + "/health":
            return 200, {"status": "UP"}
        if "/_security" in path:
            if not sec or not path.startswith(sec + "/api/"):
                return 400, {"error": "no handler found for uri"}
            if who != "admin":
                return 403, {"error": "forbidden"}
            kind, _, name = path[len(sec) + 5:].partition("/")
            if method == "PUT" and kind == "roles":
                if self.role_code:
                    return self.role_code, {"error": "denied"}
                created = name not in self.roles
                self.roles[name] = json.loads(body)
                return (201 if created else 200), {"status": "CREATED" if created else "OK"}
            if method == "PUT" and kind == "internalusers":
                if self.user_code:
                    return self.user_code, {"error": "denied"}
                created = name not in self.users
                self.users[name] = json.loads(body)
                return (201 if created else 200), {"status": "CREATED" if created else "OK"}
            return 404, {"error": "not found"}
        if who == "reader" and any(path.startswith(p) for p in self.reader_denied):
            return 403, {"error": "no permissions"}
        return 200, {"status": "green"} if path.startswith("/_cluster/health") else {}

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def run_reader(stub, conf_dir, es_user=ADMIN, es_pass=ADMIN_PASS, os_account="reader", oscid="node1cid"):
    """Source install.sh, swap docker exec for a local call, run ensure_os_reader and report what it chose."""
    argv_log = os.path.join(conf_dir, "argv.log")
    script = r'''
source "$INSTALL"
in_node1() { printf '%s\n' "$*" >> "$ARGV_LOG"; "$@"; }
sleep() { :; }
SCHEME=http ES_PORT="$PORT" CONF_DIR="$CONF_DIR_IN" ES_USER="$ES_USER_IN" ES_PASS="$ES_PASS_IN" OSCID="$OSCID_IN" OS_ACCOUNT="$OS_ACCOUNT_IN"
ensure_os_reader
printf 'RESULT_USER=%s\nRESULT_PASS=%s\n' "$OS_RUN_USER" "$OS_RUN_PASS"
'''
    env = dict(os.environ, INSTALL=INSTALL, ARGV_LOG=argv_log, PORT=str(stub.port), CONF_DIR_IN=conf_dir,
               ES_USER_IN=es_user, ES_PASS_IN=es_pass, OSCID_IN=oscid, OS_ACCOUNT_IN=os_account)
    p = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stderr
    res = dict(line.split("=", 1) for line in p.stdout.splitlines() if line.startswith("RESULT_"))
    argv = read(argv_log) if os.path.exists(argv_log) else ""
    return res["RESULT_USER"], res["RESULT_PASS"], p.stderr, argv


def role_body():
    m = re.search(r"^READER_ROLE_BODY='(.*)'$", read(INSTALL), re.M)
    return json.loads(m.group(1))


@unittest.skipUnless(shutil.which("bash") and shutil.which("curl"), "needs bash and curl")
class TestOsReader(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.stubs = []

    def tearDown(self):
        for s in self.stubs:
            s.close()
        shutil.rmtree(self.dir, ignore_errors=True)

    def stub(self, **kw):
        s = StubOpenSearch(**kw)
        self.stubs.append(s)
        return s

    def test_creates_role_and_user_and_uses_them(self):
        s = self.stub()
        user, pw, err, argv = run_reader(s, self.dir)
        self.assertEqual(user, "observatory_reader")
        self.assertGreaterEqual(len(pw), 24)
        self.assertEqual(s.roles["observatory_read"], role_body())
        self.assertEqual(s.users["observatory_reader"]["password"], pw)
        self.assertEqual(s.users["observatory_reader"]["opendistro_security_roles"], ["observatory_read"])
        f = os.path.join(self.dir, "os_reader.pass")
        self.assertEqual(read(f), pw)
        self.assertEqual(os.stat(f).st_mode & 0o777, 0o600)
        # the new account was checked before it replaced the administrator's
        self.assertIn(("GET", "/_cluster/health", "observatory_reader"), [(m, p, u) for m, p, u, _ in s.log])
        # no password on any command line
        self.assertNotIn(pw, argv)
        self.assertNotIn("Pass-1", argv)

    def test_rerun_keeps_user_and_password(self):
        s = self.stub()
        first = run_reader(s, self.dir)[:2]
        second = run_reader(s, self.dir)[:2]
        self.assertEqual(first, second)
        self.assertEqual(s.users["observatory_reader"]["password"], first[1])
        self.assertEqual(list(s.users), ["observatory_reader"])

    def test_role_grants_only_read_and_monitor(self):
        r = role_body()
        self.assertEqual(r["cluster_permissions"], ["cluster:monitor/*"])
        acts = {a for p in r["index_permissions"] for a in p["allowed_actions"]}
        self.assertEqual(acts, {"read", "view_index_metadata", "indices:monitor/*"})
        for p in r["index_permissions"]:
            if p["index_patterns"] != ["v11-*"]:
                self.assertEqual(p["allowed_actions"], ["indices:monitor/*"])

    def test_opendistro_api_on_older_versions(self):
        s = self.stub(security="_opendistro")
        user, _, _, _ = run_reader(s, self.dir)
        self.assertEqual(user, "observatory_reader")
        self.assertTrue(any(p.startswith("/_opendistro/_security/api/roles/") for _, p, _, _ in s.log))

    def test_security_plugin_disabled_falls_back(self):
        s = self.stub(security=None)
        user, pw, err, _ = run_reader(s, self.dir)
        self.assertEqual((user, pw), (ADMIN, ADMIN_PASS))
        self.assertIn("security REST API is not available", err)

    def test_role_denied_falls_back(self):
        s = self.stub(role_code=403)
        user, pw, err, _ = run_reader(s, self.dir)
        self.assertEqual((user, pw), (ADMIN, ADMIN_PASS))
        self.assertIn("HTTP 403", err)
        self.assertEqual(s.users, {})

    def test_user_denied_falls_back(self):
        s = self.stub(user_code=500)
        user, _, err, _ = run_reader(s, self.dir)
        self.assertEqual(user, ADMIN)
        self.assertIn("read-only OpenSearch user (HTTP 500)", err)

    def test_reader_that_cannot_read_falls_back(self):
        s = self.stub(reader_denied=("/v11-",))
        user, _, err, _ = run_reader(s, self.dir)
        self.assertEqual(user, ADMIN)
        self.assertIn("cannot read the v11-* indices", err)

    def test_cluster_page_permission_missing_only_warns(self):
        s = self.stub(reader_denied=("/_cat/",))
        user, _, err, _ = run_reader(s, self.dir)
        self.assertEqual(user, "observatory_reader")
        self.assertIn("--os-account backend", err)

    def test_api_unreachable_falls_back(self):
        s = self.stub()
        s.close()
        self.stubs.remove(s)
        user, _, err, _ = run_reader(s, self.dir)
        self.assertEqual(user, ADMIN)

    def test_no_authentication_needs_no_user(self):
        s = self.stub()
        user, pw, _, _ = run_reader(s, self.dir, es_user="", es_pass="")
        self.assertEqual((user, pw), ("", ""))
        self.assertEqual(s.log, [])

    def test_backend_opt_out(self):
        s = self.stub()
        user, _, err, _ = run_reader(s, self.dir, os_account="backend")
        self.assertEqual(user, ADMIN)
        self.assertEqual(s.log, [])
        self.assertIn("--os-account backend", err)

    def test_node1_elsewhere_falls_back(self):
        s = self.stub()
        user, _, err, _ = run_reader(s, self.dir, oscid="")
        self.assertEqual(user, ADMIN)
        self.assertEqual(s.log, [])


# What each OpenSearch request in app/server.py needs (OpenSearch security action names), keyed by path prefix.
# A new query path makes test_role_covers_every_query fail until it is listed here and the role is checked.
SEARCH = [("index", "indices:data/read/search")]
CAT_INDICES = [("cluster", "cluster:monitor/state"), ("cluster", "cluster:monitor/health"),
               ("all", "indices:monitor/settings/get"), ("all", "indices:monitor/stats")]
REQUIRED = {
    "/_cluster/health": [("cluster", "cluster:monitor/health")],
    "/_cluster/allocation/explain": [("cluster", "cluster:monitor/allocation/explain")],
    "/_cat/shards": [("cluster", "cluster:monitor/state"), ("all", "indices:monitor/stats")],
    "/_cat/indices": CAT_INDICES,
}
NOT_CALLED = {"/_template/", "/_cluster/settings"}   # writes: only the fix account sends them (see TestFixerRole)
GROUPS = {"read": ["indices:data/read/*"],
          "view_index_metadata": ["indices:admin/get", "indices:admin/mappings/get", "indices:admin/aliases/get",
                                  "indices:monitor/settings/get", "indices:admin/resolve/index"]}


def allowed(role, kind, action, index):
    if kind == "cluster":
        return any(fnmatch.fnmatchcase(action, p) for p in role["cluster_permissions"])
    for perm in role["index_permissions"]:
        if not any(fnmatch.fnmatchcase(index, p) for p in perm["index_patterns"]):
            continue
        for a in perm["allowed_actions"]:
            if any(fnmatch.fnmatchcase(action, p) for p in GROUPS.get(a, [a])):
                return True
    return False


class TestRoleCoversQueries(unittest.TestCase):
    def test_role_covers_every_query(self):
        src = read(os.path.join(ROOT, "app", "server.py"))
        paths = set(re.findall(r'"(/(?:v11-|_)[^"]*)"', src))
        self.assertGreater(len(paths), 8)
        role = role_body()
        for path in sorted(paths):
            if any(path.startswith(p) for p in NOT_CALLED):
                continue
            if path.startswith("/v11-"):
                index = path[1:].split("/")[0].replace("%s", "x")
                self.assertTrue(index.startswith("v11-"), path)
                for kind, action in SEARCH:
                    self.assertTrue(allowed(role, kind, action, index), "%s needs %s" % (path, action))
                continue
            key = next((k for k in REQUIRED if path.startswith(k)), None)
            self.assertIsNotNone(key, "server.py calls %s: add it to REQUIRED and check the role" % path)
            for kind, action in REQUIRED[key]:
                for index in ("v11-alert-2026.10.19", ".hidden-index", "other-index"):
                    self.assertTrue(allowed(role, kind, action, index), "%s needs %s on %s" % (path, action, index))


def fixer_role_body():
    m = re.search(r"^FIXER_ROLE_BODY='(.*)'$", read(INSTALL), re.M)
    return json.loads(m.group(1))


class TestFixerRole(unittest.TestCase):
    """The fix account may do exactly what the "Apply fix" button sends, and nothing that reads or deletes data."""
    def test_covers_the_fix_requests_only(self):
        role = fixer_role_body()
        for kind, action, index in (("cluster", "cluster:admin/settings/update", None),
                                    ("cluster", "indices:admin/template/put", None),
                                    ("index", "indices:admin/settings/update", "v11-alert-2026.10.19"),
                                    ("index", "indices:admin/settings/update", ".opendistro-ism-managed-index-history-2026.10.19")):
            self.assertTrue(allowed(role, kind, action, index), action)
        for kind, action, index in (("index", "indices:data/read/search", "v11-alert-x"), ("index", "indices:admin/delete", "v11-alert-x"),
                                    ("index", "indices:data/write/index", "v11-alert-x"), ("cluster", "cluster:admin/opendistro/security/x", None),
                                    ("cluster", "cluster:admin/snapshot/delete", None)):
            self.assertFalse(allowed(role, kind, action, index), action)


@unittest.skipUnless(shutil.which("bash") and shutil.which("curl"), "needs bash and curl")
class TestOsFixer(unittest.TestCase):
    def run_both(self, stub, conf_dir, health_fix="1"):
        script = r'''
source "$INSTALL"
in_node1() { "$@"; }
sleep() { :; }
SCHEME=http ES_PORT="$PORT" CONF_DIR="$CONF_DIR_IN" ES_USER="$ES_USER_IN" ES_PASS="$ES_PASS_IN" OSCID=node1 OS_ACCOUNT=reader HEALTH_FIX="$HF"
ensure_os_reader
ensure_os_fixer
printf 'RESULT_USER=%s\nRESULT_FIX=%s\nRESULT_FIXPW=%s\n' "$OS_RUN_USER" "$OS_FIX_RUN_USER" "$OS_FIX_RUN_PASS"
'''
        env = dict(os.environ, INSTALL=INSTALL, PORT=str(stub.port), CONF_DIR_IN=conf_dir, ES_USER_IN=ADMIN,
                   ES_PASS_IN=ADMIN_PASS, HF=health_fix)
        p = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        return dict(line.split("=", 1) for line in p.stdout.splitlines() if line.startswith("RESULT_")), p.stderr

    def test_creates_the_fix_user_next_to_the_reader(self):
        d = tempfile.mkdtemp()
        s = StubOpenSearch()
        try:
            r, err = self.run_both(s, d)
            self.assertEqual(r["RESULT_USER"], "observatory_reader")
            self.assertEqual(r["RESULT_FIX"], "observatory_fixer")
            self.assertEqual(s.roles["observatory_health_fix"], fixer_role_body())
            self.assertEqual(s.users["observatory_fixer"]["opendistro_security_roles"], ["observatory_health_fix"])
            self.assertEqual(read(os.path.join(d, "os_fixer.pass")), r["RESULT_FIXPW"])
            again, _ = self.run_both(s, d)
            self.assertEqual(again["RESULT_FIXPW"], r["RESULT_FIXPW"])     # re-runs keep the password
            off, _ = self.run_both(s, d, health_fix="0")
            self.assertEqual(off["RESULT_FIX"], "")                   # --no-health-fix: no button, commands only
        finally:
            s.close()
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
