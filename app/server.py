#!/usr/bin/env python3
# Copyright (c) 2026 Victor Beitner. All rights reserved. See LICENSE.
"""UTMStack Observatory: a read-only operations dashboard for a UTMStack SIEM.

Reads from UTMStack's OpenSearch (events, alerts, ingest statistics) and keeps 30 days of hourly
aggregates in a local SQLite file. Python standard library only.

Configuration is by environment variable (see README.md). Secrets can be given as NAME or as
NAME_FILE (path to a file, e.g. a Docker secret under /run/secrets).
"""
import base64, hashlib, hmac, json, os, re, shutil, socket, ssl, subprocess, sys, threading, time
import urllib.error, urllib.request
from datetime import datetime, timedelta, timezone
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "1.22.0"
HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:                          # the container runs "python3 -I", which leaves this folder off sys.path
    sys.path.insert(0, HERE)
import layout_store  # noqa: E402  (needs the path above)
import settings_store  # noqa: E402
import reports  # noqa: E402
import geoip  # noqa: E402
import users_store  # noqa: E402
import mailer  # noqa: E402


def env(name, default=""):
    return os.environ.get(name, default).strip()


def secret(name):
    f = env(name + "_FILE")
    if f and os.path.exists(f):
        with open(f) as fh:
            return fh.read().strip()
    return env(name)


OS_URL = env("OS_URL").rstrip("/")             # e.g. https://node1:9200 ; empty = docker-exec transport
OS_USER, OS_PASS = env("OS_USER"), secret("OS_PASS")
# Narrow write account for the SIEM-health "Apply fix" button only (index replica settings, cluster settings,
# index templates); everything else reads with OS_USER. Unset = the button is offered only when OS_USER can write.
OS_FIX_USER, OS_FIX_PASS = env("OS_FIX_USER"), secret("OS_FIX_PASS")
DATA_DIR = env("DATA_DIR", HERE)
DASH_USER, DASH_PASS = env("DASH_USER", "admin"), secret("DASH_PASS")        # install-time defaults;
ABUSEIPDB_KEY = secret("ABUSEIPDB_KEY")        # current_*() below is what every request actually uses --
VIRUSTOTAL_KEY = secret("VIRUSTOTAL_KEY")      # it prefers whatever was saved live over these
PORT = int(env("PORT", "8765"))
BIND = env("BIND") or env("HOST") or ("0.0.0.0" if (DASH_PASS or settings_store.configured(DATA_DIR, "dash_pass")
                                                     or users_store.has_users(DATA_DIR)) else "127.0.0.1")
TLS_CERT, TLS_KEY = env("TLS_CERT"), env("TLS_KEY")
DISK_PATH = env("DISK_PATH", "/utmstack" if os.path.isdir("/utmstack") else "/")
HOST_NAME = env("HOST_NAME") or os.uname().nodename
TRANSPORT = "http" if OS_URL else "docker-exec"
REFRESH_S = 4
REQUEST_TIMEOUT_S = float(env("REQUEST_TIMEOUT_S", "15"))
MAX_CONNECTIONS = int(env("MAX_CONNECTIONS", "64") or "0")   # 0 = unlimited
MAX_CONNECTIONS_PER_IP = int(env("MAX_CONNECTIONS_PER_IP", "32") or "0")
HEADER_DEADLINE_S = float(env("HEADER_DEADLINE_S", "10"))      # whole request line + headers, not per read
ALLOWED_HOSTS = {h.strip().lower() for h in env("ALLOWED_HOSTS").split(",") if h.strip()}
OS_CA_FILE = env("OS_CA_FILE")                  # verify OpenSearch's certificate against this CA (default: no check)
DOCKER = ["sudo", "-n", "docker"]               # docker-exec transport only (bare-metal installs)


def current_dash_user():
    return settings_store.get(DATA_DIR, "dash_user") or DASH_USER


def current_dash_pass():
    """The stored credential: a pbkdf2 hash when saved from the Settings panel, else the installer's password.
    Only for "is a login configured?" checks -- compare passwords with check_password()."""
    return settings_store.get(DATA_DIR, "dash_pass") or DASH_PASS


PBKDF2_ITER = 600_000
_verified = {}                                   # hmac(pw) -> (stored credential, time); avoids a pbkdf2 per poll
_VERIFY_KEY = os.urandom(32)
VERIFY_TTL_S = 300


def hash_password(pw):
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, PBKDF2_ITER)
    return "pbkdf2_sha256$%d$%s$%s" % (PBKDF2_ITER, salt.hex(), dk.hex())


def check_password(pw):
    stored = current_dash_pass()
    if not stored:
        return True
    if not stored.startswith("pbkdf2_sha256$"):
        return hmac.compare_digest(pw.encode(), stored.encode())
    tag = hmac.new(_VERIFY_KEY, pw.encode(), "sha256").digest()
    hit = _verified.get(tag)
    if hit and hit[0] == stored and time.time() - hit[1] < VERIFY_TTL_S:
        return True
    try:
        _, it, salt, want = stored.split("$")
        ok = hmac.compare_digest(hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), int(it)).hex(), want)
    except ValueError:
        return False
    if ok:
        if len(_verified) > 64:
            _verified.clear()
        _verified[tag] = (stored, time.time())
    return ok


def password_ok(user, pw):
    """The break-glass login: the installer's (or Settings panel's) username and password."""
    if not current_dash_pass() or not isinstance(user, str) or not isinstance(pw, str):
        return False
    ok_u = hmac.compare_digest(user.encode(), current_dash_user().encode())
    ok_p = check_password(pw)                   # always run, so a wrong username takes as long as a wrong password
    return ok_u and ok_p


def migrate_plain_password():
    """Settings saved by versions before 1.16 held the password in clear text; hash it in place."""
    raw = settings_store.get(DATA_DIR, "dash_pass")
    if raw and not raw.startswith("pbkdf2_sha256$"):
        settings_store.save(DATA_DIR, {"dash_pass": hash_password(raw)})
        print("settings: stored dashboard password converted to a pbkdf2 hash", flush=True)


def current_abuseipdb_key():
    return settings_store.get(DATA_DIR, "abuseipdb_key") or ABUSEIPDB_KEY


def current_virustotal_key():
    return settings_store.get(DATA_DIR, "virustotal_key") or VIRUSTOTAL_KEY


def current_report_hour():
    """0-23 (UTC) to auto-generate a daily report at that hour, or None: scheduling is off until set."""
    raw = settings_store.get(DATA_DIR, "report_hour")
    return int(raw) if raw and raw.isdigit() and 0 <= int(raw) <= 23 else None


_state = {"data": {"error": "starting"}, "cid": None}
_lock = threading.Lock()
if OS_CA_FILE:
    _ctx = ssl.create_default_context(cafile=OS_CA_FILE)
    _ctx.check_hostname = env("OS_CHECK_HOSTNAME", "1") == "1"
else:
    _ctx = ssl.create_default_context()
    _ctx.check_hostname = False                 # OpenSearch inside UTMStack uses its own self-signed certificate
    _ctx.verify_mode = ssl.CERT_NONE            # (set OS_CA_FILE to verify it)


def sh(args, **kw):
    return subprocess.run(args, capture_output=True, text=True, timeout=kw.pop("timeout", 30), **kw)


def get_password():                             # docker-exec transport: read it from the backend service spec
    out = sh(DOCKER + ["service", "inspect", "utmstack_backend", "--format",
                       "{{range .Spec.TaskTemplate.ContainerSpec.Env}}{{println .}}{{end}}"]).stdout
    for line in out.splitlines():
        if line.startswith("ELASTICSEARCH_PASSWORD="):
            return line.split("=", 1)[1]
    raise RuntimeError("ELASTICSEARCH_PASSWORD not found in utmstack_backend spec")


def container_id():
    if not _state["cid"]:
        _state["cid"] = sh(DOCKER + ["ps", "-q", "-f", "name=utmstack_node1"]).stdout.split()[0]
    return _state["cid"]


def _call_exec(path, body, method):
    if not re.fullmatch(r"/[A-Za-z0-9_*.,/?=&:-]*", path) or method not in ("GET", "POST", "PUT"):
        raise ValueError("refusing unexpected OpenSearch path")   # it goes into a shell string below
    # Password goes in on stdin, never on the command line: sudo logs command lines.
    cmd = DOCKER + ["exec", "-i", container_id(), "sh", "-c",
                    'read -r PW; curl -sk -m 25 -X %s -u "admin:$PW" -H "Content-Type: application/json" '
                    '--data-binary @- "https://localhost:9200%s"' % (method, path)]
    r = sh(cmd, input=OS_PASS + "\n" + json.dumps(body or {}), timeout=40)
    if r.returncode != 0:
        _state["cid"] = None
        raise RuntimeError("docker exec failed: " + r.stderr.strip()[:200])
    return json.loads(r.stdout)


def _call_http(path, body, method, creds=None):
    data = None if method == "GET" else json.dumps(body or {}).encode()
    req = urllib.request.Request(OS_URL + path, data=data, method=method, headers={"Content-Type": "application/json"})
    user, pw = creds or (OS_USER, OS_PASS)
    if user:
        req.add_header("Authorization", "Basic " + base64.b64encode(("%s:%s" % (user, pw)).encode()).decode())
    try:
        with urllib.request.urlopen(req, timeout=25, context=_ctx) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        raw = e.read()
        if e.code == 401:
            raise RuntimeError("OpenSearch rejected the credentials (HTTP 401); check OS_USER / OS_PASS")
        try:
            return json.loads(raw)
        except ValueError:
            raise RuntimeError("OpenSearch HTTP %d" % e.code)


def os_call(path, body=None, method="POST"):
    res = _call_exec(path, body, method) if TRANSPORT == "docker-exec" else _call_http(path, body, method)
    if isinstance(res, dict) and "error" in res:
        raise RuntimeError(str(res["error"])[:300])
    return res




def rng(gte, lt=None):
    r = {"gte": gte}
    if lt:
        r["lt"] = lt
    return {"range": {"@timestamp": r}}


def minute_hist(start="now-61m/m"):
    return {"filter": rng(start, "now/m"),
            "aggs": {"h": {"date_histogram": {"field": "@timestamp", "fixed_interval": "1m",
                                               "min_doc_count": 0,
                                               "extended_bounds": {"min": "now-61m/m", "max": "now/m"}}}}}


# Hosts whose firewall-visible traffic is reported on the "AI Traffic" tab, e.g. AI_HOSTS="gx10=10.0.2.34,webai=10.0.2.17".
# Needs Sophos XG firewall logs in UTMStack. Empty = feature off.
AI_HOSTS = dict(p.strip().split("=", 1) for p in env("AI_HOSTS").split(",") if "=" in p)


def current_ai_hosts():
    raw = settings_store.get(DATA_DIR, "ai_hosts")
    if raw is None:
        return AI_HOSTS
    return dict(p.strip().split("=", 1) for p in raw.split(",") if "=" in p)


def _bytes_script(field):
    # Sophos stores numbers as quoted text, e.g. "1234"; parse defensively.
    return {"script": {"lang": "painless", "source":
            "def v=doc['log.%s.keyword']; if(v.size()==0) return 0L; "
            "try { return Long.parseLong(v.value.replace('\"','').trim()); } catch(Exception e) { return 0L; }" % field}}


def _sums():
    return {"sent": {"sum": _bytes_script("bytes_sent")}, "recv": {"sum": _bytes_script("bytes_received")}}


def ai_traffic():
    ai_hosts = current_ai_hosts()
    if not ai_hosts:
        return {"configured": False}
    ip2name = {ip: n for n, ip in ai_hosts.items()}
    quoted = [json.dumps(ip) for ip in ai_hosts.values()]   # log values carry literal quotes
    ranged = {"range": {"@timestamp": {"gte": "now-24h"}}}
    hist = {"date_histogram": {"field": "@timestamp", "fixed_interval": "1h", "min_doc_count": 0,
                               "extended_bounds": {"min": "now-24h/h", "max": "now/h"}},
            "aggs": _sums()}

    def side(ai_field, peer_field, peer_country):
        return {"filter": {"terms": {"log.%s.keyword" % ai_field: quoted}},
                "aggs": dict(_sums(), **{
                    "hosts": {"terms": {"field": "log.%s.keyword" % ai_field, "size": 10}, "aggs": _sums()},
                    "peers": {"terms": {"field": "log.%s.keyword" % peer_field, "size": 8}, "aggs": dict(_sums(), c={
                        "terms": {"field": "log.%s.keyword" % peer_country, "size": 1}})},
                    "ports": {"terms": {"field": "log.dst_port.keyword", "size": 6}},
                    "hist": hist}),
                }

    res = os_call("/v11-log-firewall-sophos-xg-*/_search", {
        "size": 0, "track_total_hits": True,
        "query": {"bool": {"filter": [ranged], "should": [
            {"terms": {"log.dst_ip.keyword": quoted}}, {"terms": {"log.src_ip.keyword": quoted}}],
            "minimum_should_match": 1}},
        "aggs": {"to_ai": side("dst_ip", "src_ip", "src_country"), "from_ai": side("src_ip", "dst_ip", "dst_country")}})
    a = res["aggregations"]
    to_ai, from_ai = a["to_ai"], a["from_ai"]
    clean = lambda s: str(s).strip('"')

    # Direction is relative to the AI host: "in" = bytes the AI host received, "out" = bytes it sent.
    # Sophos: bytes_sent = originator -> responder, bytes_received = responder -> originator.
    hosts = {n: {"name": n, "ip": ip, "in": 0, "out": 0, "conn_in": 0, "conn_out": 0} for n, ip in ai_hosts.items()}
    for b in to_ai["hosts"]["buckets"]:
        h = hosts.get(ip2name.get(clean(b["key"])))
        if h:
            h["in"] += b["sent"]["value"]; h["out"] += b["recv"]["value"]; h["conn_in"] += b["doc_count"]
    for b in from_ai["hosts"]["buckets"]:
        h = hosts.get(ip2name.get(clean(b["key"])))
        if h:
            h["out"] += b["sent"]["value"]; h["in"] += b["recv"]["value"]; h["conn_out"] += b["doc_count"]

    peers = {}
    for side_, inb in ((to_ai, True), (from_ai, False)):
        for b in side_["peers"]["buckets"]:
            ip = clean(b["key"])
            p = peers.setdefault(ip, {"ip": ip, "country": "", "conns": 0, "in": 0, "out": 0, "dir": set()})
            p["conns"] += b["doc_count"]
            p["in"] += b["sent"]["value"] if inb else b["recv"]["value"]
            p["out"] += b["recv"]["value"] if inb else b["sent"]["value"]
            p["dir"].add("in" if inb else "out")
            if b["c"]["buckets"] and not p["country"]:
                p["country"] = clean(b["c"]["buckets"][0]["key"])
    top_peers = sorted(peers.values(), key=lambda p: (p["in"] + p["out"], p["conns"]), reverse=True)[:5]
    for p in top_peers:
        p["dir"] = "both" if len(p["dir"]) == 2 else next(iter(p["dir"]))

    port_counts = {}
    for side_ in (to_ai, from_ai):
        for b in side_["ports"]["buckets"]:
            port_counts[clean(b["key"])] = port_counts.get(clean(b["key"]), 0) + b["doc_count"]
    top_ports = [{"port": p, "count": c} for p, c in sorted(port_counts.items(), key=lambda x: -x[1])[:5]]

    hours = {}
    for b in to_ai["hist"]["buckets"]:
        h = hours.setdefault(b["key"], {"t": b["key"], "in": 0, "out": 0})
        h["in"] += b["sent"]["value"]; h["out"] += b["recv"]["value"]
    for b in from_ai["hist"]["buckets"]:
        h = hours.setdefault(b["key"], {"t": b["key"], "in": 0, "out": 0})
        h["out"] += b["sent"]["value"]; h["in"] += b["recv"]["value"]

    return {
        "configured": True,
        "hosts": list(hosts.values()),
        "in": sum(h["in"] for h in hosts.values()), "out": sum(h["out"] for h in hosts.values()),
        "conn_in": to_ai["doc_count"], "conn_out": from_ai["doc_count"],
        "peers": top_peers,
        "ports": top_ports,
        "hourly": [hours[k] for k in sorted(hours)],
    }


RANGES_H = (1, 6, 24)                           # selectable dashboard windows; 24 h is the live default


def collect(hours=24):
    span = "now-%dh" % hours
    logs = os_call("/v11-log-*/_search", {
        "size": 0, "track_total_hits": True, "query": rng(span),
        "aggs": {
            "types": {"terms": {"field": "dataType.keyword", "size": 8}},
            "ds": {"terms": {"field": "dataSource.keyword", "size": 200},
                   "aggs": {"last": {"max": {"field": "@timestamp"}},
                            "types": {"terms": {"field": "dataType.keyword", "size": 1}}}},
            "recent": minute_hist(),
            "latest": {"max": {"field": "@timestamp"}},
        }})
    prev = os_call("/v11-log-*/_count", {"query": rng("now-%dh" % (2 * hours), span)})
    alerts = os_call("/v11-alert-*/_search", {
        "size": 14, "track_total_hits": True, "query": rng(span), "sort": [{"@timestamp": "desc"}],
        "_source": ["@timestamp", "name", "severityLabel", "dataSource", "dataType", "statusLabel",
                    "description", "events", "target", "adversary", "technique"],
        "aggs": {
            "sev": {"terms": {"field": "severityLabel.keyword"}},
            "rules": {"terms": {"field": "name.keyword", "size": 5},
                      "aggs": {"sev": {"terms": {"field": "severityLabel.keyword", "size": 1}}}},
            "recent": minute_hist(),
        }})
    health = os_call("/_cluster/health", method="GET")
    try:
        ai = ai_traffic()
    except Exception as e:  # AI panel is optional; never take down the rest of the dashboard
        ai = {"error": str(e)[:200]}

    now = time.time()
    latest = logs["aggregations"]["latest"].get("value")
    lag = max(0, now - latest / 1000) if latest else None

    ev_min = {b["key"]: b["doc_count"] for b in logs["aggregations"]["recent"]["h"]["buckets"]}
    al_min = {b["key"]: b["doc_count"] for b in alerts["aggregations"]["recent"]["h"]["buckets"]}
    keys = sorted(ev_min)[:-1] if len(ev_min) > 60 else sorted(ev_min)   # drop partial/odd edge bucket
    keys = keys[-60:]
    minutes = [{"t": k, "events": ev_min.get(k, 0), "alerts": al_min.get(k, 0)} for k in keys]

    if hours == 24:                              # the source list behind the drill-downs is always 24 h
        _state["ds"] = [{"name": b["key"], "docs": b["doc_count"], "last": b["last"].get("value") or 0,
                         "type": (b["types"]["buckets"][0]["key"] if b["types"]["buckets"] else "")}
                        for b in logs["aggregations"]["ds"]["buckets"]]
    stale_cut = (now - 600) * 1000
    ds = logs["aggregations"]["ds"]["buckets"]
    online = [b for b in ds if (b["last"].get("value") or 0) >= stale_cut]
    stale = [b["key"] for b in ds if (b["last"].get("value") or 0) < stale_cut]

    sev = {b["key"]: b["doc_count"] for b in alerts["aggregations"]["sev"]["buckets"]}
    last5 = [m["events"] for m in minutes[-5:]]
    peak = max(minutes, key=lambda m: m["events"]) if minutes else None

    def alert_row(h):
        s = h["_source"]
        evs = s.get("events") or []
        ev0 = evs[0] if evs else {}
        adv, tgt = s.get("adversary") or {}, s.get("target") or {}
        origin = ev0.get("origin") or {}
        ip, loc = alert_ip_loc(adv, origin, tgt)
        technique = s.get("technique") or ""
        return {"id": h["_id"], "t": s.get("@timestamp"), "sev": s.get("severityLabel") or "Low",
                "source": s.get("dataSource") or s.get("dataType") or "-", "name": s.get("name") or "-",
                "status": s.get("statusLabel") or "Open", "desc": s.get("description") or "",
                "affected": len(evs), "ip": ip, "lat": loc[0], "lon": loc[1],
                "technique": technique if technique != "Indeterminate" else ""}

    return {
        "now": datetime.now(timezone.utc).isoformat(),
        "range_h": hours,
        "minutes": minutes,
        "kpi": {
            "sources_online": len(online), "sources_total": len(ds), "sources_stale": stale[:6],
            "events_24h": logs["hits"]["total"]["value"], "events_prev_24h": prev["count"],
            "alerts_24h": alerts["hits"]["total"]["value"], "sev": sev,
            "lag_s": lag, "eps_5m": (sum(last5) / len(last5) / 60) if last5 else 0,
            "peak": {"t": peak["t"], "n": peak["events"]} if peak else None,
        },
        "types": [{"name": b["key"], "count": b["doc_count"]} for b in logs["aggregations"]["types"]["buckets"]],
        "rules": [{"name": b["key"], "count": b["doc_count"],
                   "sev": (b["sev"]["buckets"][0]["key"] if b["sev"]["buckets"] else "Low")}
                  for b in alerts["aggregations"]["rules"]["buckets"]],
        "alerts": [alert_row(h) for h in alerts["hits"]["hits"]],
        "cluster": {"status": health.get("status"), "unassigned": health.get("unassigned_shards"), "nodes": health.get("number_of_nodes"),
                    "active_pct": health.get("active_shards_percent_as_number")},
        "host": host_stats(),
        "ai": ai,
    }


def host_stats():
    cores = os.cpu_count() or 1
    load1 = float(open("/proc/loadavg").read().split()[0])
    mem = {}
    for line in open("/proc/meminfo"):
        k, v = line.split(":")
        mem[k] = int(v.split()[0]) * 1024
    used = mem["MemTotal"] - mem["MemAvailable"]
    du = shutil.disk_usage(DISK_PATH)
    gb = 1024 ** 3
    return {"hostname": HOST_NAME, "cores": cores, "load1": load1,
            "cpu_pct": min(100.0, load1 / cores * 100),
            "mem_used_gb": used / gb, "mem_total_gb": mem["MemTotal"] / gb, "mem_pct": used / mem["MemTotal"] * 100,
            "disk_used_gb": du.used / gb, "disk_total_gb": du.total / gb, "disk_pct": du.used / du.total * 100}


# ---------------------------------------------------------------------------
# History: hourly aggregates kept for RETAIN_DAYS in a local SQLite file, because
# OpenSearch only retains ~1 day of logs/alerts. Aggregates only; no raw events.
# ---------------------------------------------------------------------------
import sqlite3

os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "history.db")
RETAIN_DAYS = 30
HOUR_MS = 3600 * 1000
SYNC_EVERY_S = 300
_db = None
_dblock = threading.Lock()
METRICS = ("events", "alerts", "sev_high", "ai_in", "ai_out")


def db():
    global _db
    if _db is None:
        _db = sqlite3.connect(DB_PATH, check_same_thread=False)
        _db.execute("CREATE TABLE IF NOT EXISTS hourly(hour INTEGER PRIMARY KEY, events INTEGER, alerts INTEGER,"
                    " sev_high INTEGER, sev_med INTEGER, sev_low INTEGER, ai_in REAL, ai_out REAL, ai_conn INTEGER, src TEXT)")
        _db.execute("CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT)")
        _db.execute("CREATE TABLE IF NOT EXISTS storage(day TEXT, fam TEXT, bytes INTEGER, docs INTEGER, PRIMARY KEY(day, fam))")
        _db.commit()
    return _db


def _hist(extra=None):
    h = {"date_histogram": {"field": "@timestamp", "fixed_interval": "1h", "min_doc_count": 1}}
    if extra:
        h["aggs"] = extra
    return h


def _safe(path, body):
    try:
        return os_call(path + "?ignore_unavailable=true&allow_no_indices=true", body)
    except Exception as e:
        print("history query failed:", path, str(e)[:160], flush=True)
        return None


def fetch_hourly(gte):
    rq = {"range": {"@timestamp": {"gte": gte, "lt": "now/h"}}}      # complete hours only
    out = {"logs": {}, "stats": {}, "alerts": {}, "ai": {}}
    r = _safe("/v11-log-*/_search", {"size": 0, "query": rq, "aggs": {"h": _hist()}})
    if r:
        out["logs"] = {b["key"]: b["doc_count"] for b in r["aggregations"]["h"]["buckets"]}
    r = _safe("/v11-statistics-*/_search", {"size": 0, "query": {"bool": {"filter": [
        rq, {"term": {"type.keyword": "enqueue_success"}}]}},
        "aggs": {"h": _hist({"n": {"sum": {"field": "count"}}})}})
    if r:
        out["stats"] = {b["key"]: int(b["n"]["value"]) for b in r["aggregations"]["h"]["buckets"]}
    r = _safe("/v11-alert-*/_search", {"size": 0, "query": rq, "aggs": {"h": _hist(
        {"sev": {"terms": {"field": "severityLabel.keyword", "size": 5}}})}})
    if r:
        for b in r["aggregations"]["h"]["buckets"]:
            sev = {s["key"]: s["doc_count"] for s in b["sev"]["buckets"]}
            out["alerts"][b["key"]] = {"n": b["doc_count"], "high": sev.get("High", 0) + sev.get("Critical", 0),
                                       "med": sev.get("Medium", 0), "low": sev.get("Low", 0)}
    ai_hosts = current_ai_hosts()
    if not ai_hosts:
        return out
    quoted = [json.dumps(ip) for ip in ai_hosts.values()]
    r = _safe("/v11-log-firewall-sophos-xg-*/_search", {"size": 0, "query": {"bool": {"filter": [rq], "should": [
        {"terms": {"log.dst_ip.keyword": quoted}}, {"terms": {"log.src_ip.keyword": quoted}}], "minimum_should_match": 1}},
        "aggs": {"to": {"filter": {"terms": {"log.dst_ip.keyword": quoted}}, "aggs": {"h": _hist(_sums())}},
                 "frm": {"filter": {"terms": {"log.src_ip.keyword": quoted}}, "aggs": {"h": _hist(_sums())}}}})
    if r:
        for b in r["aggregations"]["to"]["h"]["buckets"]:        # AI host is the destination
            a = out["ai"].setdefault(b["key"], [0, 0, 0]); a[0] += b["sent"]["value"]; a[1] += b["recv"]["value"]; a[2] += b["doc_count"]
        for b in r["aggregations"]["frm"]["h"]["buckets"]:       # AI host is the source
            a = out["ai"].setdefault(b["key"], [0, 0, 0]); a[1] += b["sent"]["value"]; a[0] += b["recv"]["value"]; a[2] += b["doc_count"]
    return out


def sync_history():
    with _dblock:
        full = db().execute("SELECT v FROM meta WHERE k='backfilled'").fetchone() is None
    d = fetch_hourly("now-%dd/d" % RETAIN_DAYS if full else "now-48h/h")
    hours = set(d["logs"]) | set(d["stats"]) | set(d["alerts"]) | set(d["ai"])
    with _dblock:
        c = db()
        for h in sorted(hours):
            old = c.execute("SELECT events,alerts,sev_high,sev_med,sev_low,ai_in,ai_out,ai_conn,src FROM hourly WHERE hour=?", (h,)).fetchone()
            ev, al, hi, me, lo, ain, aout, aconn, src = old if old else (None,) * 9
            if d["logs"].get(h):
                ev, src = d["logs"][h], "live"
                al, hi, me, lo = 0, 0, 0, 0                      # live hour: no alert docs means zero alerts
                ain, aout, aconn = 0.0, 0.0, 0
            elif d["stats"].get(h) and src != "live":
                ev, src = d["stats"][h], "stats"
            if h in d["alerts"]:
                a = d["alerts"][h]; al, hi, me, lo = a["n"], a["high"], a["med"], a["low"]
            if h in d["ai"]:
                ain, aout, aconn = d["ai"][h]
            c.execute("INSERT OR REPLACE INTO hourly VALUES (?,?,?,?,?,?,?,?,?,?)", (h, ev, al, hi, me, lo, ain, aout, aconn, src))
        c.execute("DELETE FROM hourly WHERE hour < ?", (int(time.time() * 1000) - RETAIN_DAYS * 24 * HOUR_MS,))
        if full and hours:
            c.execute("INSERT OR REPLACE INTO meta VALUES ('backfilled', ?)", (datetime.now(timezone.utc).isoformat(),))
        c.commit()


_IDX_RE = re.compile(r"^(v11-alert|v11-log-[a-z0-9-]+?)-(\d{4})[-.](\d{2})[-.](\d{2})$")


def snapshot_storage():
    """Record the on-disk size of each day's alert/log indices (primary shards; this is a
    single-node cluster so replicas are unassigned). Kept after OpenSearch deletes the index."""
    rows = os_call("/_cat/indices/v11-alert-*,v11-log-*?h=index,docs.count,pri.store.size&bytes=b&format=json", method="GET")
    agg = {}
    for r in rows:
        m = _IDX_RE.match(r["index"])
        if not m:
            continue
        day = "%s-%s-%s" % m.groups()[1:]
        fam = "alerts" if m.group(1) == "v11-alert" else "logs"
        a = agg.setdefault((day, fam), [0, 0])
        a[0] += int(r["pri.store.size"] or 0); a[1] += int(r["docs.count"] or 0)
    cutoff = (datetime.now(timezone.utc) - timedelta(days=RETAIN_DAYS)).strftime("%Y-%m-%d")
    with _dblock:
        c = db()
        for (day, fam), (b, d) in agg.items():
            old = c.execute("SELECT bytes, docs FROM storage WHERE day=? AND fam=?", (day, fam)).fetchone()
            c.execute("INSERT OR REPLACE INTO storage VALUES (?,?,?,?)", (day, fam, max(b, old[0] if old else 0), max(d, old[1] if old else 0)))
        c.execute("DELETE FROM storage WHERE day < ?", (cutoff,))
        c.commit()


def api_storage():
    with _dblock:
        rows = db().execute("SELECT day, fam, bytes, docs FROM storage ORDER BY day").fetchall()
    byday = {}
    for day, fam, b, d in rows:
        e = byday.setdefault(day, {"day": day, "alerts": 0, "alert_docs": 0, "logs": 0, "log_docs": 0})
        e[fam] = b; e["alert_docs" if fam == "alerts" else "log_docs"] = d
    days = sorted(byday.values(), key=lambda x: x["day"])[-RETAIN_DAYS:]
    for e in days:
        e["total"] = e["alerts"] + e["logs"]
        e["per_alert"] = e["alerts"] / e["alert_docs"] if e["alert_docs"] else None
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    done = [e for e in days if e["day"] != today]
    basis = done if done else days
    avg = sum(e["total"] for e in basis) / len(basis) if basis else None
    du = shutil.disk_usage(DISK_PATH)
    return {"days": days, "today_utc": today, "avg_daily_total": avg, "avg_basis": "complete days" if done else "today so far (partial day)",
            "avg_daily_alerts": (sum(e["alerts"] for e in basis) / len(basis)) if basis else None,
            "disk_free": du.free, "disk_total": du.total, "disk_used": du.used,
            "days_left": (du.free / avg) if avg else None,
            "note": "Sizes are primary shards in OpenSearch; index days are UTC. A day is final once its index is closed out."}


def report_trend(hours):
    """Hourly event counts for the last `hours` from the same local history the Trends drawer reads --
    data_for()'s own "minutes" series only ever covers the last 60 minutes, too short for a 24 h report."""
    cutoff = int(time.time() * 1000) - hours * HOUR_MS
    with _dblock:
        rows = db().execute("SELECT hour, events FROM hourly WHERE hour >= ? ORDER BY hour", (cutoff,)).fetchall()
    return [{"t": r[0], "events": r[1] or 0} for r in rows]


def build_report_data(hours=24):
    """Everything reports.render_html()/render_pdf() need, reusing the same aggregations the dashboard itself uses."""
    hours = hours if hours in RANGES_H else 24
    d = data_for(hours)
    geo = build_geo(min(hours * 3600, 86400))
    store = api_storage()
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(), "range_h": hours, "host": HOST_NAME,
        "kpi": d["kpi"], "rules": d["rules"], "alerts": d["alerts"], "types": d["types"],
        "cluster": d["cluster"], "resources": d["host"], "trend": report_trend(hours),
        "geo": {"per_min": geo["per_min"], "denied": geo["denied"], "total": geo["total"],
                "window_s": geo["window_s"], "countries": geo["countries"][:10]},
        "storage": {"disk_free": store["disk_free"], "disk_total": store["disk_total"],
                    "days_left": store["days_left"], "avg_daily_total": store["avg_daily_total"]},
        "connections": _report_connections_safe(hours),
    }


def _report_connections_safe(hours):
    try:
        return report_connections(max(hours, 24))
    except Exception as e:                       # the rest of the report is still worth sending
        print("report connections failed: %s" % str(e)[:200], flush=True)
        return None


def generate_report(hours=24):
    return reports.generate(DATA_DIR, build_report_data(hours))


_last_report_day = None


def report_loop():
    global _last_report_day
    while True:
        try:
            hour = current_report_hour()
            today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            if hour is not None and datetime.now(timezone.utc).hour == hour and _last_report_day != today:
                generate_report()
                _last_report_day = today
        except Exception as e:
            print("scheduled report failed:", str(e)[:200], flush=True)
        time.sleep(60)


def history_loop():
    while True:
        try:
            sync_history()
        except Exception as e:
            print("history sync failed:", str(e)[:200], flush=True)
        try:
            snapshot_storage()
        except Exception as e:
            print("storage snapshot failed:", str(e)[:200], flush=True)
        time.sleep(SYNC_EVERY_S)


def compute_history():
    now_ms = int(time.time() * 1000)
    T = now_ms - now_ms % HOUR_MS
    with _dblock:
        rows = db().execute("SELECT hour,events,alerts,sev_high,ai_in,ai_out,src FROM hourly ORDER BY hour").fetchall()
    idx = {"events": 1, "alerts": 2, "sev_high": 3, "ai_in": 4, "ai_out": 5}

    def window(a, b):
        res = {}
        for m, i in idx.items():
            vals = [r[i] for r in rows if a <= r[0] < b and r[i] is not None]
            res[m] = {"sum": sum(vals) if vals else None, "hours": len(vals)}
        return res

    def cmp(cur, prev, extra=None):
        out = {"hours": (cur[1] - cur[0]) // HOUR_MS, "metrics": {}}
        w = {"cur": window(*cur), "prev": window(*prev)}
        if extra:
            w["wk"] = window(*extra)
        for m in idx:
            out["metrics"][m] = {k: w[k][m] for k in w}
        return out

    day, wk = 24 * HOUR_MS, 7 * 24 * HOUR_MS
    daily = cmp((T - day, T), (T - 2 * day, T - day), (T - day - wk, T - wk))
    weekly = cmp((T - wk, T), (T - 2 * wk, T - wk))

    today = datetime.now().date()
    days = []
    for i in range(RETAIN_DAYS - 1, -1, -1):
        d = today - timedelta(days=i)
        key = d.strftime("%Y-%m-%d")
        rs = [r for r in rows if datetime.fromtimestamp(r[0] / 1000).date() == d]
        entry = {"day": key, "hours": sum(1 for r in rs if r[1] is not None), "today": i == 0}
        for m, k in idx.items():
            vals = [r[k] for r in rs if r[k] is not None]
            entry[m] = sum(vals) if vals else None
        days.append(entry)
    first = lambda f: next((datetime.fromtimestamp(r[0] / 1000).strftime("%Y-%m-%d") for r in rows if f(r)), None)
    return {"generated": datetime.now(timezone.utc).isoformat(), "retain_days": RETAIN_DAYS, "ai_configured": bool(current_ai_hosts()),
            "daily": daily, "weekly": weekly, "days": days,
            "since": {"events": first(lambda r: r[1] is not None), "live": first(lambda r: r[6] == "live"),
                      "alerts": first(lambda r: r[2] is not None), "ai": first(lambda r: r[4] is not None)},
            "last_complete_hour": datetime.fromtimestamp(T / 1000).strftime("%Y-%m-%d %H:00")}


# ---------------------------------------------------------------------------
# Drill-down APIs: sources, source detail, alert list/detail, ingest-lag analysis
# ---------------------------------------------------------------------------
from urllib.parse import urlparse, parse_qs

IX = "?ignore_unavailable=true&allow_no_indices=true"
SEVS = {"High", "Medium", "Low", "Critical"}
UUID_RE = re.compile(r"^[0-9A-Za-z_-]{8,64}$")
DELAY_SCRIPT = ("def a=doc['@timestamp']; def b=doc['deviceTime']; if(a.size()==0||b.size()==0) return null; "
                "return (a.value.toInstant().toEpochMilli()-b.value.toInstant().toEpochMilli())/1000.0;")
LAG_WINDOW_S = 900
DELAYED_S, SILENT_S = 60, 600
_lag = {"computed_at": None, "sources": []}


def trim(o, depth=0, limit=500):
    """Shrink a document for the UI: cap string length, list length and depth."""
    if depth > 6:
        return "…"
    if isinstance(o, str):
        return o if len(o) <= limit else o[:limit] + "… (+%d chars)" % (len(o) - limit)
    if isinstance(o, list):
        return [trim(x, depth + 1, limit) for x in o[:20]]
    if isinstance(o, dict):
        return {k: trim(v, depth + 1, limit) for k, v in list(o.items())[:60]}
    return o


def _clip(v, n=200):
    return (v or "")[:n] if isinstance(v, str) else ""


def api_sources():
    one_day = rng("now-24h")
    logs = os_call("/v11-log-*/_search" + IX, {
        "size": 0, "track_total_hits": True, "query": one_day, "aggs": {
            "ds": {"terms": {"field": "dataSource.keyword", "size": 300}, "aggs": {
                "types": {"terms": {"field": "dataType.keyword", "size": 3}},
                "last": {"max": {"field": "@timestamp"}},
                "h": {"date_histogram": {"field": "@timestamp", "fixed_interval": "1h", "min_doc_count": 0,
                                         "extended_bounds": {"min": "now-24h/h", "max": "now/h"}}}}},
            "types": {"terms": {"field": "dataType.keyword", "size": 20}, "aggs": {
                "n": {"cardinality": {"field": "dataSource.keyword"}},
                "top": {"terms": {"field": "dataSource.keyword", "size": 1}}}}}})
    al = os_call("/v11-alert-*/_search" + IX, {"size": 0, "query": one_day, "aggs": {
        "ds": {"terms": {"field": "dataSource.keyword", "size": 300}}}})
    alerts = {b["key"]: b["doc_count"] for b in al["aggregations"]["ds"]["buckets"]}
    total = logs["hits"]["total"]["value"] or 1
    srcs = []
    for b in logs["aggregations"]["ds"]["buckets"]:
        srcs.append({"name": b["key"], "events": b["doc_count"], "share": b["doc_count"] / total * 100,
                     "type": b["types"]["buckets"][0]["key"] if b["types"]["buckets"] else "",
                     "types": [t["key"] for t in b["types"]["buckets"]],
                     "last": b["last"].get("value"), "alerts": alerts.get(b["key"], 0),
                     "hourly": [h["doc_count"] for h in b["h"]["buckets"]]})
    types = [{"name": b["key"], "events": b["doc_count"], "share": b["doc_count"] / total * 100,
              "sources": b["n"]["value"], "top": b["top"]["buckets"][0]["key"] if b["top"]["buckets"] else ""}
             for b in logs["aggregations"]["types"]["buckets"]]
    return {"total": logs["hits"]["total"]["value"], "now": int(time.time() * 1000), "sources": srcs, "types": types}


def api_source(name):
    f = {"term": {"dataSource.keyword": name}}
    q = {"bool": {"filter": [rng("now-24h"), f]}}
    logs = os_call("/v11-log-*/_search" + IX, {
        "size": 20, "track_total_hits": True, "query": q, "sort": [{"@timestamp": "desc"}],
        "_source": ["@timestamp", "deviceTime", "dataType", "raw"],
        "aggs": {"h": {"date_histogram": {"field": "@timestamp", "fixed_interval": "1h", "min_doc_count": 0,
                                          "extended_bounds": {"min": "now-24h/h", "max": "now/h"}}},
                 "types": {"terms": {"field": "dataType.keyword", "size": 5}}}})
    al = os_call("/v11-alert-*/_search" + IX, {
        "size": 0, "track_total_hits": True, "query": {"bool": {"filter": [rng("now-24h"), f]}},
        "aggs": {"rules": {"terms": {"field": "name.keyword", "size": 8}, "aggs": {
            "sev": {"terms": {"field": "severityLabel.keyword", "size": 1}}}}}})
    lag = next((x for x in _lag["sources"] if x["name"] == name), None)
    return {
        "name": name, "events": logs["hits"]["total"]["value"], "alerts": al["hits"]["total"]["value"],
        "hourly": [{"t": b["key"], "n": b["doc_count"]} for b in logs["aggregations"]["h"]["buckets"]],
        "types": [{"name": b["key"], "n": b["doc_count"]} for b in logs["aggregations"]["types"]["buckets"]],
        "rules": [{"name": b["key"], "n": b["doc_count"], "sev": b["sev"]["buckets"][0]["key"] if b["sev"]["buckets"] else "Low"}
                  for b in al["aggregations"]["rules"]["buckets"]],
        "recent": [{"t": h["_source"].get("@timestamp"), "device_t": h["_source"].get("deviceTime"),
                    "type": h["_source"].get("dataType"), "raw": _clip(h["_source"].get("raw"), 1500)} for h in logs["hits"]["hits"]],
        "lag": lag,
    }


def _num(v, kind=float):
    """Third-party and log values that the UI prints as numbers: a real number or None, never a string."""
    try:
        return kind(v) if v is not None and not isinstance(v, bool) else None
    except (TypeError, ValueError):
        return None


def alert_ip_loc(*candidates):
    """Pick the first candidate dict (adversary / event origin / target, in caller's preference order) that has
    an ip, and return (ip, (lat, lon)) using that same dict's geolocation -- never mix an IP from one party with
    another party's coordinates."""
    for c in candidates:
        ip = c.get("ip")
        if ip:
            g = c.get("geolocation") or {}
            return ip, (_num(g.get("latitude")), _num(g.get("longitude")))
    return "", (None, None)


def alert_summary(h):
    s = h["_source"]
    evs = s.get("events") or []
    ev0 = evs[0] if evs else {}
    adv, tgt, origin = s.get("adversary") or {}, s.get("target") or {}, ev0.get("origin") or {}
    ip, loc = alert_ip_loc(adv, origin, tgt)
    technique = s.get("technique") or ""
    return {"id": h["_id"], "t": s.get("@timestamp"), "sev": s.get("severityLabel") or "Low", "name": s.get("name") or "-",
            "source": s.get("dataSource") or "-", "type": s.get("dataType") or "", "status": s.get("statusLabel") or "Open",
            "ip": ip, "affected": len(evs), "category": s.get("category") or "", "lat": loc[0], "lon": loc[1],
            "technique": technique if technique != "Indeterminate" else ""}


def api_alerts(p):
    flt = [rng("now-24h")]
    if p.get("sev") in SEVS:
        flt.append({"term": {"severityLabel.keyword": p["sev"]}})
    if p.get("source"):
        flt.append({"term": {"dataSource.keyword": p["source"][:200]}})
    if p.get("rule"):
        flt.append({"term": {"name.keyword": p["rule"][:300]}})
    if p.get("q"):
        flt.append({"simple_query_string": {"query": p["q"][:100], "default_operator": "and",
                                            "flags": "AND|OR|NOT|PHRASE|PRECEDENCE|WHITESPACE|ESCAPE",
                                            "fields": ["name", "description", "dataSource", "dataType", "category", "technique"]}})
    size = max(1, min(100, int(p.get("size", 25))))
    frm = max(0, min(10000 - size, int(p.get("from", 0))))
    r = os_call("/v11-alert-*/_search" + IX, {
        "size": size, "from": frm, "track_total_hits": True, "query": {"bool": {"filter": flt}},
        "sort": [{"@timestamp": "desc"}],
        "_source": ["@timestamp", "name", "severityLabel", "dataSource", "dataType", "statusLabel", "events", "adversary", "target", "category", "technique"],
        "aggs": {"sev": {"terms": {"field": "severityLabel.keyword"}},
                 "sources": {"terms": {"field": "dataSource.keyword", "size": 30}},
                 "rules": {"terms": {"field": "name.keyword", "size": 30}}}})
    ag = r["aggregations"]
    return {"total": r["hits"]["total"]["value"], "from": frm, "size": size,
            "items": [alert_summary(h) for h in r["hits"]["hits"]],
            "sev": {b["key"]: b["doc_count"] for b in ag["sev"]["buckets"]},
            "sources": [b["key"] for b in ag["sources"]["buckets"]], "rules": [b["key"] for b in ag["rules"]["buckets"]]}


def api_alert(aid):
    if not UUID_RE.match(aid):
        raise ValueError("bad alert id")
    r = os_call("/v11-alert-*/_search" + IX, {"size": 1, "query": {"ids": {"values": [aid]}}})
    hits = r["hits"]["hits"]
    if not hits:
        return {"error": "Alert not found (it may have aged out of OpenSearch)."}
    s = dict(hits[0]["_source"])
    evs = s.pop("events", []) or []
    out = trim(s)
    out["id"], out["_index"] = hits[0]["_id"], hits[0]["_index"]
    out["event_count"] = len(evs)
    out["events"] = [trim(e, limit=1500) for e in evs[:10]]
    return out


def compute_lag():
    r = os_call("/v11-log-*/_search" + IX, {
        "size": 0, "query": rng("now-%ds" % LAG_WINDOW_S), "aggs": {"s": {
            "terms": {"field": "dataSource.keyword", "size": 300}, "aggs": {
                "last": {"max": {"field": "@timestamp"}},
                "types": {"terms": {"field": "dataType.keyword", "size": 1}},
                "d": {"percentiles": {"percents": [50, 95], "script": {"lang": "painless", "source": DELAY_SCRIPT}}}}}}})
    now = time.time()
    out = []
    for b in r["aggregations"]["s"]["buckets"]:
        v = b["d"]["values"]
        out.append({"name": b["key"], "type": b["types"]["buckets"][0]["key"] if b["types"]["buckets"] else "",
                    "docs": b["doc_count"], "eps": b["doc_count"] / LAG_WINDOW_S,
                    "age_s": max(0, now - (b["last"].get("value") or 0) / 1000),
                    "p50": v.get("50.0"), "p95": v.get("95.0")})
    out.sort(key=lambda x: -(abs(x["p50"]) if x["p50"] is not None else 0))
    _lag.update({"computed_at": int(now * 1000), "sources": out})


def lag_loop():
    while True:
        try:
            compute_lag()
        except Exception as e:
            print("lag compute failed:", str(e)[:200], flush=True)
        time.sleep(60)


def lag_summary():
    delayed = [x for x in _lag["sources"] if x["p50"] is not None and x["p50"] >= DELAYED_S and x["docs"] >= 20]
    if not delayed:
        return {"delayed": 0}
    worst = max(delayed, key=lambda x: x["p95"] or 0)
    return {"delayed": len(delayed), "worst": worst["name"], "worst_p95": worst["p95"], "worst_p50": worst["p50"]}


def mins(s):
    s = abs(s)
    return "%.1f min" % (s / 60) if s >= 90 else "%d s" % round(s)


def api_lag():
    with _lock:
        d = _state["data"]
    kpi = d.get("kpi") or {}
    srcs = _lag["sources"]
    live_names = {x["name"] for x in srcs}
    silent = [x for x in _state.get("ds", []) if x["name"] not in live_names and (time.time() * 1000 - x["last"]) > SILENT_S * 1000]
    delayed = [x for x in srcs if x["p50"] is not None and x["p50"] >= DELAYED_S and x["docs"] >= 20]
    ahead = [x for x in srcs if x["p50"] is not None and x["p50"] <= -DELAYED_S and x["docs"] >= 20]
    notes = []
    age = kpi.get("lag_s")
    if age is not None:
        if age < 15:
            notes.append({"level": "ok", "title": "UTMStack is keeping up",
                          "text": "The newest stored event is %s old, so events are being stored as fast as they arrive. "
                                  "This headline number measures only that: it can look fine while individual sources are late." % mins(age)})
        else:
            notes.append({"level": "bad", "title": "No fresh events arriving",
                          "text": "The newest stored event is %s old. All sources went quiet or the event pipeline is stalled; "
                                  "check the event-processor services and the collectors." % mins(age)})
    if delayed:
        names = ", ".join("%s (%s)" % (x["name"], mins(x["p50"])) for x in delayed[:6])
        steady = all((x["p95"] or 0) - (x["p50"] or 0) < 0.25 * x["p50"] for x in delayed)
        cloud = [x["name"] for x in delayed if x["type"] == "o365"]
        extra = (" Microsoft 365 feeds (%s) are collected by API polling, so a few minutes of delay is normal for them." % ", ".join(cloud[:4])) if cloud else ""
        notes.append({"level": "warn", "title": "%d source%s deliver events late" % (len(delayed), "" if len(delayed) == 1 else "s"),
                      "text": "Median gap between the device's own timestamp and the time UTMStack stored the event: %s. %s" % (names,
                              "The gap is steady, which usually means the delay happens on the device side (log export/batching interval, "
                              "or a fixed clock/time-zone offset), not inside UTMStack." if steady else
                              "The gap varies a lot, which points to bursty delivery (batching, network or collector backlog).") + extra})
    if ahead:
        notes.append({"level": "warn", "title": "%d source%s have clocks ahead" % (len(ahead), "" if len(ahead) == 1 else "s"),
                      "text": ", ".join("%s (%s ahead)" % (x["name"], mins(x["p50"])) for x in ahead[:6]) +
                              ". Their events are stamped in the future, so they look like negative lag. Check NTP/time zone on those devices."})
    if silent:
        notes.append({"level": "warn", "title": "%d source%s silent for over 10 minutes" % (len(silent), "" if len(silent) == 1 else "s"),
                      "text": ", ".join(x["name"] for x in silent[:8]) + ". They are not slowing anyone else down, but nothing is arriving from them."})
    c = d.get("cluster") or {}
    if c.get("status") and c["status"] != "green":
        single = c.get("nodes") == 1
        notes.append({"level": "info", "title": "OpenSearch is %s" % c["status"],
                      "text": "%s unassigned shards%s" % (c.get("unassigned"), " on a single-node cluster: replica shards cannot be placed, "
                              "which is expected and does not by itself delay indexing." if single else ". Check cluster allocation.")})
    h = d.get("host") or {}
    for key, label in (("cpu_pct", "CPU"), ("mem_pct", "memory"), ("disk_pct", "disk")):
        if (h.get(key) or 0) > 85:
            notes.append({"level": "warn", "title": "Host %s is high" % label, "text": "%.0f%% used on %s; a starved host can slow indexing." % (h[key], h.get("hostname"))})
    if not notes:
        notes.append({"level": "info", "title": "No data yet", "text": "The lag analysis has not run yet; try again in a minute."})
    return {"newest_age_s": age, "window_s": LAG_WINDOW_S, "computed_at": _lag["computed_at"], "notes": notes,
            "sources": srcs, "silent": [{"name": x["name"], "type": x["type"], "age_s": (time.time() * 1000 - x["last"]) / 1000} for x in silent]}


# ---------------------------------------------------------------------------
# WHOIS via RDAP (the structured successor to whois). rdap.org redirects to the right registry.
# Only public addresses are looked up; results are cached for 24 h.
# ---------------------------------------------------------------------------
import ipaddress
import urllib.request
from urllib.parse import quote, urlencode

_whois_cache = {}
WHOIS_TTL_S = 86400


def _vcard(e):
    out = {}
    for f in (e.get("vcardArray") or [None, []])[1]:
        if f[0] in ("fn", "org", "email", "tel", "adr") and f[0] not in out:
            v = f[3]
            out[f[0]] = " ".join(x for x in v if x) if isinstance(v, list) else v
            if f[0] == "email" and (f[1] or {}).get("type") == "abuse":
                out["abuse"] = True
    return out


def parse_ip(ip):
    """A plain IPv4/IPv6 address, or None. Zone ids (fe80::1%eth0) are refused: they can carry ?&# into URLs."""
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return None
    return None if getattr(addr, "scope_id", None) else addr


def api_whois(ip):
    addr = parse_ip(ip)
    if addr is None:
        return {"error": "not a valid IP address"}
    key = str(addr)
    hit = _whois_cache.get(key)
    if hit and time.time() - hit[0] < WHOIS_TTL_S:
        return hit[1]
    if not addr.is_global:
        res = {"ip": key, "private": True, "note": "Private, loopback or reserved address: it has no public WHOIS record."}
        _whois_cache[key] = (time.time(), res)
        return res
    req = urllib.request.Request("https://rdap.org/ip/" + quote(key, safe=":."), headers={"Accept": "application/rdap+json", "User-Agent": "utmstack-observatory/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            d = json.loads(r.read(400_000))
    except Exception as e:
        return {"ip": key, "error": "RDAP lookup failed: %s" % str(e)[:120]}
    contacts, abuse = [], None
    for e in d.get("entities", [])[:12]:
        v = _vcard(e)
        if not v:
            continue
        c = {"roles": e.get("roles", []), "name": v.get("fn") or v.get("org") or e.get("handle", ""), "email": v.get("email", ""), "tel": v.get("tel", "")}
        contacts.append(c)
        if v.get("abuse") or "abuse" in c["roles"]:
            abuse = abuse or c["email"] or None
        for sub in e.get("entities", [])[:6]:          # abuse contacts are often nested under the org
            sv = _vcard(sub)
            if sv.get("email") and ("abuse" in sub.get("roles", []) or sv.get("abuse")):
                abuse = abuse or sv["email"]
    ev = {x.get("eventAction"): x.get("eventDate") for x in d.get("events", [])}
    res = {"ip": key, "name": d.get("name"), "handle": d.get("handle"), "country": d.get("country"), "type": d.get("type"),
           "start": d.get("startAddress"), "end": d.get("endAddress"), "parent": d.get("parentHandle"),
           "cidrs": ["%s/%s" % (c.get("v4prefix") or c.get("v6prefix"), c.get("length")) for c in d.get("cidr0_cidrs", [])],
           "status": d.get("status", []), "registered": ev.get("registration"), "changed": ev.get("last changed"),
           "contacts": contacts[:6], "abuse": abuse, "source": d.get("port43"),
           "remarks": [" ".join(r.get("description", [])) for r in d.get("remarks", [])][:3]}
    if len(_whois_cache) > 500:
        _whois_cache.clear()
    _whois_cache[key] = (time.time(), res)
    return res


# ---------------------------------------------------------------------------
# IP reputation: AbuseIPDB and VirusTotal, each optional (ABUSEIPDB_KEY / VIRUSTOTAL_KEY), cached 24 h like WHOIS.
# ---------------------------------------------------------------------------
_reputation_cache = {}
REPUTATION_TTL_S = 86400


def _abuseipdb(ip):
    key = current_abuseipdb_key()
    if not key:
        return {"configured": False}
    req = urllib.request.Request(
        "https://api.abuseipdb.com/api/v2/check?" + urlencode({"ipAddress": ip, "maxAgeInDays": 90}),
        headers={"Key": key, "Accept": "application/json", "User-Agent": "utmstack-observatory/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            d = json.loads(r.read(200_000))["data"]
    except Exception as e:
        return {"configured": True, "error": "AbuseIPDB lookup failed: %s" % str(e)[:120]}
    return {"configured": True, "score": _num(d.get("abuseConfidenceScore"), int), "reports": _num(d.get("totalReports"), int),
            "distinct_reporters": _num(d.get("numDistinctUsers"), int), "last_reported": d.get("lastReportedAt"),
            "usage_type": d.get("usageType"), "isp": d.get("isp"), "domain": d.get("domain"),
            "whitelisted": d.get("isWhitelisted")}


def _virustotal(ip):
    key = current_virustotal_key()
    if not key:
        return {"configured": False}
    req = urllib.request.Request("https://www.virustotal.com/api/v3/ip_addresses/%s" % quote(ip, safe=":."),
                                  headers={"x-apikey": key, "User-Agent": "utmstack-observatory/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            a = json.loads(r.read(500_000))["data"]["attributes"]
    except Exception as e:
        return {"configured": True, "error": "VirusTotal lookup failed: %s" % str(e)[:120]}
    stats = a.get("last_analysis_stats") or {}
    flagged = [v.get("result") for v in (a.get("last_analysis_results") or {}).values() if v.get("category") == "malicious"]
    return {"configured": True, "malicious": _num(stats.get("malicious", 0), int) or 0,
            "suspicious": _num(stats.get("suspicious", 0), int) or 0, "harmless": _num(stats.get("harmless", 0), int) or 0,
            "undetected": _num(stats.get("undetected", 0), int) or 0, "reputation": _num(a.get("reputation"), int), "as_owner": a.get("as_owner"), "country": a.get("country"),
            "flagged_by": [x for x in flagged if x][:8]}


def api_reputation(ip):
    addr = parse_ip(ip)
    if addr is None:
        return {"error": "not a valid IP address"}
    key = str(addr)
    hit = _reputation_cache.get(key)
    if hit and time.time() - hit[0] < REPUTATION_TTL_S:
        return hit[1]
    if not addr.is_global:
        res = {"ip": key, "private": True, "note": "Private, loopback or reserved address: no reputation to check."}
        _reputation_cache[key] = (time.time(), res)
        return res
    res = {"ip": key, "abuseipdb": _abuseipdb(key), "virustotal": _virustotal(key)}
    if len(_reputation_cache) > 500:
        _reputation_cache.clear()
    _reputation_cache[key] = (time.time(), res)
    return res


def _family(name):
    return re.sub(r"[-.]?\d{4}[-.]\d{2}([-.]\d{2})?(-\d+)?$", "", name)


def api_cluster():
    """Explain a non-green OpenSearch status: which shards, why they cannot be placed, and what would fix it."""
    h = os_call("/_cluster/health", method="GET")
    shards = os_call("/_cat/shards?h=index,shard,prirep,state,unassigned.reason&format=json", method="GET")
    idx = os_call("/_cat/indices?h=index,health,pri,rep,pri.store.size&bytes=b&format=json&expand_wildcards=all", method="GET")
    try:
        ex = os_call("/_cluster/allocation/explain", {})
    except RuntimeError:
        ex = None                                    # 400 when nothing is unassigned
    un = [x for x in shards if x["state"] == "UNASSIGNED"]
    un_p = [x for x in un if x["prirep"] == "p"]
    reasons = {}
    for x in un:
        k = "%s shard, %s" % ("primary" if x["prirep"] == "p" else "replica", x.get("unassigned.reason") or "unknown")
        reasons[k] = reasons.get(k, 0) + 1
    fams = {}
    for i in idx:
        f = fams.setdefault(_family(i["index"]), {"family": _family(i["index"]), "indices": 0, "unassigned": 0, "replicas": 0, "bytes": 0, "yellow": 0})
        f["indices"] += 1; f["replicas"] = max(f["replicas"], int(i["rep"] or 0)); f["bytes"] += int(i["pri.store.size"] or 0)
        f["yellow"] += i["health"] != "green"
    for x in un:                                     # hidden indices may be absent from _cat/indices; never assume
        f = fams.setdefault(_family(x["index"]), {"family": _family(x["index"]), "indices": 0, "unassigned": 0, "replicas": 0, "bytes": 0, "yellow": 0})
        f["unassigned"] += 1
    fam_rows = sorted([f for f in fams.values() if f["unassigned"]], key=lambda f: -f["unassigned"])
    single = h.get("number_of_data_nodes") == 1
    decider = []
    if ex:
        for n in ex.get("node_allocation_decisions", [])[:1]:
            decider = [{"decider": d["decider"], "text": d["explanation"][:260]} for d in n.get("deciders", []) if d["decision"] == "NO"]
    notes = []
    if h["status"] == "green":
        notes.append({"level": "ok", "title": "Cluster is green", "text": "All primary and replica shards are assigned."})
    if un_p:
        notes.append({"level": "bad", "title": "%d primary shard(s) unassigned" % len(un_p),
                      "text": "Data in those indices is unavailable right now. Indices: " + ", ".join(sorted({x["index"] for x in un_p})[:8]) + "."})
    if un and not un_p:
        if single:
            notes.append({"level": "warn", "title": "All %d unassigned shards are replicas on a one-node cluster" % len(un),
                          "text": "OpenSearch will never place a replica on the same node as its primary (the 'same_shard' rule), so with a single "
                                  "node these replica copies can never be created and the status stays yellow. Nothing is missing: all %d primary "
                                  "shards are active, and searching and indexing work normally. A replica would not add safety here anyway, because "
                                  "it would live on the same machine." % h.get("active_primary_shards", 0)})
            notes.append({"level": "info", "title": "Why these indices have a replica",
                          "text": "OpenSearch gives every new index 1 replica unless a template says otherwise. UTMStack ships a template meant "
                                  "to set 0 replicas for its own indices, but on some versions its patterns have no wildcard (e.g. 'v11-alert-'), "
                                  "so it does not match the daily indices. The security audit log, statistics and OpenSearch's management "
                                  "history are not covered by it at all."})
        else:
            notes.append({"level": "warn", "title": "%d replica shards cannot be placed" % len(un), "text": "See the allocation decider below; with several nodes this usually means disk watermarks, allocation filters or too few nodes."})
    fix = None
    if un and not un_p and single:
        names = {}
        for x in un:
            names.setdefault(_family(x["index"]), set()).add(x["index"])
        safe = [f["family"] for f in fam_rows if SAFE_INDEX.fullmatch(f["family"])]
        # A family whose only index is the family name itself (no date) is matched exactly; daily series get -*
        pats = [fam if names.get(fam, set()) <= {fam} else fam + "-*" for fam in safe]
        system = [x for x in pats if x.startswith(".") or x.startswith("security-auditlog")]
        data = [x for x in pats if x not in system]
        series = [x for x in pats if x.endswith("-*")]
        fix = {"patterns": pats, "steps": [],
               "manual": [f["family"] for f in fam_rows if not SAFE_INDEX.fullmatch(f["family"])]}

        def step(title, path, body):
            # the same request twice: as a copy-paste command, and as the operation the "Apply fix" button runs
            fix["steps"].append({"title": title, "cmd": opensearch_put_cmd(path, json.dumps(body, separators=(",", ":"))),
                                 "op": {"method": "PUT", "path": path, "body": body}})
        no_replica = {"index": {"number_of_replicas": 0}}
        if data:
            step("Remove replicas from the existing data indices", "/%s/_settings" % ",".join(data), no_replica)
        for fam in system:
            # One request per family: the security plugin refuses a whole request when any index in it is protected.
            step("Remove replicas from the system index %s" % fam, "/%s/_settings?expand_wildcards=all" % fam, no_replica)
        fams_un = {f["family"] for f in fam_rows}
        # Plugins that create their daily indices with an explicit replica count ignore templates; their own setting
        # is the only lasting fix (seen on UTMStack: index-management history, query insights).
        if ".opendistro-ism-managed-index-history" in fams_un:
            step("Stop OpenSearch's index-management history asking for a replica", "/_cluster/settings",
                 {"persistent": {"plugins.index_state_management.history.number_of_replicas": 0}})
        if "top_queries" in fams_un:
            step("Stop the query-insights plugin writing daily indices (UTMStack does not use them)", "/_cluster/settings",
                 {"persistent": {"search.insights.top_queries.exporter.type": "none"}})
        fix["protected_note"] = ("A system-index step that answers 403 'no permissions' means OpenSearch protects that index: "
                                 "the admin password is not enough, it needs the super-admin certificate (the admin_dn "
                                 "certificate in opensearch.yml). The other steps are not affected.")
        if series:
            # Legacy template with order 0: it only applies when no composable template matches, so if UTMStack's own
            # (composable) template is ever fixed to match its indices, UTMStack's settings and mappings win.
            step("Stop new daily indices getting a replica", "/_template/single-node-no-replicas",
                 {"index_patterns": series, "order": 0, "settings": {"number_of_replicas": 0}})
    return {"status": h["status"], "nodes": h.get("number_of_data_nodes"), "active_pct": h.get("active_shards_percent_as_number"),
            "active": h.get("active_shards"), "primaries": h.get("active_primary_shards"), "unassigned": len(un), "unassigned_primaries": len(un_p),
            "reasons": reasons, "families": fam_rows, "decider": decider,
            "explained": ({"index": ex.get("index"), "shard": ex.get("shard"), "primary": ex.get("primary"), "text": ex.get("allocate_explanation")} if ex else None),
            "notes": notes, "fix": fix, "can_fix": can_fix(), "needs_password": bool(current_dash_pass())}


def can_fix():
    """The button needs an account that may write: the dedicated fixer, the docker-exec admin, or (when the installer
    kept UTMStack's admin account) OS_USER itself. Never the read-only observatory_reader."""
    if DEMO:
        return False
    return bool(OS_FIX_USER) or TRANSPORT == "docker-exec" or (bool(OS_USER) and OS_USER != "observatory_reader") or not OS_USER


FIX_OP_PATH = re.compile(r"/(_cluster/settings|_template/single-node-no-replicas|[a-z0-9._*,-]+/_settings(\?expand_wildcards=all)?)")
FIX_SETTINGS = {"plugins.index_state_management.history.number_of_replicas", "search.insights.top_queries.exporter.type"}
_fix_lock = threading.Lock()
FIX_SETTLE_S = 1.5


def _fix_op_allowed(op):
    """Second line of defence: only the request shapes api_cluster() produces may ever be sent."""
    path, body = op.get("path", ""), op.get("body") or {}
    if op.get("method") != "PUT" or not FIX_OP_PATH.fullmatch(path):
        return False
    if path == "/_cluster/settings":
        return set(body) == {"persistent"} and set(body["persistent"]) <= FIX_SETTINGS
    if path.startswith("/_template/"):
        return set(body) == {"index_patterns", "order", "settings"} and body["settings"] == {"number_of_replicas": 0}
    return body == {"index": {"number_of_replicas": 0}}


def apply_cluster_fix(who):
    """Re-derive the fix from the cluster's current state (never from the browser) and run its steps."""
    with _fix_lock:
        before = api_cluster()
        steps = [x for x in ((before.get("fix") or {}).get("steps") or []) if x.get("op")]
        results = []
        for st in steps:
            op = st["op"]
            if not _fix_op_allowed(op):
                results.append({"title": st["title"], "ok": False, "text": "skipped: not an allowed change"})
                continue
            try:
                if TRANSPORT == "docker-exec":
                    res = _call_exec(op["path"], op["body"], "PUT")
                else:
                    res = _call_http(op["path"], op["body"], "PUT", (OS_FIX_USER, OS_FIX_PASS) if OS_FIX_USER else None)
            except Exception as e:
                res = {"error": str(e)}
            ok = isinstance(res, dict) and res.get("acknowledged") is True
            err = (res or {}).get("error") if isinstance(res, dict) else None
            text = "done" if ok else str((err or {}).get("reason") if isinstance(err, dict) else err or res)[:240]
            if not ok and "no permissions" in text:
                text = "OpenSearch refused: this is a protected index (needs the super-admin certificate) or the fix account lacks the right"
            results.append({"title": st["title"], "ok": ok, "text": text})
        print("audit: cluster fix by %s: %s" % (who, "; ".join("%s=%s" % (r["title"], "ok" if r["ok"] else "failed") for r in results) or "nothing to do"), flush=True)
    time.sleep(FIX_SETTLE_S)                     # let OpenSearch drop the replicas before re-reading the status
    return {"results": results, "cluster": api_cluster()}


SAFE_INDEX = re.compile(r"[a-z0-9._-]+")      # index names come from OpenSearch; only these ever reach a shell command
STACK = env("STACK_NAME", "utmstack")


def opensearch_put_cmd(path, body):
    """A copy-paste command for the UTMStack host: every docker call under sudo, the OpenSearch password read from
    UTMStack's backend service and passed on stdin (never typed, never on a command line or in shell history)."""
    body_sh = body.replace('"', '\\"')
    return ("P=$(sudo docker service inspect %s_backend --format '{{range .Spec.TaskTemplate.ContainerSpec.Env}}{{println .}}{{end}}' "
            "| sed -n 's/^ELASTICSEARCH_PASSWORD=//p'); N=$(sudo docker ps -q -f name=%s_node1); "
            "printf '%%s\\n' \"$P\" | sudo docker exec -i \"$N\" sh -c 'read -r PW; curl -sk -u \"admin:$PW\" -XPUT "
            "-H \"Content-Type: application/json\" \"https://localhost:9200%s\" -d \"%s\"'; echo"
            % (STACK, STACK, path, body_sh))


# ---------------------------------------------------------------- live firewall map
# Arcs between each firewall and the remote cities it talks to, from Sophos XG logs. UTMStack already
# geolocates public IPs (origin/target.geolocation), so no GeoIP database or outside lookup is needed.
FW_SEARCH = "/v11-log-firewall-sophos-xg-*/_search"
# Types UTMStack geolocates itself, and types whose attacker IPs this dashboard looks up (geoip.py);
# "all" means every one of them together.
NET_TYPES = ("firewall-sophos-xg", "o365", "google")
ATTACK_TYPES = ("linux", "syslog", "wineventlog", "o365")
GEO_TYPES = NET_TYPES + ("linux", "syslog", "wineventlog")
GEO = geoip.GeoIP(DATA_DIR, secret("PROXYCHECK_KEY"), int(env("GEOIP_ONLINE_DAILY", "100") or 0))
GEO_WINDOWS_S = (60, 300, 900)
# Street basemap: MapLibre is served from here; only map tiles, fonts and icons come from this one host.
TILE_HOST = "https://tiles.openfreemap.org"
STATIC_FILES = {"/maplibre-gl.css": "text/css; charset=utf-8"}
# MapLibre GL JS 6 (ES modules). Their imports of each other get ?v=<version> when served (see module_body).
MODULE_FILES = ("/maplibre-loader.mjs", "/maplibre-gl.mjs", "/maplibre-gl-shared.mjs", "/maplibre-gl-worker.mjs")
_module_cache = {}


def module_body(path):
    if path not in _module_cache:
        with open(os.path.join(HERE, path[1:]), "rb") as f:
            body = f.read()
        v = VERSION.encode()
        body = body.replace(b"__VERSION__", v).replace(b'"./maplibre-gl-shared.mjs"', b'"./maplibre-gl-shared.mjs?v=' + v + b'"')
        _module_cache[path] = body
    return _module_cache[path]
GEO_TTL_S = 10                                   # one shared query per 10 s, however many viewers
SITE_TTL_S = 1800                                # re-check firewall locations every 30 min
MAX_ARCS = 200


def parse_loc(text):
    """'lat,lon[,label]' -> {"lat", "lon", "city"} or None."""
    parts = [x.strip() for x in (text or "").split(",")]
    try:
        lat, lon = float(parts[0]), float(parts[1])
    except (ValueError, IndexError):
        return None
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        return None
    return {"lat": lat, "lon": lon, "city": ",".join(parts[2:]).strip() or None}


def parse_sites(text):
    """SITE_LOCATIONS='Name=lat,lon,City;1.2.3.4=lat,lon' -> {name or ip: loc}."""
    out = {}
    for item in (text or "").split(";"):
        key, _, loc = item.partition("=")
        loc = parse_loc(loc)
        if key.strip() and loc:
            out[key.strip()] = loc
    return out


HOME = parse_loc(env("HOME_LOCATION")) or {"lat": 43.6532, "lon": -79.3832, "city": "Toronto"}
SITE_OVERRIDES = parse_sites(env("SITE_LOCATIONS"))


def current_home():
    raw = settings_store.get(DATA_DIR, "home")
    if raw is None:
        return HOME
    return parse_loc(raw) or HOME


def current_site_overrides():
    raw = settings_store.get(DATA_DIR, "sites")
    return SITE_OVERRIDES if raw is None else parse_sites(raw)


_geo_cache = {}
_geo_lock = threading.Lock()
_sites = {"t": 0, "list": []}
_located = {}                                    # firewall WAN IP -> (checked_at, loc or None)


def _q(v):
    return str(v or "").strip().strip('"')


def _locate_ip(ip):
    """Find UTMStack's own geolocation for an address anywhere in the indices."""
    hit = _located.get(ip)
    if hit and (hit[1] or time.time() - hit[0] < SITE_TTL_S):
        return hit[1]
    loc = None
    for side in ("origin", "target"):
        h = os_call("/v11-*/_search", {"size": 1, "_source": [side + ".geolocation"], "query": {"bool": {"filter": [
            {"term": {side + ".ip.keyword": ip}}, {"exists": {"field": side + ".geolocation.latitude"}}]}}})["hits"]["hits"]
        if h:
            g = h[0]["_source"][side]["geolocation"]
            loc = {"lat": g["latitude"], "lon": g["longitude"], "city": g.get("city") or g.get("country")}
            break
    _located[ip] = (time.time(), loc)
    return loc


def fw_sites():
    """The firewalls reporting in the last hour, each with a location: override > UTMStack GeoIP > home."""
    if _sites["list"] and time.time() - _sites["t"] < SITE_TTL_S:
        return _sites["list"]
    r = os_call(FW_SEARCH, {"size": 0, "query": rng("now-1h"), "aggs": {"fw": {
        "terms": {"field": "dataSource.keyword", "size": 100},
        "aggs": {"dn": {"terms": {"field": "log.deviceName.keyword", "size": 1}}}}}})
    site_overrides, home = current_site_overrides(), current_home()
    out = []
    for b in r["aggregations"]["fw"]["buckets"]:
        ip = _q(b["key"])
        name = _q(b["dn"]["buckets"][0]["key"]) if b["dn"]["buckets"] else ip
        loc, source = site_overrides.get(name) or site_overrides.get(ip), "configured"
        if not loc:
            try:
                loc, source = _locate_ip(ip), "geoip"
            except Exception:
                loc = None
        if not loc:
            loc, source = home, "home"
        out.append({"id": ip, "name": name, "lat": loc["lat"], "lon": loc["lon"], "city": loc.get("city"), "loc_source": source})
    out.sort(key=lambda x: x["name"].lower())
    _sites.update(t=time.time(), list=out)
    return out


def _remote_aggs(side):
    g = side + ".geolocation."
    city_aggs = {"lat": {"avg": {"field": g + "latitude"}}, "lon": {"avg": {"field": g + "longitude"}},
                 "country": {"terms": {"field": g + "country.keyword", "size": 1}},
                 "out": {"terms": {"field": "actionResult.keyword", "size": 4}}}
    if side == "origin":                         # the busiest remote addresses, to flag VPN / Tor / hosting ones
        city_aggs["ip"] = {"terms": {"field": "origin.ip.keyword", "size": 10}}
    return {"terms": {"field": "dataSource.keyword", "size": 100}, "aggs": {
        "cc": {"terms": {"field": g + "countryCode.keyword", "size": 15, "missing": "??"}, "aggs": {
            "city": {"terms": {"field": g + "city.keyword", "size": 6, "missing": ""}, "aggs": city_aggs}}}}}


def net_counts(ip_buckets):
    """VPN, Tor and hosting connection counts among an arc's busiest remote addresses."""
    n = {"vpn": 0, "tor": 0, "hosting": 0}
    for b in ip_buckets:
        kind = GEO.net_kind(_q(b["key"]))
        if kind:
            n[kind] += b["doc_count"]
    return n


def _outcomes(buckets):
    o = {_q(b["key"]).lower(): b["doc_count"] for b in buckets}
    return o.get("denied", 0), o.get("failed", 0)


def geo_scope(dtype):
    """Index pattern and dataType filter for the types UTMStack geolocates itself, one or all of them."""
    if dtype == "firewall-sophos-xg":
        return FW_SEARCH, {"term": {"dataType.keyword": dtype}}
    if dtype in NET_TYPES:
        return "/v11-log-%s*/_search" % dtype, {"term": {"dataType.keyword": dtype}}
    return "/v11-log-*/_search", {"terms": {"dataType.keyword": list(NET_TYPES)}}


def empty_geo(window, dtype, port=None):
    return {"window_s": window, "type": dtype, "port": port, "generated": datetime.now(timezone.utc).isoformat(), "age_s": None,
            "total": 0, "denied": 0, "failed": 0, "per_min": 0, "home": current_home(), "sites": [], "arcs": [],
            "arcs_total": 0, "countries": {}, "ticker": [], "_newest": None}


def build_geo(window, dtype="all", port=None):
    g = build_net_geo(window, dtype, port) if dtype == "all" or dtype in NET_TYPES else empty_geo(window, dtype, port)
    for t in ATTACK_TYPES if dtype == "all" else ([dtype] if dtype in ATTACK_TYPES else []):
        try:
            add_attackers(g, window, t, port)
        except Exception as e:                   # one source failing must not blank the map
            print("attacker geo (%s) failed: %s" % (t, str(e)[:200]), flush=True)
    for x in g["ticker"]:
        x.setdefault("net", GEO.net_kind(x["ip"]) if x.get("ip") else None)
    seen, uniq = set(), []
    for x in sorted(g["ticker"], key=lambda x: x["t"] or "", reverse=True):
        k = ((x["t"] or "")[:19], x.get("ip"), x.get("site"))   # sshd logs one attempt as 2-3 lines in the same second
        if k not in seen:
            seen.add(k); uniq.append(x)
    g["ticker"] = uniq[:14]
    g["arcs"].sort(key=lambda x: x["count"], reverse=True)
    g["arcs_total"] = len(g["arcs"])
    g["arcs"] = g["arcs"][:MAX_ARCS]
    g["countries"] = sorted(g["countries"].values(), key=lambda c: c["count"], reverse=True)[:12]
    g["per_min"] = round(g["total"] * 60 / window)
    newest = g.pop("_newest")
    g["age_s"] = round(max(0, time.time() - newest / 1000), 1) if newest else None
    g["geoip"] = {k: GEO.status[k] for k in ("db", "lists", "online_today")}
    return g


def build_net_geo(window, dtype, port=None):
    search, type_flt = geo_scope(dtype)
    span = {"bool": {"filter": [rng("now-%ds" % window), type_flt] + ([{"term": {"target.port": port}}] if port else [])}}
    has = lambda f: {"exists": {"field": f}}
    # firewalls only "deny"; for sign-in logs (M365, Google) a failed login is the blocked event
    blocked = ["denied"] if dtype == "firewall-sophos-xg" else ["denied", "failed"]
    r = os_call(search, {"size": 0, "track_total_hits": True, "query": span, "aggs": {
        "newest": {"max": {"field": "@timestamp"}},
        "outcome": {"terms": {"field": "actionResult.keyword", "size": 5}},
        "per_fw": {"terms": {"field": "dataSource.keyword", "size": 100},
                   "aggs": {"out": {"terms": {"field": "actionResult.keyword", "size": 4}}}},
        # inbound: the remote side started it; outbound: a local host reached a remote one
        "in": {"filter": has("origin.geolocation.latitude"), "aggs": {"fw": _remote_aggs("origin")}},
        "out": {"filter": {"bool": {"filter": [has("target.geolocation.latitude")],
                                    "must_not": [has("origin.geolocation.latitude")]}},
                "aggs": {"fw": _remote_aggs("target")}},
    }})
    t = os_call(search, {"size": 14, "sort": [{"@timestamp": "desc"}], "query": {"bool": {"filter": [
        span, {"terms": {"actionResult.keyword": blocked}}, has("origin.geolocation.latitude")]}},
        "_source": ["@timestamp", "origin.ip", "origin.geolocation.city", "origin.geolocation.country",
                    "origin.geolocation.countryCode", "origin.geolocation.latitude", "origin.geolocation.longitude",
                    "target.port", "protocol", "dataSource", "dataType"]})
    if "aggregations" not in r:                  # no index for this type yet (e.g. Google not connected): empty map
        return empty_geo(window, dtype, port)
    a = r["aggregations"]
    total = r["hits"]["total"]["value"]
    denied, failed = _outcomes(a["outcome"]["buckets"])

    sites = [dict(x) for x in fw_sites()] if dtype in ("all", "firewall-sophos-xg") else []
    by_id = {x["id"]: x for x in sites}
    for b in a["per_fw"]["buckets"]:
        ip = _q(b["key"])
        if ip not in by_id:                      # firewall seen for the first time since the site list was cached
            home = current_home()
            by_id[ip] = {"id": ip, "name": ip, "lat": home["lat"], "lon": home["lon"], "city": home.get("city"), "loc_source": "home"}
            sites.append(by_id[ip])
        d, f = _outcomes(b["out"]["buckets"])
        by_id[ip].update(total=b["doc_count"], denied=d)
    for x in sites:
        x.setdefault("total", 0); x.setdefault("denied", 0)

    arcs, countries = [], {}
    for direction in ("in", "out"):
        for fb in a[direction]["fw"]["buckets"]:
            site = _q(fb["key"])
            for cb in fb["cc"]["buckets"]:
                cc = _q(cb["key"])
                for cityb in cb["city"]["buckets"]:
                    lat, lon = cityb["lat"]["value"], cityb["lon"]["value"]
                    if lat is None or lon is None:
                        continue
                    d, _ = _outcomes(cityb["out"]["buckets"])
                    name = cityb["country"]["buckets"][0]["key"] if cityb["country"]["buckets"] else cc
                    arc = {"site": site, "dir": direction, "cc": cc, "country": _q(name), "city": _q(cityb["key"]),
                           "lat": round(lat, 3), "lon": round(lon, 3), "count": cityb["doc_count"], "denied": d}
                    arc.update(net_counts(cityb.get("ip", {}).get("buckets", [])))
                    arcs.append(arc)
                    c = countries.setdefault(cc, {"cc": cc, "country": _q(name), "count": 0, "denied": 0, "in": 0, "out": 0})
                    c["count"] += cityb["doc_count"]; c["denied"] += d; c[direction] += cityb["doc_count"]

    ticker = []
    for h in t["hits"]["hits"]:
        s_ = h["_source"]
        o = s_.get("origin") or {}
        g = o.get("geolocation") or {}
        lat, lon = g.get("latitude"), g.get("longitude")
        ticker.append({"t": s_.get("@timestamp"), "ip": o.get("ip"), "city": g.get("city"), "country": g.get("country"),
                       "cc": g.get("countryCode"), "port": (s_.get("target") or {}).get("port"),
                       "proto": s_.get("protocol"), "site": _q(s_.get("dataSource")), "type": s_.get("dataType"),
                       "lat": round(lat, 3) if lat is not None else None, "lon": round(lon, 3) if lon is not None else None})

    out = empty_geo(window, dtype, port)
    out.update(total=total, denied=denied, failed=failed, sites=sites, arcs=arcs, countries=countries, ticker=ticker,
               _newest=a["newest"].get("value"))
    return out


# ---------------------------------------------------------------- attackers from logs UTMStack doesn't geolocate
# Syslog keeps the address inside the message text; Linux, Windows and M365 have origin.ip. Their locations and
# VPN / hosting / Tor status come from geoip.py (local databases, online fallback).
SYSLOG_PHRASES = ("Invalid user", "Failed password", "Failed publickey", "authentication failure", "preauth",
                  "Unable to negotiate", "maximum authentication attempts", "Accepted")
IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")


def syslog_ip(message):
    for ip in IPV4_RE.findall(message or ""):
        if geoip.is_public(ip):
            return ip
    return None


def attacker_rows(window, dtype, port=None):
    """-> (rows [{site, name, ip, count, blocked}], ticker candidates, newest ms) for one log type."""
    span = rng("now-%ds" % window)
    path = "/v11-log-%s*/_search" % dtype + IX
    rows, ticker, newest = {}, [], None
    if dtype == "syslog":
        if port and port != 22:                  # syslog lines carry no service port; the SSH ones are port 22
            return [], [], None
        r = os_call(path, {"size": 1000, "sort": [{"@timestamp": "desc"}],
                           "_source": ["@timestamp", "log.message", "dataSource", "origin.host", "origin.process"],
                           "query": {"bool": {"filter": [span, {"term": {"dataType.keyword": "syslog"}}],
                                              "should": [{"match_phrase": {"log.message": p}} for p in SYSLOG_PHRASES],
                                              "minimum_should_match": 1}}})
        for h in r.get("hits", {}).get("hits", []):
            s_ = h["_source"]
            msg = (s_.get("log") or {}).get("message") or ""
            ip = syslog_ip(msg)
            if not ip or (port and not str((s_.get("origin") or {}).get("process") or "").startswith("sshd")):
                continue
            site = _q(s_.get("dataSource")) or "syslog"
            bad = not msg.startswith("Accepted")
            row = rows.setdefault((site, ip), {"site": site, "name": (s_.get("origin") or {}).get("host") or site,
                                               "ip": ip, "count": 0, "blocked": 0})
            row["count"] += 1; row["blocked"] += bad
            if bad and len(ticker) < 14:                 # the "port N" in sshd lines is the attacker's source port
                ssh = str((s_.get("origin") or {}).get("process") or "").startswith("sshd")
                ticker.append({"t": s_.get("@timestamp"), "ip": ip, "site": site, "type": "syslog",
                               "port": 22 if ssh else None, "what": msg[:80]})
        hits = r.get("hits", {}).get("hits", [])
        if hits:
            newest = datetime.fromisoformat(hits[0]["_source"]["@timestamp"].replace("Z", "+00:00")).timestamp() * 1000
        return list(rows.values()), ticker, newest

    flt = [span, {"term": {"dataType.keyword": dtype}}, {"exists": {"field": "origin.ip"}}] + \
        ([{"term": {"target.port": port}}] if port else [])
    q = {"bool": {"filter": flt}}
    if dtype == "o365":                          # the ones UTMStack already placed are on the map via build_net_geo
        q["bool"]["must_not"] = [{"exists": {"field": "origin.geolocation.latitude"}}]
    r = os_call(path, {"size": 0, "query": q, "aggs": {
        "newest": {"max": {"field": "@timestamp"}},
        "src": {"terms": {"field": "dataSource.keyword", "size": 50}, "aggs": {
            "host": {"terms": {"field": "origin.host.keyword", "size": 1}},
            "ip": {"terms": {"field": "origin.ip.keyword", "size": 300},
                   "aggs": {"out": {"terms": {"field": "actionResult.keyword", "size": 4}}}}}}}})
    a = r.get("aggregations")
    if not a:
        return [], [], None
    for sb in a["src"]["buckets"]:
        site = _q(sb["key"])
        name = _q(sb["host"]["buckets"][0]["key"]) if sb["host"]["buckets"] and dtype != "o365" else site
        for ib in sb["ip"]["buckets"]:
            ip = _q(ib["key"])
            if not geoip.is_public(ip):
                continue
            d, f = _outcomes(ib["out"]["buckets"])
            rows[(site, ip)] = {"site": site, "name": name, "ip": ip, "count": ib["doc_count"], "blocked": d + f}
    t = os_call(path, {"size": 30, "sort": [{"@timestamp": "desc"}], "_source": ["@timestamp", "origin.ip", "dataSource", "target.port"],
                       "query": {"bool": {"filter": flt + [{"terms": {"actionResult.keyword": ["denied", "failed"]}}]}}})
    for h in t.get("hits", {}).get("hits", []):
        s_ = h["_source"]
        ip = (s_.get("origin") or {}).get("ip")
        if geoip.is_public(ip or "") and len(ticker) < 14:
            ticker.append({"t": s_.get("@timestamp"), "ip": ip, "site": _q(s_.get("dataSource")), "type": dtype,
                           "port": (s_.get("target") or {}).get("port")})
    return list(rows.values()), ticker, a["newest"].get("value")


def add_attackers(g, window, dtype, port=None):
    rows, ticker, newest = attacker_rows(window, dtype, port)
    if newest and (not g["_newest"] or newest > g["_newest"]):
        g["_newest"] = newest
    by_id = {x["id"]: x for x in g["sites"]}
    arcs = {(a["site"], a["dir"], a["cc"], a["city"]): a for a in g["arcs"]}
    countries = g["countries"]
    home = current_home()
    for r in rows:
        g["total"] += r["count"]; g["denied"] += r["blocked"]
        site = by_id.get(r["site"])
        if not site:                             # a server or tenant, not a firewall: no location of its own
            site = by_id[r["site"]] = {"id": r["site"], "name": r["name"], "lat": home["lat"], "lon": home["lon"],
                                       "city": home.get("city"), "loc_source": "home", "total": 0, "denied": 0}
            g["sites"].append(site)
        site["total"] += r["count"]; site["denied"] += r["blocked"]
        loc = GEO.lookup(r["ip"])
        if not loc:
            continue
        key = (r["site"], "in", loc["cc"], loc["city"])
        a = arcs.get(key)
        if not a:
            a = arcs[key] = {"site": r["site"], "dir": "in", "cc": loc["cc"], "country": loc["country"], "city": loc["city"],
                             "lat": round(loc["lat"], 3), "lon": round(loc["lon"], 3), "count": 0, "denied": 0,
                             "vpn": 0, "tor": 0, "hosting": 0}
            g["arcs"].append(a)
        a["count"] += r["count"]; a["denied"] += r["blocked"]
        if loc.get("net"):
            a[loc["net"]] = a.get(loc["net"], 0) + r["count"]
        c = countries.setdefault(loc["cc"], {"cc": loc["cc"], "country": loc["country"], "count": 0, "denied": 0, "in": 0, "out": 0})
        c["count"] += r["count"]; c["denied"] += r["blocked"]; c["in"] += r["count"]
    for x in ticker:
        loc = GEO.lookup(x["ip"]) or {}
        x.update(city=loc.get("city"), country=loc.get("country"), cc=loc.get("cc"), net=loc.get("net"),
                 lat=round(loc["lat"], 3) if loc.get("lat") is not None else None,
                 lon=round(loc["lon"], 3) if loc.get("lon") is not None else None)
        x.setdefault("proto", None)
        g["ticker"].append(x)


def anonymize(geo):
    """Wall-display mode: client firewall names and WAN addresses become Site A, Site B, ..."""
    def label(i):
        s = ""
        i += 1
        while i:
            i, r = divmod(i - 1, 26)
            s = chr(65 + r) + s
        return "Site " + s
    alias = {x["id"]: ("s%d" % i, label(i)) for i, x in enumerate(geo["sites"])}
    out = dict(geo)
    out["sites"] = [dict(x, id=alias[x["id"]][0], name=alias[x["id"]][1]) for x in geo["sites"]]
    out["arcs"] = [dict(x, site=alias.get(x["site"], ("?",))[0]) for x in geo["arcs"]]
    out["ticker"] = [dict(x, site=alias.get(x["site"], ("?", "?"))[1]) for x in geo["ticker"]]
    out["anonymized"] = True
    return out


def api_geo(window=60, anon=False, dtype="all", port=None):
    window = window if window in GEO_WINDOWS_S else 60
    dtype = dtype if dtype in GEO_TYPES else "all"
    port = port if isinstance(port, int) and 1 <= port <= 65535 else None
    with _geo_lock:
        if len(_geo_cache) > 200:                # many different ports tried: drop the old answers
            _geo_cache.clear()
        hit = _geo_cache.get((window, dtype, port))
        if not hit or time.time() - hit[0] >= GEO_TTL_S:
            hit = (time.time(), build_geo(window, dtype, port))
            _geo_cache[(window, dtype, port)] = hit
    data = hit[1]                                # shared cache: never modify it in place
    if anon:
        return anonymize(data)
    names = {x["id"]: x["name"] for x in data["sites"]}
    return dict(data, ticker=[dict(x, site=names.get(x["site"], x["site"])) for x in data["ticker"]])


# ---------------------------------------------------------------- one attacker: which ports, allowed or blocked
ATTACKER_TTL_S = 60
# A denied packet from a remote service port (443, 80, 53...) to a high port on our side is almost always a late
# reply to one of our own connections that the firewall had already closed ("Could not associate packet to any
# connection"), not an attack. Counted separately so the ports list shows what was really tried.
REPLY_TRAFFIC = {"bool": {"filter": [{"range": {"origin.port": {"gte": 1, "lte": 1023}}}, {"range": {"target.port": {"gte": 1024}}}]}}
_attacker_cache = {}
_attacker_lock = threading.Lock()


def _outcome_map(buckets):
    o = {_q(b["key"]).lower(): b["doc_count"] for b in buckets}
    return {"denied": o.get("denied", 0) + o.get("failed", 0), "allowed": o.get("success", 0)}


def _port_rows(buckets):
    rows = []
    for b in buckets:
        port = _num(b["key"], int)
        if port is None:
            continue
        row = {"port": port, "count": b["doc_count"], "proto": _q(b["proto"]["buckets"][0]["key"]) if b["proto"]["buckets"] else None}
        row.update(_outcome_map(b["out"]["buckets"]))
        rows.append(row)
    return rows


def build_attacker(key, hours):
    """Everything one remote address did in the last `hours`: outcomes, the ports it tried (denied vs allowed), which
    firewalls/servers it reached and the hosts behind them. Firewall, Linux, Windows and M365 logs carry origin.ip;
    syslog keeps the address in the message, and its sshd lines are port 22."""
    outcome = {"terms": {"field": "actionResult.keyword", "size": 5}}
    r = os_call("/v11-log-*/_search" + IX, {"size": 0, "track_total_hits": True, "query": {"bool": {"filter": [
        rng("now-%dh" % hours), {"term": {"origin.ip.keyword": key}}]}}, "aggs": {
        "first": {"min": {"field": "@timestamp"}}, "last": {"max": {"field": "@timestamp"}},
        "out": outcome,
        "types": {"terms": {"field": "dataType.keyword", "size": 10}},
        "replies": {"filter": REPLY_TRAFFIC, "aggs": {"src": {"terms": {"field": "origin.port", "size": 3}}}},
        "tries": {"filter": {"bool": {"must_not": [REPLY_TRAFFIC]}}, "aggs": {
            "port_count": {"cardinality": {"field": "target.port"}},
            "ports": {"terms": {"field": "target.port", "size": 25}, "aggs": {
                "out": outcome, "proto": {"terms": {"field": "protocol.keyword", "size": 1}}}}}},
        "reasons": {"terms": {"field": "log.logMessage.keyword", "size": 3}},
        "sites": {"terms": {"field": "dataSource.keyword", "size": 10}, "aggs": {
            "out": outcome, "name": {"terms": {"field": "log.deviceName.keyword", "size": 1}},
            "host": {"terms": {"field": "origin.host.keyword", "size": 1}}}},
        "targets": {"terms": {"field": "target.ip.keyword", "size": 10}, "aggs": {
            "out": outcome, "ports": {"terms": {"field": "target.port", "size": 5}}}},
    }})
    a = r.get("aggregations") or {}
    res = {"ip": key, "hours": hours, "total": r.get("hits", {}).get("total", {}).get("value", 0),
           "first": (a.get("first") or {}).get("value_as_string"), "last": (a.get("last") or {}).get("value_as_string"),
           "net": GEO.net_kind(key), "types": [{"type": _q(b["key"]), "count": b["doc_count"]} for b in (a.get("types") or {}).get("buckets", [])],
           "ports": _port_rows(((a.get("tries") or {}).get("ports") or {}).get("buckets", [])),
           "port_count": ((a.get("tries") or {}).get("port_count") or {}).get("value", 0),
           "replies": (a.get("replies") or {}).get("doc_count", 0),
           "reply_ports": [_num(b["key"], int) for b in ((a.get("replies") or {}).get("src") or {}).get("buckets", [])],
           "reasons": [{"text": _q(b["key"]), "count": b["doc_count"]} for b in (a.get("reasons") or {}).get("buckets", [])],
           "sites": [], "targets": [], "syslog_ssh": 0}
    res.update(_outcome_map((a.get("out") or {}).get("buckets", [])))
    names = {x["id"]: x["name"] for x in fw_sites()} if res["total"] else {}
    for b in (a.get("sites") or {}).get("buckets", []):
        site = _q(b["key"])
        name = next((_q(x["key"]) for k in ("name", "host") for x in b[k]["buckets"]), None) or names.get(site, site)
        row = {"site": site, "name": names.get(site, name), "count": b["doc_count"]}
        row.update(_outcome_map(b["out"]["buckets"]))
        res["sites"].append(row)
    for b in (a.get("targets") or {}).get("buckets", []):
        row = {"ip": _q(b["key"]), "count": b["doc_count"], "ports": [_num(x["key"], int) for x in b["ports"]["buckets"]]}
        row.update(_outcome_map(b["out"]["buckets"]))
        res["targets"].append(row)
    # syslog: the address is inside the message text (match_phrase on the exact address, then re-check it)
    s_ = os_call("/v11-log-syslog*/_search" + IX, {"size": 500, "sort": [{"@timestamp": "desc"}],
                                                  "_source": ["@timestamp", "log.message", "dataSource", "origin.host", "origin.process"],
                                                  "query": {"bool": {"filter": [rng("now-%dh" % hours), {"match_phrase": {"log.message": key}}]}}})
    ssh = {"denied": 0, "allowed": 0, "count": 0}
    for h in s_.get("hits", {}).get("hits", []):
        src = h["_source"]
        msg = (src.get("log") or {}).get("message") or ""
        if key not in IPV4_RE.findall(msg) or not str((src.get("origin") or {}).get("process") or "").startswith("sshd"):
            continue
        ssh["count"] += 1
        ssh["allowed" if msg.startswith("Accepted") else "denied"] += 1
        site = _q(src.get("dataSource")) or "syslog"
        row = next((x for x in res["sites"] if x["site"] == site), None)
        if row is None:
            row = {"site": site, "name": (src.get("origin") or {}).get("host") or site, "count": 0, "denied": 0, "allowed": 0}
            res["sites"].append(row)
        row["count"] += 1; row["denied" if not msg.startswith("Accepted") else "allowed"] += 1
        t = src.get("@timestamp")
        res["first"] = min(filter(None, (res["first"], t))) if t else res["first"]
        res["last"] = max(filter(None, (res["last"], t))) if t else res["last"]
    if ssh["count"]:
        res["syslog_ssh"] = ssh["count"]
        res["total"] += ssh["count"]; res["denied"] += ssh["denied"]; res["allowed"] += ssh["allowed"]
        row = next((x for x in res["ports"] if x["port"] == 22), None)
        if row is None:
            row = {"port": 22, "count": 0, "proto": "TCP", "denied": 0, "allowed": 0}
            res["ports"].append(row)
        for k in ("count", "denied", "allowed"):
            row[k] += ssh[k]
    res["ports"].sort(key=lambda x: (x["denied"], x["count"]), reverse=True)
    res["sites"].sort(key=lambda x: x["count"], reverse=True)
    return res


def api_attacker(ip, anon=False, hours=24):
    addr = parse_ip(ip)
    if addr is None:
        return {"error": "not a valid IP address"}
    key = str(addr)
    if not addr.is_global:
        return {"ip": key, "private": True, "note": "Private or reserved address: an internal device, not an outside attacker."}
    with _attacker_lock:
        hit = _attacker_cache.get(key)
    if not hit or time.time() - hit[0] >= ATTACKER_TTL_S:
        hit = (time.time(), build_attacker(key, hours))
        with _attacker_lock:
            if len(_attacker_cache) > 200:
                _attacker_cache.clear()
            _attacker_cache[key] = hit
    data = hit[1]
    if anon:                                     # wall screens never receive site names or internal addresses
        data = dict(data, sites=[dict(x, site="", name="Site %s" % chr(65 + i)) for i, x in enumerate(data["sites"])], targets=[])
    return data


# ---------------------------------------------------------------- report: denied and allowed connections, 24 h
def report_connections(hours=24):
    """Firewall traffic for the report: who was denied on which ports (inbound attackers), and which allowed
    connections ran between which addresses on which ports."""
    span = rng("now-%dh" % hours)
    inbound = {"exists": {"field": "origin.geolocation.latitude"}}       # the remote side started it
    denied = os_call(FW_SEARCH + IX, {"size": 0, "track_total_hits": True, "query": {"bool": {"filter": [
        span, {"term": {"actionResult.keyword": "denied"}}]}}, "aggs": {
        "replies": {"filter": {"bool": {"filter": [inbound, REPLY_TRAFFIC]}}},
        "inbound": {"filter": {"bool": {"filter": [inbound], "must_not": [REPLY_TRAFFIC]}}, "aggs": {
            "attackers": {"cardinality": {"field": "origin.ip.keyword"}},
            "ports": {"terms": {"field": "target.port", "size": 15}, "aggs": {
                "src": {"cardinality": {"field": "origin.ip.keyword"}}, "proto": {"terms": {"field": "protocol.keyword", "size": 1}}}},
            "top": {"terms": {"field": "origin.ip.keyword", "size": 20}, "aggs": {
                "country": {"terms": {"field": "origin.geolocation.country.keyword", "size": 1}},
                "ports": {"terms": {"field": "target.port", "size": 6}},
                "sites": {"terms": {"field": "log.deviceName.keyword", "size": 3}}}}}}}})
    ok = os_call(FW_SEARCH + IX, {"size": 0, "track_total_hits": True, "query": {"bool": {"filter": [
        span, {"term": {"actionResult.keyword": "success"}}]}}, "aggs": {
        "ports": {"terms": {"field": "target.port", "size": 15}, "aggs": {
            "src": {"cardinality": {"field": "origin.ip.keyword"}}, "dst": {"cardinality": {"field": "target.ip.keyword"}},
            "proto": {"terms": {"field": "protocol.keyword", "size": 1}}}},
        "inbound": {"filter": inbound, "aggs": {"top": {"terms": {"field": "origin.ip.keyword", "size": 15}, "aggs": {
            "country": {"terms": {"field": "origin.geolocation.country.keyword", "size": 1}},
            "site": {"terms": {"field": "log.deviceName.keyword", "size": 1}},
            "dst": {"terms": {"field": "target.ip.keyword", "size": 2}},
            "ports": {"terms": {"field": "target.port", "size": 4}}}}}},
        "flows": {"terms": {"field": "origin.ip.keyword", "size": 25}, "aggs": {
            "country": {"terms": {"field": "origin.geolocation.country.keyword", "size": 1}},
            "site": {"terms": {"field": "log.deviceName.keyword", "size": 1}},
            "dst": {"terms": {"field": "target.ip.keyword", "size": 3}, "aggs": {
                "country": {"terms": {"field": "target.geolocation.country.keyword", "size": 1}},
                "ports": {"terms": {"field": "target.port", "size": 3}}}}}}}})
    first = lambda b, k: _q(b[k]["buckets"][0]["key"]) if b[k]["buckets"] else None
    da, oa = (denied.get("aggregations") or {}).get("inbound") or {}, ok.get("aggregations") or {}
    out = {"hours": hours, "denied_total": denied.get("hits", {}).get("total", {}).get("value", 0),
           "denied_inbound": da.get("doc_count", 0),
           "denied_replies": ((denied.get("aggregations") or {}).get("replies") or {}).get("doc_count", 0), "attackers": (da.get("attackers") or {}).get("value", 0),
           "denied_ports": [], "top_attackers": [], "allowed_total": ok.get("hits", {}).get("total", {}).get("value", 0),
           "allowed_ports": [], "allowed_flows": [], "allowed_inbound": []}
    for b in ((oa.get("inbound") or {}).get("top") or {}).get("buckets", []):
        ip = _q(b["key"])
        out["allowed_inbound"].append({"ip": ip, "country": first(b, "country"), "site": first(b, "site"), "count": b["doc_count"],
                                       "net": GEO.net_kind(ip), "dst": [_q(x["key"]) for x in b["dst"]["buckets"]],
                                       "ports": [_num(x["key"], int) for x in b["ports"]["buckets"]]})
    for b in (da.get("ports") or {}).get("buckets", []):
        out["denied_ports"].append({"port": _num(b["key"], int), "proto": first(b, "proto"), "count": b["doc_count"],
                                    "sources": b["src"]["value"]})
    for b in (da.get("top") or {}).get("buckets", []):
        ip = _q(b["key"])
        out["top_attackers"].append({"ip": ip, "country": first(b, "country"), "count": b["doc_count"], "net": GEO.net_kind(ip),
                                     "ports": [_num(x["key"], int) for x in b["ports"]["buckets"]],
                                     "sites": [_q(x["key"]) for x in b["sites"]["buckets"]]})
    for b in (oa.get("ports") or {}).get("buckets", []):
        out["allowed_ports"].append({"port": _num(b["key"], int), "proto": first(b, "proto"), "count": b["doc_count"],
                                     "sources": b["src"]["value"], "destinations": b["dst"]["value"]})
    flows = []
    for b in (oa.get("flows") or {}).get("buckets", []):
        for d in b["dst"]["buckets"]:
            src, dst = _q(b["key"]), _q(d["key"])
            flows.append({"src": src, "src_country": first(b, "country"), "site": first(b, "site"),
                          "dir": "inbound" if geoip.is_public(src) else "outbound" if geoip.is_public(dst) else "internal",
                          "dst": dst, "dst_country": first(d, "country"), "count": d["doc_count"],
                          "ports": [_num(x["key"], int) for x in d["ports"]["buckets"]]})
    out["allowed_flows"] = sorted(flows, key=lambda x: x["count"], reverse=True)[:25]
    return out


# ---------------------------------------------------------------- support info (logo click)
COPYRIGHT = "© 2026 Victor Beitner. All rights reserved."
DEFAULT_SUPPORT = "Cyber Security Canada|info@cybersecuritycanada.com||https://cybersecuritycanada.com"
STARTED_AT = datetime.now(timezone.utc).isoformat()


def parse_support(text):
    """SUPPORT_CONTACT='Name|email|phone|url' -> dict; empty parts are dropped."""
    parts = [x.strip() for x in (text or DEFAULT_SUPPORT).split("|")] + ["", "", "", ""]
    name, email, phone, url = parts[:4]
    if url and not re.match(r"^https?://", url):
        url = "https://" + url
    return {k: v for k, v in (("name", name), ("email", email), ("phone", phone), ("url", url)) if v}


SUPPORT = parse_support(env("SUPPORT_CONTACT"))


def current_support():
    raw = settings_store.get(DATA_DIR, "support")
    return SUPPORT if raw is None else parse_support(raw)


def api_support(anon=False):
    """Contact + health summary for the support panel. Never includes secrets or client names."""
    out = {"contact": current_support(), "version": VERSION, "installed": env("INSTALLED_AT") or None, "copyright": COPYRIGHT}
    if anon:                                     # wall screen: contact and version only
        return out
    with _lock:
        d = dict(_state["data"])
    k = d.get("kpi") or {}
    out.update(host=HOST_NAME, started=STARTED_AT, transport=TRANSPORT,
               opensearch=(d.get("cluster") or {}).get("status"),
               data_age_s=k.get("lag_s"), sources_online=k.get("sources_online"), sources_total=k.get("sources_total"),
               error=d.get("error"), tls=bool(TLS_CERT and TLS_KEY))
    return out


_range_cache = {}
_range_lock = threading.Lock()


def data_for(hours):
    """Dashboard data for a window. 24 h comes from the background refresher; 1 h / 6 h are built on
    request and shared for REFRESH_S seconds, so extra viewers do not multiply OpenSearch load."""
    if hours == 24:
        with _lock:
            return dict(_state["data"])
    with _range_lock:
        hit = _range_cache.get(hours)
        if hit and time.time() - hit[0] < REFRESH_S:
            return dict(hit[1])
        try:
            data = collect(hours)
        except Exception as e:
            data = dict(hit[1]) if hit else {}
            data["error"] = str(e)
        _range_cache[hours] = (time.time(), data)
        return dict(data)


def refresher():
    while True:
        t0 = time.time()
        try:
            data = collect()
            data["took_ms"] = int((time.time() - t0) * 1000)
        except Exception as e:  # keep serving the last good data, flag the error
            with _lock:
                data = dict(_state["data"]) if "minutes" in _state["data"] else {}
            data["error"] = str(e)
        with _lock:
            _state["data"] = data
        time.sleep(max(0.5, REFRESH_S - (time.time() - t0)))


# ---------------------------------------------------------------- login lockout (per client IP)
LOGIN_MAX_FAILURES = int(env("LOGIN_MAX_FAILURES", "5"))
LOGIN_LOCK_S = float(env("LOGIN_LOCK_S", "900"))
_logins = {}                                     # ip -> {"fails": [t, ...], "until": t}
_logins_lock = threading.Lock()
# Server-wide budget against guessing spread over many addresses: past this many failures a minute (all addresses
# together), every failed attempt is answered slowly instead of locking anyone out.
LOGIN_SURGE_PER_MIN = int(env("LOGIN_SURGE_PER_MIN", "30") or "0")
_login_fail_times = []
_surge_noted = [0.0]


def login_surge():
    """True while failures from all addresses together exceed LOGIN_SURGE_PER_MIN."""
    if not LOGIN_SURGE_PER_MIN:
        return False
    now = time.time()
    with _logins_lock:
        while _login_fail_times and now - _login_fail_times[0] > 60:
            _login_fail_times.pop(0)
        busy = len(_login_fail_times) > LOGIN_SURGE_PER_MIN
        if busy and now - _surge_noted[0] > 60:
            _surge_noted[0] = now
            print("login: %d failed logins in the last minute from all addresses: slowing every failed attempt down"
                  % len(_login_fail_times), flush=True)
    return busy


def client_error(where, e):
    """Log the real exception, give the browser a short message and an id to find it in the logs."""
    ref = os.urandom(3).hex()
    print("error %s in %s: %s: %s" % (ref, where, type(e).__name__, str(e)[:500]), flush=True)
    msg = str(e) if isinstance(e, (RuntimeError, ValueError)) and str(e)[:1].isupper() else "internal error"
    return {"error": "%s (ref %s)" % (msg[:160], ref)}


def login_attempt(ip, check):
    """Run the (microsecond) password check and the failure bookkeeping as one atomic step per server, so parallel
    guesses are serialised: after LOGIN_MAX_FAILURES wrong ones the address is locked, even for the right password.
    Returns (ok, seconds_locked)."""
    now = time.time()
    with _logins_lock:
        if len(_logins) > 10000:                 # bound memory under a spray from many addresses
            for k in [k for k, v in _logins.items() if v["until"] < now][:5000]:
                del _logins[k]
        st = _logins.setdefault(ip, {"fails": [], "until": 0.0})
        if st["until"] > now:
            return False, st["until"] - now
        ok = check()
        if ok:
            st["fails"] = []
            return True, 0
        st["fails"] = [t for t in st["fails"] if now - t < LOGIN_LOCK_S] + [now]
        if len(_login_fail_times) < 10000:
            _login_fail_times.append(now)
        if len(st["fails"]) >= LOGIN_MAX_FAILURES:
            st["until"] = now + LOGIN_LOCK_S
            print("login: %s locked for %d s after %d failed logins" % (ip, LOGIN_LOCK_S, len(st["fails"])), flush=True)
        return False, 0


# ---------------------------------------------------------------- users, sessions and email sign-in links
# Invited users sign in with a one-time link sent by email (users_store, mailer); the installer's username and
# password stay as the break-glass admin login, through the sign-in page or HTTP Basic (scripts, install.sh).
PUBLIC_URL = env("PUBLIC_URL").rstrip("/")      # where links point; the Settings panel can override it
ADMIN_EMAIL = env("ADMIN_EMAIL")                 # install.sh --admin-email: made an admin at start-up
SESSION_DAYS = float(env("SESSION_DAYS", "7") or "7")
LINK_MINUTES = int(env("LINK_MINUTES", "15") or "15")
REAUTH_S = int(env("REAUTH_MINUTES", "15") or "15") * 60
LINK_PER_IP, LINK_PER_EMAIL, LINK_WINDOW_S = 5, 3, 900
SESSION_COOKIE = "obs_session"
_link_reqs = {}                                  # ("ip"|"email", value) -> [request times]
_cred_tags = {}


def login_required():
    return bool(current_dash_pass()) or users_store.has_users(DATA_DIR)


def cred_tag():
    """Fingerprint of the break-glass password: a session opened with it ends when the password changes. Slow hash,
    computed once per password, because an installer password is stored in clear text."""
    stored = current_dash_pass() or ""
    if stored not in _cred_tags:
        _cred_tags.clear()
        _cred_tags[stored] = hashlib.pbkdf2_hmac("sha256", stored.encode(), b"observatory-session", 100_000).hex()[:32]
    return _cred_tags[stored]


def current_public_url():
    return (settings_store.get(DATA_DIR, "public_url") or PUBLIC_URL).rstrip("/")


def mail_config():
    g = lambda k: settings_store.get(DATA_DIR, k) or ""
    return {"method": g("mail_method"), "from": g("mail_from"), "smtp_host": g("smtp_host"), "smtp_port": g("smtp_port"),
            "smtp_security": g("smtp_security"), "smtp_user": g("smtp_user"), "smtp_pass": g("smtp_pass"),
            "graph_tenant": g("graph_tenant"), "graph_client_id": g("graph_client_id"), "graph_secret": g("graph_secret")}


def link_status():
    """None when sign-in links can be sent, else what is missing. Links never use the request's Host header: an
    attacker could otherwise have a victim's link point at their own server."""
    why = mailer.configured(mail_config())
    if why:
        return why
    return None if current_public_url() else "set the dashboard's public address"


def link_allowed(ip, email):
    """At most LINK_PER_IP requests per address and LINK_PER_EMAIL per mailbox in LINK_WINDOW_S."""
    now = time.time()
    keys = ((("ip", ip), LINK_PER_IP), (("email", email), LINK_PER_EMAIL))
    with _logins_lock:
        if len(_link_reqs) > 10000:
            _link_reqs.clear()
        ok = True
        for key, cap in keys:
            _link_reqs[key] = [t for t in _link_reqs.get(key, []) if now - t < LINK_WINDOW_S]
            ok = ok and len(_link_reqs[key]) < cap
        if ok:
            for key, _ in keys:
                _link_reqs[key].append(now)
    return ok


def _mail_page(lines, url, button):
    paras = "".join('<p style="margin:0 0 14px">%s</p>' % escape(t) for t in lines)
    return ('<div style="font-family:Segoe UI,Helvetica,Arial,sans-serif;font-size:15px;color:#1b2a3a;max-width:520px">'
            '<p style="margin:0 0 18px;font-weight:700;font-size:17px">UTMStack Observatory</p>%s'
            '<p style="margin:22px 0"><a href="%s" style="background:#0b6e8a;color:#fff;padding:11px 20px;border-radius:4px;'
            'text-decoration:none;font-weight:600">%s</a></p>'
            '<p style="margin:0;color:#5b6b78;font-size:13px">Or paste this address into your browser:<br>%s</p></div>'
            % (paras, escape(url), escape(button), escape(url)))


def send_sign_in_link(email, ip):
    """Runs on its own thread, so the request is answered the same way, at the same speed, for any address."""
    try:
        if not users_store.get_user(DATA_DIR, email):
            print("login: sign-in link requested from %s for %s, which is not an invited user" % (ip, email), flush=True)
            return
        why = link_status()
        if why:
            print("login: cannot email a sign-in link to %s: %s" % (email, why), flush=True)
            return
        url = current_public_url() + "/login#t=" + users_store.new_link(email, LINK_MINUTES)
        lines = ["Someone (hopefully you) asked to sign in to the UTMStack Observatory dashboard as %s." % email,
                 "This link works once and expires in %d minutes. It was requested from %s." % (LINK_MINUTES, ip),
                 "If you did not ask for it, ignore this email: nobody can sign in without the link."]
        mailer.send(mail_config(), email, "Your UTMStack Observatory sign-in link",
                    "\n\n".join(lines[:2]) + "\n\nSign in: " + url + "\n\n" + lines[2] + "\n",
                    _mail_page(lines, url, "Sign in"))
        print("login: sign-in link emailed to %s (requested from %s)" % (email, ip), flush=True)
    except Exception as e:
        print("login: sign-in link to %s failed: %s" % (email, str(e)[:300]), flush=True)


def send_invite(email, by):
    try:
        if link_status():
            return
        url = current_public_url() + "/login"
        lines = ["%s gave you access to the UTMStack Observatory dashboard." % by,
                 "To sign in, open the dashboard and enter this email address; you will get a one-time sign-in link. "
                 "There is no password to remember."]
        mailer.send(mail_config(), email, "You have access to UTMStack Observatory",
                    "\n\n".join(lines) + "\n\nDashboard: " + url + "\n", _mail_page(lines, url, "Open the dashboard"))
        print("users: invitation emailed to %s" % email, flush=True)
    except Exception as e:
        print("users: invitation to %s failed: %s" % (email, str(e)[:300]), flush=True)


_layout_lock = threading.Lock()                  # one writer at a time; version check + save are atomic together
_settings_lock = threading.Lock()


def api_settings():
    """The settings drawer's form values: override-or-env-default for plain fields, just a flag for secrets."""
    state = settings_store.public_state(DATA_DIR)
    state.update(
        dash_user=settings_store.get(DATA_DIR, "dash_user", DASH_USER),
        support=settings_store.get(DATA_DIR, "support", env("SUPPORT_CONTACT")),
        home=settings_store.get(DATA_DIR, "home", env("HOME_LOCATION")),
        sites=settings_store.get(DATA_DIR, "sites", env("SITE_LOCATIONS")),
        ai_hosts=settings_store.get(DATA_DIR, "ai_hosts", env("AI_HOSTS")),
        public_url=current_public_url(),
        mail_status=link_status() or "",
    )
    return state


# The mail settings decide where sign-in links go and who sends them, so they need the same confirmation as the login.
SENSITIVE_SETTINGS = {"dash_user", "dash_pass", "abuseipdb_key", "virustotal_key", "support"} | settings_store.MAIL_KEYS
HOST_RE = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$|^\[[0-9A-Fa-f:.]+\]$")


def current_plain_settings():
    """Today's value of each non-secret sensitive setting, so re-sending an unchanged one needs no confirmation."""
    same = {k: settings_store.get(DATA_DIR, k) or "" for k in settings_store.MAIL_KEYS - settings_store.SECRET_KEYS}
    same.update(dash_user=current_dash_user(), support=settings_store.get(DATA_DIR, "support", env("SUPPORT_CONTACT")) or "",
                public_url=current_public_url())
    return same


def validate_settings_patch(patch):
    """Reject values that would be silently useless or dangerous; settings_store.save() only checks shape/size."""
    if "dash_user" in patch and not patch["dash_user"].strip():
        raise ValueError("the dashboard username cannot be empty")
    if "dash_pass" in patch and len(patch["dash_pass"]) < 12:
        raise ValueError("the dashboard password must be at least 12 characters")
    if patch.get("public_url"):
        patch["public_url"] = patch["public_url"].strip().rstrip("/")
        u = urlparse(patch["public_url"])
        try:
            u.port
            ok = (u.scheme in ("http", "https") and not (u.path or u.params or u.query or u.fragment or u.username)
                  and bool(u.hostname) and (HOST_RE.match(u.hostname) or ipaddress.ip_address(u.hostname)))
        except ValueError:
            ok = False
        if not ok:
            raise ValueError("public address must look like https://observatory.example.com:8765 (no path)")
    if patch.get("mail_method", "") not in ("", "smtp", "graph"):
        raise ValueError("mail_method must be smtp, graph or empty")
    if patch.get("smtp_security", "") not in ("", "starttls", "tls", "none"):
        raise ValueError("smtp_security must be starttls, tls or none")
    if patch.get("smtp_port") and not (patch["smtp_port"].isdigit() and 0 < int(patch["smtp_port"]) < 65536):
        raise ValueError("SMTP port must be a number 1-65535")
    if patch.get("smtp_host") and not HOST_RE.match(patch["smtp_host"]):
        raise ValueError("SMTP server must be a host name or address")
    if patch.get("mail_from"):
        try:
            patch["mail_from"] = users_store.norm_email(patch["mail_from"])
        except ValueError:
            raise ValueError("the sender must be a single email address")
    for k in ("graph_tenant", "graph_client_id"):
        if patch.get(k) and not re.match(r"^[A-Za-z0-9.-]{1,100}$", patch[k]):
            raise ValueError("%s must be a GUID or domain name" % k.replace("_", " "))
    if patch.get("home") and not parse_loc(patch["home"]):
        raise ValueError("home must be 'lat,lon[,city]'")
    if patch.get("sites"):
        for item in patch["sites"].split(";"):
            key, _, loc = item.partition("=")
            if key.strip() and not parse_loc(loc):
                raise ValueError("sites: bad location for %r" % key.strip())
    if patch.get("ai_hosts"):
        for p in patch["ai_hosts"].split(","):
            if p.strip() and "=" not in p:
                raise ValueError("ai_hosts must be 'name=ip,name=ip'")
    if patch.get("report_hour"):
        try:
            if not 0 <= int(patch["report_hour"]) <= 23:
                raise ValueError
        except ValueError:
            raise ValueError("report_hour must be 0-23")


class _Watchdog:
    """Closes connections that have not delivered a complete request line + headers within HEADER_DEADLINE_S.
    The socket timeout alone is per read, so a client trickling one header line every few seconds would hold a
    thread forever (slowloris)."""
    def __init__(self):
        self._lock, self._due = threading.Lock(), {}
        threading.Thread(target=self._run, daemon=True).start()

    def arm(self, sock):
        with self._lock:
            self._due[sock] = time.time() + HEADER_DEADLINE_S

    def disarm(self, sock):
        with self._lock:
            self._due.pop(sock, None)

    def _run(self):
        while True:
            time.sleep(1)
            now = time.time()
            with self._lock:
                late = [k for k, t in self._due.items() if t < now]
                for k in late:
                    del self._due[k]
            for k in late:
                try:
                    k.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass


WATCHDOG = _Watchdog()


def host_ok(host):
    """With no login configured the server only listens on localhost; refuse other Host names there, so a
    DNS-rebinding page cannot reach it through the victim's browser."""
    name = (host or "").strip().lower()
    name = name[1:].split("]")[0] if name.startswith("[") else name.rsplit(":", 1)[0] if name.count(":") == 1 else name
    return name in {"localhost", "127.0.0.1", "::1"} | ALLOWED_HOSTS


class Handler(BaseHTTPRequestHandler):
    server_version = "UTMStack-Observatory"     # no Python / BaseHTTP version in the Server header
    sys_version = ""
    timeout = REQUEST_TIMEOUT_S                 # idle or slow clients are dropped instead of holding a thread forever

    def log_message(self, *a):
        pass

    def handle_one_request(self):
        WATCHDOG.arm(self.connection)
        try:
            super().handle_one_request()
        finally:
            WATCHDOG.disarm(self.connection)

    def parse_request(self):
        ok = super().parse_request()
        WATCHDOG.disarm(self.connection)        # headers are in; the body has its own Content-Length limits
        return ok

    def setup(self):
        """Do the TLS handshake here, in this connection's own thread — not on the listening socket, which
        would serialise every client's handshake behind the accept loop (one slow/idle client stalls all)."""
        ctx = getattr(self.server, "tls_context", None)
        if ctx:
            self.request.settimeout(self.timeout)
            self.request = ctx.wrap_socket(self.request, server_side=True)
        super().setup()

    def send_error(self, code, message=None, explain=None):
        """Python's own error pages (bad request line, unknown method) get the same headers as everything else."""
        self.close_connection = True
        if self.request_version == "HTTP/0.9":     # a garbled request line: answer as HTTP/1.0 so headers go out
            self.request_version = "HTTP/1.0"
        text = (message or self.responses.get(code, ("Error",))[0])[:200]
        self.send(code, "text/plain; charset=utf-8", text.encode("utf-8", "replace"),
                  {"Allow": "GET, PUT, POST"} if code in (405, 501) else None)

    def _method_not_allowed(self):
        self.send(405, "text/plain", b"method not allowed", {"Allow": "GET, PUT, POST"})

    do_DELETE = do_PATCH = do_OPTIONS = do_TRACE = do_CONNECT = _method_not_allowed

    def do_HEAD(self):
        self._head_only = True
        self.do_GET()

    def send(self, code, ctype, body, extra=None):
        head_only, self._head_only = getattr(self, "_head_only", False), False
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", (extra or {}).pop("Cache-Control", "no-store"))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                         "img-src 'self' data: blob: %s; connect-src 'self' %s; worker-src 'self' blob:; child-src blob:; "
                         "object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'" % (TILE_HOST, TILE_HOST))
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        if isinstance(self.connection, ssl.SSLSocket):
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    # ------------------------------------------------------------ who is asking
    def cookie_token(self):
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == SESSION_COOKIE and v:
                return v
        return None

    def session_ident(self):
        tok = self.cookie_token()
        return users_store.get_session(DATA_DIR, tok, cred_tag()) if tok else None

    def gate(self, admin=False):
        """Authenticate the request: a session cookie, else Basic credentials (the break-glass admin login) with a
        per-IP lockout. Sends the 302/401/403/429 itself; returns True when allowed and sets self.ident.
        Requests without credentials do not count as failures."""
        self.ident = None
        if not login_required():
            if host_ok(self.headers.get("Host")):
                self.ident = {"email": None, "role": "admin", "method": "none", "auth_time": time.time()}
                return True
            self.send(403, "text/plain", b"This dashboard has no login and only answers to localhost.")
            return False
        ident = self.session_ident()
        if ident is None and self.headers.get("Authorization"):
            ip = self.client_address[0]
            ok, wait = login_attempt(ip, self.authorized)
            if wait:
                self.send(429, "text/plain", b"Too many failed logins from this address. Try again later.",
                          {"Retry-After": str(int(wait) + 1)})
                return False
            if ok:
                ident = {"email": None, "role": "admin", "method": "password", "auth_time": time.time()}
            else:
                print("login: failed login from %s" % ip, flush=True)
                time.sleep(3 if login_surge() else 0.5)   # slow down password guessing; much slower during a spread-out attack
        if ident is None:
            # no WWW-Authenticate: a browser's own password prompt would pop up over the sign-in page
            if urlparse(self.path).path in ("/", "/index.html"):
                self.send(302, "text/plain", b"sign in at /login", {"Location": "/login"})
            else:
                self.send(401, "application/json", b'{"error":"sign in required","login":"/login"}')
            return False
        if admin and ident["role"] != "admin":
            self.send(403, "application/json", b'{"error":"only an admin can do this"}')
            return False
        self.ident = ident
        return True

    def authorized(self):
        """HTTP Basic with the break-glass username and password."""
        h = self.headers.get("Authorization", "")
        if h.startswith("Basic "):
            try:
                user, _, pw = base64.b64decode(h[6:]).decode().partition(":")
            except Exception:
                return False
            return password_ok(user, pw)
        return False

    def who(self):
        return "%s (%s)" % ((self.ident or {}).get("email") or "password login", self.client_address[0])

    def reconfirm(self, cur, need, what):
        """Sensitive changes: the password again for a password sign-in; for an email-link sign-in, a sign-in from the
        last REAUTH_S (there is no password to ask for). Sends the refusal itself; returns True when confirmed."""
        ident = self.ident
        if ident["method"] == "link":
            if time.time() - ident["auth_time"] <= REAUTH_S:
                return True
            print("audit: %s refused for %s (sign-in older than %d min)" % (what, self.who(), REAUTH_S // 60), flush=True)
            self.send(403, "application/json", json.dumps(
                {"error": "for safety this needs a sign-in from the last %d minutes: sign out, then sign in with a new link"
                 % (REAUTH_S // 60), "reauth": True}).encode())
            return False
        if ident["method"] == "none" or not current_dash_pass():
            return True
        ok, wait = login_attempt(self.client_address[0], lambda: isinstance(cur, str) and check_password(cur))
        if ok:
            return True
        print("audit: %s refused for %s (wrong current password)" % (what, self.client_address[0]), flush=True)
        self.send(429 if wait else 403, "application/json", json.dumps(
            {"error": "too many wrong passwords, try again later" if wait else need}).encode())
        return False

    def read_json(self, cap):
        """The request body as a JSON object, CSRF-checked; None after sending the error."""
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = -1
        if not 0 <= n <= cap:
            self.send(400, "application/json", b'{"error":"request too large or missing length"}')
            self.close_connection = True
            return None
        raw = self.rfile.read(n)                   # always consume the body, or a rejected request resets the socket
        if not layout_store.csrf_ok(self.headers):
            self.send(403, "application/json", b'{"error":"forbidden"}')
            return None
        try:
            req = json.loads(raw or b"{}")
        except ValueError:
            req = None
        if not isinstance(req, dict):
            self.send(400, "application/json", b'{"error":"request body must be a JSON object"}')
            return None
        return req

    def session_cookie(self, token, max_age):
        secure = "; Secure" if isinstance(self.connection, ssl.SSLSocket) else ""
        return "%s=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=%d%s" % (SESSION_COOKIE, token, max_age, secure)

    def start_session(self, email, method):
        token = users_store.new_session(DATA_DIR, email, method, SESSION_DAYS, cred_tag() if method == "password" else "")
        self.send(200, "application/json", b'{"ok":true}',
                  {"Set-Cookie": self.session_cookie(token, int(SESSION_DAYS * 86400))})

    # ------------------------------------------------------------ sign-in endpoints (no session needed)
    def auth_post(self, path):
        ip = self.client_address[0]
        if path == "/auth/logout":
            if self.read_json(1024) is None:
                return
            tok = self.cookie_token()
            if tok:
                users_store.end_session(DATA_DIR, tok)
            self.send(200, "application/json", b'{"ok":true}', {"Set-Cookie": self.session_cookie("", 0)})
            return
        req = self.read_json(2048)
        if req is None:
            return
        if path == "/auth/request":
            try:
                email = users_store.norm_email(req.get("email"))
            except ValueError as e:
                self.send(400, "application/json", json.dumps({"error": str(e)}).encode())
                return
            if link_allowed(ip, email):
                threading.Thread(target=send_sign_in_link, args=(email, ip), daemon=True).start()
            else:
                print("login: sign-in link requests from %s for %s rate-limited" % (ip, email), flush=True)
            # same answer for invited, unknown and rate-limited addresses: nobody can probe who has access
            self.send(200, "application/json", json.dumps({"ok": True, "minutes": LINK_MINUTES}).encode())
        elif path == "/auth/verify":
            got = []
            ok, wait = login_attempt(ip, lambda: got.append(users_store.use_link(DATA_DIR, req.get("token"))) or bool(got[0]))
            if not ok:
                print("login: %s sign-in link from %s" % ("locked out:" if wait else "invalid or expired", ip), flush=True)
                self.send(429 if wait else 403, "application/json", json.dumps(
                    {"error": "too many failed sign-ins from this address, try again later" if wait else
                     "this link has expired or was already used: ask for a new one"}).encode())
                return
            print("login: %s signed in with an email link from %s" % (got[0]["email"], ip), flush=True)
            self.start_session(got[0]["email"], "link")
        elif path == "/auth/password":
            user, pw = req.get("user"), req.get("password")
            ok, wait = login_attempt(ip, lambda: password_ok(user, pw))
            if not ok:
                if not wait:
                    print("login: failed login from %s" % ip, flush=True)
                    time.sleep(3 if login_surge() else 0.5)
                self.send(429 if wait else 403, "application/json", json.dumps(
                    {"error": "too many failed logins from this address, try again later" if wait else
                     "wrong username or password"}).encode())
                return
            print("login: password (break-glass) sign-in from %s" % ip, flush=True)
            self.start_session(None, "password")
        else:
            self.send(404, "text/plain", b"not found")

    # ------------------------------------------------------------ user management (admins)
    def api_me(self):
        i = self.ident
        return {"email": i["email"], "role": i["role"], "method": i["method"],
                "name": i["email"] or (current_dash_user() if i["method"] == "password" else "local"),
                "reauth_minutes": REAUTH_S // 60}

    def api_users(self):
        return {"users": users_store.list_users(DATA_DIR), "me": self.ident["email"], "link_status": link_status() or "",
                "public_url": current_public_url()}

    def users_post(self, req):
        action, email, role = req.get("action"), req.get("email"), req.get("role", "viewer")
        if action not in ("add", "remove"):
            self.send(400, "application/json", b'{"error":"action must be add or remove"}')
            return
        try:
            email = users_store.norm_email(email)
        except ValueError as e:
            self.send(400, "application/json", json.dumps({"error": str(e)}).encode())
            return
        if email == self.ident["email"] and (action == "remove" or role != "admin"):
            self.send(400, "application/json", b'{"error":"you cannot remove or demote yourself: ask another admin, '
                      b'or use the installer password"}')
            return
        if not self.reconfirm(req.get("current_password", ""), "enter your current password to change users", "user change"):
            return
        try:
            if action == "add":
                new = users_store.get_user(DATA_DIR, email) is None
                users_store.set_user(DATA_DIR, email, role, by=self.ident["email"] or "password login")
                print("audit: user %s %s as %s by %s" % (email, "added" if new else "changed", role, self.who()), flush=True)
                if new and req.get("invite"):
                    threading.Thread(target=send_invite, args=(email, self.ident["email"] or "An administrator"),
                                     daemon=True).start()
            elif users_store.remove_user(DATA_DIR, email):
                print("audit: user %s removed by %s" % (email, self.who()), flush=True)
        except ValueError as e:
            self.send(400, "application/json", json.dumps({"error": str(e)}).encode())
            return
        self.send(200, "application/json", json.dumps(self.api_users()).encode())

    def mail_test(self, req):
        to = req.get("to") or self.ident["email"]
        try:
            to = users_store.norm_email(to)
        except ValueError:
            self.send(400, "application/json", b'{"error":"enter the address to send the test email to"}')
            return
        if not link_allowed(self.client_address[0], "test:" + to):
            self.send(429, "application/json", b'{"error":"too many test emails, wait a few minutes"}')
            return
        try:
            mailer.send(mail_config(), to, "UTMStack Observatory test email",
                        "This test email shows the dashboard can send sign-in links.\n")
        except RuntimeError as e:
            print("mail: test email to %s failed: %s" % (to, e), flush=True)
            self.send(200, "application/json", json.dumps({"ok": False, "error": str(e)[:300]}).encode())
            return
        print("mail: test email sent to %s by %s" % (to, self.who()), flush=True)
        self.send(200, "application/json", json.dumps({"ok": True, "to": to}).encode())

    def cluster_view(self):
        d = api_cluster()
        if isinstance(d, dict):
            d["needs_password"] = self.ident["method"] == "password" and bool(current_dash_pass())
            if self.ident["role"] != "admin":
                d["can_fix"], d["viewer"] = False, True
        return d

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/healthz":                      # liveness only; no data, no auth
            self.send(200, "text/plain", b"ok")
            return
        if u.path == "/login":
            if login_required() and self.session_ident():
                self.send(302, "text/plain", b"already signed in", {"Location": "/"})
                return
            with open(os.path.join(HERE, "login.html"), "rb") as f:
                self.send(200, "text/html; charset=utf-8", f.read().replace(b'"/login.js"', b'"/login.js?v=' + VERSION.encode() + b'"'))
            return
        if u.path == "/login.js":
            with open(os.path.join(HERE, "login.js"), "rb") as f:
                self.send(200, "text/javascript; charset=utf-8", f.read())
            return
        if u.path == "/auth/status":                  # what the sign-in page offers; nothing about who has access
            self.send(200, "application/json", json.dumps(
                {"link": login_required() and link_status() is None, "password": bool(current_dash_pass()),
                 "login": login_required()}).encode())
            return
        if not self.gate(admin=u.path in ("/api/settings", "/api/users")):
            return
        p = {k: v[0] for k, v in parse_qs(u.query).items()}
        routes = {
            "/api/me": lambda: self.api_me(),
            "/api/users": lambda: self.api_users(),
            "/api/sources": lambda: api_sources(),
            "/api/source": lambda: api_source(p.get("name", "")[:200]),
            "/api/alerts": lambda: api_alerts(p),
            "/api/alert": lambda: api_alert(p.get("id", "")),
            "/api/lag": lambda: api_lag(),
            "/api/cluster": lambda: self.cluster_view(),
            "/api/storage": lambda: api_storage(),
            "/api/whois": lambda: api_whois(p.get("ip", "")[:64]),
            "/api/reputation": lambda: api_reputation(p.get("ip", "")[:64]),
            "/api/attacker": lambda: api_attacker(p.get("ip", "")[:64], p.get("anon") == "1"),
            "/api/support": lambda: api_support(p.get("anon") == "1"),
            "/api/settings": lambda: api_settings(),
            "/api/reports": lambda: {"reports": reports.list_reports(DATA_DIR), "report_hour": current_report_hour()},
            "/api/geo": lambda: api_geo(int(p["window"]) if p.get("window", "").isdigit() else 60,
                                        p.get("anon") == "1", p.get("type", "all"),
                                        int(p["port"]) if p.get("port", "").isdigit() else None),
        }
        if u.path == "/api/data":
            try:
                hours = int(p.get("range", "24"))
            except ValueError:
                hours = 24
            data = data_for(hours if hours in RANGES_H else 24)
            data["lag"] = lag_summary()
            self.send(200, "application/json", json.dumps(data).encode())
        elif u.path == "/api/history":
            try:
                body = json.dumps(compute_history()).encode()
            except Exception as e:
                body = json.dumps(client_error(u.path, e)).encode()
            self.send(200, "application/json", body)
        elif u.path in routes:
            try:
                body = json.dumps(routes[u.path]()).encode()
            except Exception as e:  # report to the UI instead of dropping the connection
                body = json.dumps(client_error(u.path, e)).encode()
            self.send(200, "application/json", body)
        elif u.path in ("/layout.js", "/app.js"):
            with open(os.path.join(HERE, u.path[1:]), "rb") as f:
                self.send(200, "text/javascript; charset=utf-8", f.read())
        elif u.path == "/api/layout":
            lay, notes = layout_store.load_with_notes(DATA_DIR)
            self.send(200, "application/json", json.dumps({"layout": lay, "notes": notes}).encode())
        elif u.path in MODULE_FILES:
            self.send(200, "text/javascript; charset=utf-8", module_body(u.path), {"Cache-Control": "private, max-age=86400"})
        elif u.path in STATIC_FILES:
            with open(os.path.join(HERE, u.path[1:]), "rb") as f:
                self.send(200, STATIC_FILES[u.path], f.read(), {"Cache-Control": "private, max-age=86400"})
        elif u.path == "/land.json":                  # static world outline for the live map
            with open(os.path.join(HERE, "land.json"), "rb") as f:
                self.send(200, "application/json", f.read(), {"Cache-Control": "private, max-age=86400"})
        elif u.path.startswith("/api/reports/"):
            fname = u.path[len("/api/reports/"):]
            path = reports.safe_path(DATA_DIR, fname)
            if not path or not os.path.exists(path):
                self.send(404, "text/plain", b"not found")
                return
            ctype = "application/pdf" if fname.endswith(".pdf") else "text/html; charset=utf-8"
            with open(path, "rb") as f:
                self.send(200, ctype, f.read(), {"Content-Disposition": 'attachment; filename="%s"' % fname})
        elif u.path in ("/", "/index.html"):
            with open(os.path.join(HERE, "index.html"), "rb") as f:
                page = f.read()
            # versioned script/style URLs: a browser holding an older copy cannot mix it with a new page after an upgrade
            for name in (b"/app.js", b"/layout.js", b"/maplibre-loader.mjs", b"/maplibre-gl.css"):
                page = page.replace(b'"' + name + b'"', b'"' + name + b"?v=" + VERSION.encode() + b'"')
            self.send(200, "text/html; charset=utf-8", page)
        else:
            self.send(404, "text/plain", b"not found")

    def do_PUT(self):
        u = urlparse(self.path)
        if not self.gate(admin=u.path == "/api/settings"):
            return
        if u.path not in ("/api/layout", "/api/settings"):
            self.send(404, "text/plain", b"not found")
            return
        cap = layout_store.MAX_BYTES if u.path == "/api/layout" else settings_store.MAX_BYTES
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = -1
        if not 0 <= n <= cap + 1024:
            self.send(400, "application/json", b'{"error":"request too large or missing length"}')
            self.close_connection = True
            return
        body = self.rfile.read(n)                 # always consume the body, or a rejected request resets the socket
        if not layout_store.csrf_ok(self.headers):
            self.send(403, "application/json", b'{"error":"forbidden"}')
            return
        try:
            req = json.loads(body or b"{}")
            if not isinstance(req, dict):
                raise ValueError("request body must be a JSON object")
            if u.path == "/api/layout":
                with _layout_lock:
                    current = layout_store.load(DATA_DIR)
                    if req.get("base_version") != current.get("version"):
                        self.send(409, "application/json", json.dumps({"error": "conflict", "layout": current}).encode())
                        return
                    saved = layout_store.save(DATA_DIR, req.get("layout"))
                print("audit: shared layout saved by %s" % self.who(), flush=True)
                self.send(200, "application/json", json.dumps({"layout": saved}).encode())
            else:
                cur = req.pop("current_password", "")
                same = current_plain_settings()
                changed = {k for k in SENSITIVE_SETTINGS & set(req) if k not in same or req[k] != same[k]}
                if changed and not self.reconfirm(cur, "enter your current password to change the login, API keys, "
                                                  "email or support contact", "settings change"):
                    return
                with _settings_lock:
                    validate_settings_patch(req)
                    if req.get("dash_pass"):
                        req["dash_pass"] = hash_password(req["dash_pass"])
                    settings_store.save(DATA_DIR, req)
                print("audit: settings changed by %s: %s" % (self.who(), ", ".join(sorted(req)) or "-"), flush=True)
                self.send(200, "application/json", json.dumps(settings_store.public_state(DATA_DIR)).encode())
        except ValueError as e:
            self.send(400, "application/json", json.dumps({"error": str(e)[:200]}).encode())

    def cluster_fix(self, raw):
        if not can_fix():
            self.send(409, "application/json", json.dumps({"error": "this installation's OpenSearch account is read-only; "
                      "re-run install.sh to create the fix account, or use the commands shown"}).encode())
            return
        try:
            req = json.loads(raw or b"{}")
        except ValueError:
            req = {}
        cur = req.get("current_password", "") if isinstance(req, dict) else ""
        if not self.reconfirm(cur, "enter your dashboard password to apply the fix", "cluster fix"):
            return
        try:
            self.send(200, "application/json", json.dumps(apply_cluster_fix(self.who())).encode())
        except Exception as e:
            self.send(500, "application/json", json.dumps(client_error("/api/cluster/fix", e)).encode())

    def do_POST(self):
        u = urlparse(self.path)
        if u.path.startswith("/auth/"):
            self.auth_post(u.path)
            return
        if not self.gate(admin=u.path in ("/api/cluster/fix", "/api/users", "/api/mail/test")):
            return
        if u.path in ("/api/users", "/api/mail/test"):
            req = self.read_json(4096)
            if req is not None:
                (self.users_post if u.path == "/api/users" else self.mail_test)(req)
            return
        if u.path not in ("/api/reports/generate", "/api/cluster/fix"):
            self.send(404, "text/plain", b"not found")
            return
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = -1
        if not 0 <= n <= 4096:
            self.send(400, "application/json", b'{"error":"request too large or missing length"}')
            self.close_connection = True
            return
        raw = self.rfile.read(n)                   # always consume the body, or a rejected request resets the socket
        if not layout_store.csrf_ok(self.headers):
            self.send(403, "application/json", b'{"error":"forbidden"}')
            return
        if u.path == "/api/cluster/fix":
            self.cluster_fix(raw)
            return
        p = {k: v[0] for k, v in parse_qs(u.query).items()}
        try:
            hours = int(p.get("hours", "24"))
        except ValueError:
            hours = 24
        try:
            meta = generate_report(hours)
            self.send(200, "application/json", json.dumps(meta).encode())
        except Exception as e:
            self.send(500, "application/json", json.dumps(client_error(u.path, e)).encode())


# ---------------------------------------------------------------- shared-address hint
# Behind Docker Swarm's ingress routing mesh every client reaches the container from the same overlay address
# (e.g. 10.0.0.2), so the per-address lockout and MAX_CONNECTIONS_PER_IP apply to all users together. install.sh
# publishes in host mode to avoid that; this logs a one-time hint when a deployment still looks like the mesh.
SHARED_ADDRESS_HINT_AFTER = int(env("SHARED_ADDRESS_HINT_AFTER", "100") or "0")


def connected_subnets(route_file="/proc/net/route"):
    """IPv4 subnets this container is directly attached to (routes without a gateway); [] where unavailable."""
    import struct
    nets = []
    try:
        with open(route_file) as f:
            for line in list(f)[1:]:
                p = line.split()
                if len(p) >= 8 and p[2] == "00000000" and p[1] != "00000000":
                    dest = socket.inet_ntoa(struct.pack("<I", int(p[1], 16)))
                    mask = socket.inet_ntoa(struct.pack("<I", int(p[7], 16)))
                    nets.append(ipaddress.ip_network("%s/%s" % (dest, mask), strict=False))
    except (OSError, ValueError):
        pass
    return nets


class SharedAddressWatch:
    """Watches the first `after` non-loopback connections. If they all came from one address on one of the
    container's own subnets, seen() returns the hint (once); a second address, or an outside one, ends the watch."""

    def __init__(self, after, subnets):
        self.after, self.subnets, self.ip, self.count, self.done = after, subnets, None, 0, not after or not subnets

    def seen(self, ip):
        if self.done or not ip or ip.startswith("127.") or ip == "::1":
            return None
        if self.ip is None:
            self.ip = ip
        elif ip != self.ip:
            self.done = True
            return None
        self.count += 1
        if self.count < self.after:
            return None
        self.done = True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if not any(addr.version == n.version and addr in n for n in self.subnets):
            return None
        return ("hint: the first %d connections all came from %s, an address on this container's own network. "
                "Behind Docker Swarm's ingress routing mesh every user looks like that, so the login lockout and "
                "MAX_CONNECTIONS_PER_IP are shared by all of them. Publish the port with mode=host "
                "(re-run install.sh) to see real client addresses." % (self.count, ip))


class Server(ThreadingHTTPServer):
    """Caps concurrent connections instead of spawning an unbounded thread per accept. tls_context, when set,
    is applied per-connection by Handler.setup() rather than to the listening socket (see setup() for why)."""
    tls_context = None
    request_queue_size = 128                     # socketserver's default listen backlog of 5 resets bursts of clients

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._conn_slots = threading.Semaphore(MAX_CONNECTIONS) if MAX_CONNECTIONS else None
        self._per_ip, self._per_ip_lock, self._owner = {}, threading.Lock(), {}
        self._address_watch = SharedAddressWatch(SHARED_ADDRESS_HINT_AFTER, connected_subnets())

    def process_request(self, request, client_address):
        ip = client_address[0] if isinstance(client_address, tuple) else ""
        with self._per_ip_lock:
            hint = self._address_watch.seen(ip)
            busy = MAX_CONNECTIONS_PER_IP and self._per_ip.get(ip, 0) >= MAX_CONNECTIONS_PER_IP
            if not busy:
                self._per_ip[ip] = self._per_ip.get(ip, 0) + 1
                self._owner[id(request)] = ip
        if hint:
            print(hint, flush=True)
        if busy or (self._conn_slots is not None and not self._conn_slots.acquire(blocking=False)):
            if not busy:
                self._release_ip(request)
            try:
                request.close()
            except OSError:
                pass
            return
        super().process_request(request, client_address)

    def _release_ip(self, request):
        with self._per_ip_lock:
            ip = self._owner.pop(id(request), None)
            if ip is not None:
                n = self._per_ip.get(ip, 1) - 1
                if n > 0:
                    self._per_ip[ip] = n
                else:
                    self._per_ip.pop(ip, None)

    def shutdown_request(self, request):
        super().shutdown_request(request)
        owned = id(request) in self._owner
        self._release_ip(request)
        if self._conn_slots is not None and owned:
            self._conn_slots.release()


# Demo mode: synthetic data for sales demos, screenshots and the manual (see demo.py). No OpenSearch needed.
DEMO = env("DEMO") == "1"
if DEMO:
    import demo  # noqa: E402
    demo.install(globals())

if __name__ == "__main__":
    if TRANSPORT == "docker-exec" and not OS_PASS and not DEMO:
        OS_PASS = get_password()
    if ADMIN_EMAIL:
        try:
            if users_store.seed_admin(DATA_DIR, ADMIN_EMAIL):
                print("users: %s added as an admin (ADMIN_EMAIL)" % ADMIN_EMAIL.lower(), flush=True)
        except ValueError:
            print("users: ADMIN_EMAIL %r is not a valid email address; ignored" % ADMIN_EMAIL, flush=True)
    if not login_required() and BIND not in ("127.0.0.1", "localhost", "::1") and env("ALLOW_NO_AUTH") != "1":
        sys.exit("Refusing to listen on %s without a login. Set DASH_PASS (or DASH_PASS_FILE), "
                 "bind to 127.0.0.1, or set ALLOW_NO_AUTH=1." % BIND)
    migrate_plain_password()
    threading.Thread(target=refresher, daemon=True).start()
    threading.Thread(target=history_loop, daemon=True).start()
    threading.Thread(target=lag_loop, daemon=True).start()
    if not DEMO:
        GEO.load(); GEO.start()
    threading.Thread(target=report_loop, daemon=True).start()
    srv = Server((BIND, PORT), Handler)
    scheme = "http"
    if TLS_CERT and TLS_KEY:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.minimum_version = ssl.TLSVersion.TLSv1_2
        tls.load_cert_chain(TLS_CERT, TLS_KEY)
        srv.tls_context = tls
        scheme = "https"
    print("UTMStack Observatory %s on %s://%s:%d  (opensearch via %s, login %s, data %s)" % (
        VERSION, scheme, BIND, PORT, "DEMO DATA" if DEMO else "direct" if TRANSPORT == "http" else "docker-exec", "on" if login_required() else "OFF", DATA_DIR), flush=True)
    srv.serve_forever()
