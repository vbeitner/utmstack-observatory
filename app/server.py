#!/usr/bin/env python3
"""UTMStack Observatory: a read-only operations dashboard for a UTMStack SIEM.

Reads from UTMStack's OpenSearch (events, alerts, ingest statistics) and keeps 30 days of hourly
aggregates in a local SQLite file. Python standard library only.

Configuration is by environment variable (see README.md). Secrets can be given as NAME or as
NAME_FILE (path to a file, e.g. a Docker secret under /run/secrets).
"""
import base64, hmac, json, os, re, shutil, ssl, subprocess, sys, threading, time
import urllib.error, urllib.request
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "1.13.0"
HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:                          # the container runs "python3 -I", which leaves this folder off sys.path
    sys.path.insert(0, HERE)
import layout_store  # noqa: E402  (needs the path above)
import settings_store  # noqa: E402
import reports  # noqa: E402
import geoip  # noqa: E402


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
DATA_DIR = env("DATA_DIR", HERE)
DASH_USER, DASH_PASS = env("DASH_USER", "admin"), secret("DASH_PASS")        # install-time defaults;
ABUSEIPDB_KEY = secret("ABUSEIPDB_KEY")        # current_*() below is what every request actually uses --
VIRUSTOTAL_KEY = secret("VIRUSTOTAL_KEY")      # it prefers whatever was saved live over these
PORT = int(env("PORT", "8765"))
BIND = env("BIND") or env("HOST") or ("0.0.0.0" if (DASH_PASS or settings_store.configured(DATA_DIR, "dash_pass")) else "127.0.0.1")
TLS_CERT, TLS_KEY = env("TLS_CERT"), env("TLS_KEY")
DISK_PATH = env("DISK_PATH", "/utmstack" if os.path.isdir("/utmstack") else "/")
HOST_NAME = env("HOST_NAME") or os.uname().nodename
TRANSPORT = "http" if OS_URL else "docker-exec"
REFRESH_S = 4
REQUEST_TIMEOUT_S = float(env("REQUEST_TIMEOUT_S", "15"))
MAX_CONNECTIONS = int(env("MAX_CONNECTIONS", "0") or "0")   # 0 = unlimited
DOCKER = ["sudo", "-n", "docker"]               # docker-exec transport only (bare-metal installs)


def current_dash_user():
    return settings_store.get(DATA_DIR, "dash_user") or DASH_USER


def current_dash_pass():
    return settings_store.get(DATA_DIR, "dash_pass") or DASH_PASS


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
_ctx = ssl.create_default_context()
_ctx.check_hostname = False                     # OpenSearch inside UTMStack uses its own self-signed certificate
_ctx.verify_mode = ssl.CERT_NONE


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
    # Password goes in on stdin, never on the command line: sudo logs command lines.
    cmd = DOCKER + ["exec", "-i", container_id(), "sh", "-c",
                    'read -r PW; curl -sk -m 25 -X %s -u "admin:$PW" -H "Content-Type: application/json" '
                    '--data-binary @- "https://localhost:9200%s"' % (method, path)]
    r = sh(cmd, input=OS_PASS + "\n" + json.dumps(body or {}), timeout=40)
    if r.returncode != 0:
        _state["cid"] = None
        raise RuntimeError("docker exec failed: " + r.stderr.strip()[:200])
    return json.loads(r.stdout)


def _call_http(path, body, method):
    data = None if method == "GET" else json.dumps(body or {}).encode()
    req = urllib.request.Request(OS_URL + path, data=data, method=method, headers={"Content-Type": "application/json"})
    if OS_USER:
        req.add_header("Authorization", "Basic " + base64.b64encode(("%s:%s" % (OS_USER, OS_PASS)).encode()).decode())
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
    }


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


def alert_ip_loc(*candidates):
    """Pick the first candidate dict (adversary / event origin / target, in caller's preference order) that has
    an ip, and return (ip, (lat, lon)) using that same dict's geolocation -- never mix an IP from one party with
    another party's coordinates."""
    for c in candidates:
        ip = c.get("ip")
        if ip:
            g = c.get("geolocation") or {}
            return ip, (g.get("latitude"), g.get("longitude"))
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


def api_whois(ip):
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return {"error": "not a valid IP address"}
    key = str(addr)
    hit = _whois_cache.get(key)
    if hit and time.time() - hit[0] < WHOIS_TTL_S:
        return hit[1]
    if not addr.is_global:
        res = {"ip": key, "private": True, "note": "Private, loopback or reserved address: it has no public WHOIS record."}
        _whois_cache[key] = (time.time(), res)
        return res
    req = urllib.request.Request("https://rdap.org/ip/" + key, headers={"Accept": "application/rdap+json", "User-Agent": "utmstack-observatory/1.0"})
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
        "https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90" % ip,
        headers={"Key": key, "Accept": "application/json", "User-Agent": "utmstack-observatory/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            d = json.loads(r.read(200_000))["data"]
    except Exception as e:
        return {"configured": True, "error": "AbuseIPDB lookup failed: %s" % str(e)[:120]}
    return {"configured": True, "score": d.get("abuseConfidenceScore"), "reports": d.get("totalReports"),
            "distinct_reporters": d.get("numDistinctUsers"), "last_reported": d.get("lastReportedAt"),
            "usage_type": d.get("usageType"), "isp": d.get("isp"), "domain": d.get("domain"),
            "whitelisted": d.get("isWhitelisted")}


def _virustotal(ip):
    key = current_virustotal_key()
    if not key:
        return {"configured": False}
    req = urllib.request.Request("https://www.virustotal.com/api/v3/ip_addresses/%s" % ip,
                                  headers={"x-apikey": key, "User-Agent": "utmstack-observatory/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            a = json.loads(r.read(500_000))["data"]["attributes"]
    except Exception as e:
        return {"configured": True, "error": "VirusTotal lookup failed: %s" % str(e)[:120]}
    stats = a.get("last_analysis_stats") or {}
    flagged = [v.get("result") for v in (a.get("last_analysis_results") or {}).values() if v.get("category") == "malicious"]
    return {"configured": True, "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0), "undetected": stats.get("undetected", 0),
            "reputation": a.get("reputation"), "as_owner": a.get("as_owner"), "country": a.get("country"),
            "flagged_by": [x for x in flagged if x][:8]}


def api_reputation(ip):
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
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
        if data:
            fix["steps"].append({"title": "Remove replicas from the existing data indices",
                                 "cmd": opensearch_put_cmd("/%s/_settings" % ",".join(data), '{"index":{"number_of_replicas":0}}')})
        for fam in system:
            # One request per family: the security plugin refuses a whole request when any index in it is protected.
            fix["steps"].append({"title": "Remove replicas from the system index %s" % fam,
                                 "cmd": opensearch_put_cmd("/%s/_settings?expand_wildcards=all" % fam,
                                                           '{"index":{"number_of_replicas":0}}')})
        fix["protected_note"] = ("A system-index step that answers 403 'no permissions' means OpenSearch protects that index: "
                                 "the admin password is not enough, it needs the super-admin certificate (the admin_dn "
                                 "certificate in opensearch.yml). The other steps are not affected.")
        if series:
            # Legacy template with order 0: it only applies when no composable template matches, so if UTMStack's own
            # (composable) template is ever fixed to match its indices, UTMStack's settings and mappings win.
            fix["steps"].append({"title": "Stop new daily indices getting a replica",
                                 "cmd": opensearch_put_cmd("/_template/single-node-no-replicas",
                                                           '{"index_patterns":[%s],"order":0,"settings":{"number_of_replicas":0}}'
                                                           % ",".join('"%s"' % x for x in series))})
    return {"status": h["status"], "nodes": h.get("number_of_data_nodes"), "active_pct": h.get("active_shards_percent_as_number"),
            "active": h.get("active_shards"), "primaries": h.get("active_primary_shards"), "unassigned": len(un), "unassigned_primaries": len(un_p),
            "reasons": reasons, "families": fam_rows, "decider": decider,
            "explained": ({"index": ex.get("index"), "shard": ex.get("shard"), "primary": ex.get("primary"), "text": ex.get("allocate_explanation")} if ex else None),
            "notes": notes, "fix": fix}


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
STATIC_FILES = {"/maplibre-gl.js": "text/javascript; charset=utf-8", "/maplibre-gl.css": "text/css; charset=utf-8"}
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


def empty_geo(window, dtype):
    return {"window_s": window, "type": dtype, "generated": datetime.now(timezone.utc).isoformat(), "age_s": None,
            "total": 0, "denied": 0, "failed": 0, "per_min": 0, "home": current_home(), "sites": [], "arcs": [],
            "arcs_total": 0, "countries": {}, "ticker": [], "_newest": None}


def build_geo(window, dtype="all"):
    g = build_net_geo(window, dtype) if dtype == "all" or dtype in NET_TYPES else empty_geo(window, dtype)
    for t in ATTACK_TYPES if dtype == "all" else ([dtype] if dtype in ATTACK_TYPES else []):
        try:
            add_attackers(g, window, t)
        except Exception as e:                   # one source failing must not blank the map
            print("attacker geo (%s) failed: %s" % (t, str(e)[:200]), flush=True)
    for x in g["ticker"]:
        x.setdefault("net", GEO.net_kind(x["ip"]) if x.get("ip") else None)
    seen, uniq = set(), []
    for x in sorted(g["ticker"], key=lambda x: x["t"] or "", reverse=True):
        k = (x["t"], x.get("ip"), x.get("site"))         # sshd logs one attempt as 2-3 lines in the same second
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


def build_net_geo(window, dtype):
    search, type_flt = geo_scope(dtype)
    span = {"bool": {"filter": [rng("now-%ds" % window), type_flt]}}
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
        return empty_geo(window, dtype)
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

    out = empty_geo(window, dtype)
    out.update(total=total, denied=denied, failed=failed, sites=sites, arcs=arcs, countries=countries, ticker=ticker,
               _newest=a["newest"].get("value"))
    return out


# ---------------------------------------------------------------- attackers from logs UTMStack doesn't geolocate
# Syslog keeps the address inside the message text; Linux, Windows and M365 have origin.ip. Their locations and
# VPN / hosting / Tor status come from geoip.py (local databases, online fallback).
SYSLOG_PHRASES = ("Invalid user", "Failed password", "Failed publickey", "authentication failure", "preauth",
                  "Unable to negotiate", "maximum authentication attempts", "Accepted")
IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
PORT_RE = re.compile(r"\bport (\d{1,5})\b")


def syslog_ip(message):
    for ip in IPV4_RE.findall(message or ""):
        if geoip.is_public(ip):
            return ip
    return None


def attacker_rows(window, dtype):
    """-> (rows [{site, name, ip, count, blocked}], ticker candidates, newest ms) for one log type."""
    span = rng("now-%ds" % window)
    path = "/v11-log-%s*/_search" % dtype + IX
    rows, ticker, newest = {}, [], None
    if dtype == "syslog":
        r = os_call(path, {"size": 1000, "sort": [{"@timestamp": "desc"}],
                           "_source": ["@timestamp", "log.message", "dataSource", "origin.host"],
                           "query": {"bool": {"filter": [span, {"term": {"dataType.keyword": "syslog"}}],
                                              "should": [{"match_phrase": {"log.message": p}} for p in SYSLOG_PHRASES],
                                              "minimum_should_match": 1}}})
        for h in r.get("hits", {}).get("hits", []):
            s_ = h["_source"]
            msg = (s_.get("log") or {}).get("message") or ""
            ip = syslog_ip(msg)
            if not ip:
                continue
            site = _q(s_.get("dataSource")) or "syslog"
            bad = not msg.startswith("Accepted")
            row = rows.setdefault((site, ip), {"site": site, "name": (s_.get("origin") or {}).get("host") or site,
                                               "ip": ip, "count": 0, "blocked": 0})
            row["count"] += 1; row["blocked"] += bad
            if bad and len(ticker) < 14:
                m = PORT_RE.search(msg)
                ticker.append({"t": s_.get("@timestamp"), "ip": ip, "site": site, "type": "syslog",
                               "port": m.group(1) if m else None, "what": msg[:80]})
        hits = r.get("hits", {}).get("hits", [])
        if hits:
            newest = datetime.fromisoformat(hits[0]["_source"]["@timestamp"].replace("Z", "+00:00")).timestamp() * 1000
        return list(rows.values()), ticker, newest

    flt = [span, {"term": {"dataType.keyword": dtype}}, {"exists": {"field": "origin.ip"}}]
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


def add_attackers(g, window, dtype):
    rows, ticker, newest = attacker_rows(window, dtype)
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


def api_geo(window=60, anon=False, dtype="all"):
    window = window if window in GEO_WINDOWS_S else 60
    dtype = dtype if dtype in GEO_TYPES else "all"
    with _geo_lock:
        hit = _geo_cache.get((window, dtype))
        if not hit or time.time() - hit[0] >= GEO_TTL_S:
            hit = (time.time(), build_geo(window, dtype))
            _geo_cache[(window, dtype)] = hit
    data = hit[1]                                # shared cache: never modify it in place
    if anon:
        return anonymize(data)
    names = {x["id"]: x["name"] for x in data["sites"]}
    return dict(data, ticker=[dict(x, site=names.get(x["site"], x["site"])) for x in data["ticker"]])


# ---------------------------------------------------------------- support info (logo click)
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
    out = {"contact": current_support(), "version": VERSION, "installed": env("INSTALLED_AT") or None}
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
        if len(st["fails"]) >= LOGIN_MAX_FAILURES:
            st["until"] = now + LOGIN_LOCK_S
            print("login: %s locked for %d s after %d failed logins" % (ip, LOGIN_LOCK_S, len(st["fails"])), flush=True)
        return False, 0


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
    )
    return state


def validate_settings_patch(patch):
    """Reject values that would be silently useless or dangerous; settings_store.save() only checks shape/size."""
    if "dash_user" in patch and not patch["dash_user"].strip():
        raise ValueError("the dashboard username cannot be empty")
    if "dash_pass" in patch and len(patch["dash_pass"]) < 8:
        raise ValueError("the dashboard password must be at least 8 characters")
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


class Handler(BaseHTTPRequestHandler):
    server_version = "UTMStack-Observatory"     # no Python / BaseHTTP version in the Server header
    sys_version = ""
    timeout = REQUEST_TIMEOUT_S                 # idle or slow clients are dropped instead of holding a thread forever

    def log_message(self, *a):
        pass

    def setup(self):
        """Do the TLS handshake here, in this connection's own thread — not on the listening socket, which
        would serialise every client's handshake behind the accept loop (one slow/idle client stalls all)."""
        ctx = getattr(self.server, "tls_context", None)
        if ctx:
            self.request.settimeout(self.timeout)
            self.request = ctx.wrap_socket(self.request, server_side=True)
        super().setup()

    def send(self, code, ctype, body, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", (extra or {}).pop("Cache-Control", "no-store"))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
                         "img-src 'self' data: blob: %s; connect-src 'self' %s; worker-src blob:; child-src blob:; "
                         "frame-ancestors 'none'; base-uri 'none'; form-action 'none'" % (TILE_HOST, TILE_HOST))
        if isinstance(self.connection, ssl.SSLSocket):
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def gate(self):
        """Authenticate the request with a per-IP lockout. Sends the 401/429 itself; returns True when allowed.
        Requests without credentials (a browser's first try) do not count as failures."""
        if not current_dash_pass():
            return True
        ip = self.client_address[0]
        has_creds = bool(self.headers.get("Authorization"))
        if has_creds:
            ok, wait = login_attempt(ip, self.authorized)
            if wait:
                self.send(429, "text/plain", b"Too many failed logins from this address. Try again later.",
                          {"Retry-After": str(int(wait) + 1)})
                return False
            if ok:
                return True
            print("login: failed login from %s" % ip, flush=True)
            time.sleep(0.5)                           # slow down password guessing
        self.send(401, "text/plain", b"Authentication required",
                  {"WWW-Authenticate": 'Basic realm="UTMStack Observatory", charset="UTF-8"'})
        return False

    def authorized(self):
        if not current_dash_pass():
            return True
        h = self.headers.get("Authorization", "")
        if h.startswith("Basic "):
            try:
                user, _, pw = base64.b64decode(h[6:]).decode().partition(":")
            except Exception:
                return False
            ok_u = hmac.compare_digest(user.encode(), current_dash_user().encode())
            ok_p = hmac.compare_digest(pw.encode(), current_dash_pass().encode())
            return ok_u and ok_p
        return False

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/healthz":                      # liveness only; no data, no auth
            self.send(200, "text/plain", b"ok")
            return
        if not self.gate():
            return
        p = {k: v[0] for k, v in parse_qs(u.query).items()}
        routes = {
            "/api/sources": lambda: api_sources(),
            "/api/source": lambda: api_source(p.get("name", "")[:200]),
            "/api/alerts": lambda: api_alerts(p),
            "/api/alert": lambda: api_alert(p.get("id", "")),
            "/api/lag": lambda: api_lag(),
            "/api/cluster": lambda: api_cluster(),
            "/api/storage": lambda: api_storage(),
            "/api/whois": lambda: api_whois(p.get("ip", "")[:64]),
            "/api/reputation": lambda: api_reputation(p.get("ip", "")[:64]),
            "/api/support": lambda: api_support(p.get("anon") == "1"),
            "/api/settings": lambda: api_settings(),
            "/api/reports": lambda: {"reports": reports.list_reports(DATA_DIR), "report_hour": current_report_hour()},
            "/api/geo": lambda: api_geo(int(p["window"]) if p.get("window", "").isdigit() else 60,
                                        p.get("anon") == "1", p.get("type", "all")),
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
                body = json.dumps({"error": str(e)[:200]}).encode()
            self.send(200, "application/json", body)
        elif u.path in routes:
            try:
                body = json.dumps(routes[u.path]()).encode()
            except Exception as e:  # report to the UI instead of dropping the connection
                body = json.dumps({"error": str(e)[:300]}).encode()
            self.send(200, "application/json", body)
        elif u.path == "/layout.js":
            with open(os.path.join(HERE, "layout.js"), "rb") as f:
                self.send(200, "text/javascript; charset=utf-8", f.read())
        elif u.path == "/api/layout":
            lay, notes = layout_store.load_with_notes(DATA_DIR)
            self.send(200, "application/json", json.dumps({"layout": lay, "notes": notes}).encode())
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
                self.send(200, "text/html; charset=utf-8", f.read())
        else:
            self.send(404, "text/plain", b"not found")

    def do_PUT(self):
        u = urlparse(self.path)
        if not self.gate():
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
                self.send(200, "application/json", json.dumps({"layout": saved}).encode())
            else:
                with _settings_lock:
                    validate_settings_patch(req)
                    settings_store.save(DATA_DIR, req)
                self.send(200, "application/json", json.dumps(settings_store.public_state(DATA_DIR)).encode())
        except ValueError as e:
            self.send(400, "application/json", json.dumps({"error": str(e)[:200]}).encode())

    def do_POST(self):
        u = urlparse(self.path)
        if not self.gate():
            return
        if u.path != "/api/reports/generate":
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
        self.rfile.read(n)                         # always consume the body, or a rejected request resets the socket
        if not layout_store.csrf_ok(self.headers):
            self.send(403, "application/json", b'{"error":"forbidden"}')
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
            self.send(500, "application/json", json.dumps({"error": str(e)[:300]}).encode())


class Server(ThreadingHTTPServer):
    """Caps concurrent connections instead of spawning an unbounded thread per accept. tls_context, when set,
    is applied per-connection by Handler.setup() rather than to the listening socket (see setup() for why)."""
    tls_context = None

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._conn_slots = threading.Semaphore(MAX_CONNECTIONS) if MAX_CONNECTIONS else None

    def process_request(self, request, client_address):
        if self._conn_slots is not None and not self._conn_slots.acquire(blocking=False):
            try:
                request.close()
            except OSError:
                pass
            return
        super().process_request(request, client_address)

    def shutdown_request(self, request):
        super().shutdown_request(request)
        if self._conn_slots is not None:
            self._conn_slots.release()


if __name__ == "__main__":
    if TRANSPORT == "docker-exec" and not OS_PASS:
        OS_PASS = get_password()
    if not current_dash_pass() and BIND not in ("127.0.0.1", "localhost", "::1") and env("ALLOW_NO_AUTH") != "1":
        sys.exit("Refusing to listen on %s without a login. Set DASH_PASS (or DASH_PASS_FILE), "
                 "bind to 127.0.0.1, or set ALLOW_NO_AUTH=1." % BIND)
    threading.Thread(target=refresher, daemon=True).start()
    threading.Thread(target=history_loop, daemon=True).start()
    threading.Thread(target=lag_loop, daemon=True).start()
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
        VERSION, scheme, BIND, PORT, "direct" if TRANSPORT == "http" else "docker-exec", "on" if current_dash_pass() else "OFF", DATA_DIR), flush=True)
    srv.serve_forever()
