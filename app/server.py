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

import layout_store

VERSION = "1.2.0"
HERE = os.path.dirname(os.path.abspath(__file__))


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
DASH_USER, DASH_PASS = env("DASH_USER", "admin"), secret("DASH_PASS")
PORT = int(env("PORT", "8765"))
BIND = env("BIND") or env("HOST") or ("0.0.0.0" if DASH_PASS else "127.0.0.1")
TLS_CERT, TLS_KEY = env("TLS_CERT"), env("TLS_KEY")
DATA_DIR = env("DATA_DIR", HERE)
DISK_PATH = env("DISK_PATH", "/utmstack" if os.path.isdir("/utmstack") else "/")
HOST_NAME = env("HOST_NAME") or os.uname().nodename
TRANSPORT = "http" if OS_URL else "docker-exec"
REFRESH_S = 4
DOCKER = ["sudo", "-n", "docker"]               # docker-exec transport only (bare-metal installs)

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
_IP2NAME = {ip: n for n, ip in AI_HOSTS.items()}


def _bytes_script(field):
    # Sophos stores numbers as quoted text, e.g. "1234"; parse defensively.
    return {"script": {"lang": "painless", "source":
            "def v=doc['log.%s.keyword']; if(v.size()==0) return 0L; "
            "try { return Long.parseLong(v.value.replace('\"','').trim()); } catch(Exception e) { return 0L; }" % field}}


def _sums():
    return {"sent": {"sum": _bytes_script("bytes_sent")}, "recv": {"sum": _bytes_script("bytes_received")}}


def ai_traffic():
    if not AI_HOSTS:
        return {"configured": False}
    quoted = [json.dumps(ip) for ip in AI_HOSTS.values()]   # log values carry literal quotes
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
    hosts = {n: {"name": n, "ip": ip, "in": 0, "out": 0, "conn_in": 0, "conn_out": 0} for n, ip in AI_HOSTS.items()}
    for b in to_ai["hosts"]["buckets"]:
        h = hosts.get(_IP2NAME.get(clean(b["key"])))
        if h:
            h["in"] += b["sent"]["value"]; h["out"] += b["recv"]["value"]; h["conn_in"] += b["doc_count"]
    for b in from_ai["hosts"]["buckets"]:
        h = hosts.get(_IP2NAME.get(clean(b["key"])))
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
                    "description", "events", "target", "adversary"],
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
        ip = ((s.get("adversary") or {}).get("ip") or (ev0.get("origin") or {}).get("ip")
              or (s.get("target") or {}).get("ip") or "")
        return {"id": h["_id"], "t": s.get("@timestamp"), "sev": s.get("severityLabel") or "Low",
                "source": s.get("dataSource") or s.get("dataType") or "-", "name": s.get("name") or "-",
                "status": s.get("statusLabel") or "Open", "desc": s.get("description") or "",
                "affected": len(evs), "ip": ip}

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
    if not AI_HOSTS:
        return out
    quoted = [json.dumps(ip) for ip in AI_HOSTS.values()]
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
    return {"generated": datetime.now(timezone.utc).isoformat(), "retain_days": RETAIN_DAYS, "ai_configured": bool(AI_HOSTS),
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


def alert_summary(h):
    s = h["_source"]
    evs = s.get("events") or []
    ev0 = evs[0] if evs else {}
    ip = ((s.get("adversary") or {}).get("ip") or (ev0.get("origin") or {}).get("ip") or (s.get("target") or {}).get("ip") or "")
    return {"id": h["_id"], "t": s.get("@timestamp"), "sev": s.get("severityLabel") or "Low", "name": s.get("name") or "-",
            "source": s.get("dataSource") or "-", "type": s.get("dataType") or "", "status": s.get("statusLabel") or "Open",
            "ip": ip, "affected": len(evs), "category": s.get("category") or ""}


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
        "_source": ["@timestamp", "name", "severityLabel", "dataSource", "dataType", "statusLabel", "events", "adversary", "target", "category"],
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
        if system:
            fix["steps"].append({"title": "Remove replicas from OpenSearch's own (system) indices — run separately; the security "
                                          "plugin may refuse some of these, which does not affect step 1",
                                 "cmd": opensearch_put_cmd("/%s/_settings?expand_wildcards=all" % ",".join(system),
                                                           '{"index":{"number_of_replicas":0}}')})
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
GEO_WINDOWS_S = (60, 300, 900)
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
    out = []
    for b in r["aggregations"]["fw"]["buckets"]:
        ip = _q(b["key"])
        name = _q(b["dn"]["buckets"][0]["key"]) if b["dn"]["buckets"] else ip
        loc, source = SITE_OVERRIDES.get(name) or SITE_OVERRIDES.get(ip), "configured"
        if not loc:
            try:
                loc, source = _locate_ip(ip), "geoip"
            except Exception:
                loc = None
        if not loc:
            loc, source = HOME, "home"
        out.append({"id": ip, "name": name, "lat": loc["lat"], "lon": loc["lon"], "city": loc.get("city"), "loc_source": source})
    out.sort(key=lambda x: x["name"].lower())
    _sites.update(t=time.time(), list=out)
    return out


def _remote_aggs(side):
    g = side + ".geolocation."
    return {"terms": {"field": "dataSource.keyword", "size": 100}, "aggs": {
        "cc": {"terms": {"field": g + "countryCode.keyword", "size": 15, "missing": "??"}, "aggs": {
            "city": {"terms": {"field": g + "city.keyword", "size": 6, "missing": ""}, "aggs": {
                "lat": {"avg": {"field": g + "latitude"}}, "lon": {"avg": {"field": g + "longitude"}},
                "country": {"terms": {"field": g + "country.keyword", "size": 1}},
                "out": {"terms": {"field": "actionResult.keyword", "size": 4}}}}}}}}


def _outcomes(buckets):
    o = {_q(b["key"]).lower(): b["doc_count"] for b in buckets}
    return o.get("denied", 0), o.get("failed", 0)


def build_geo(window):
    span = rng("now-%ds" % window)
    has = lambda f: {"exists": {"field": f}}
    r = os_call(FW_SEARCH, {"size": 0, "track_total_hits": True, "query": span, "aggs": {
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
    t = os_call(FW_SEARCH, {"size": 14, "sort": [{"@timestamp": "desc"}], "query": {"bool": {"filter": [
        span, {"term": {"actionResult.keyword": "denied"}}, has("origin.geolocation.latitude")]}},
        "_source": ["@timestamp", "origin.ip", "origin.geolocation.city", "origin.geolocation.country",
                    "origin.geolocation.countryCode", "target.port", "protocol", "dataSource"]})
    a = r["aggregations"]
    total = r["hits"]["total"]["value"]
    denied, failed = _outcomes(a["outcome"]["buckets"])

    sites = [dict(x) for x in fw_sites()]
    by_id = {x["id"]: x for x in sites}
    for b in a["per_fw"]["buckets"]:
        ip = _q(b["key"])
        if ip not in by_id:                      # firewall seen for the first time since the site list was cached
            by_id[ip] = {"id": ip, "name": ip, "lat": HOME["lat"], "lon": HOME["lon"], "city": HOME.get("city"), "loc_source": "home"}
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
                    arcs.append({"site": site, "dir": direction, "cc": cc, "country": _q(name), "city": _q(cityb["key"]),
                                 "lat": round(lat, 3), "lon": round(lon, 3), "count": cityb["doc_count"], "denied": d})
                    c = countries.setdefault(cc, {"cc": cc, "country": _q(name), "count": 0, "denied": 0, "in": 0, "out": 0})
                    c["count"] += cityb["doc_count"]; c["denied"] += d; c[direction] += cityb["doc_count"]
    arcs.sort(key=lambda x: x["count"], reverse=True)

    ticker = []
    for h in t["hits"]["hits"]:
        s_ = h["_source"]
        o = s_.get("origin") or {}
        g = o.get("geolocation") or {}
        ticker.append({"t": s_.get("@timestamp"), "ip": o.get("ip"), "city": g.get("city"), "country": g.get("country"),
                       "cc": g.get("countryCode"), "port": (s_.get("target") or {}).get("port"),
                       "proto": s_.get("protocol"), "site": _q(s_.get("dataSource"))})

    newest = a["newest"].get("value")
    return {"window_s": window, "generated": datetime.now(timezone.utc).isoformat(),
            "age_s": round(max(0, time.time() - newest / 1000), 1) if newest else None,
            "total": total, "denied": denied, "failed": failed, "per_min": round(total * 60 / window),
            "home": HOME, "sites": sites, "arcs": arcs[:MAX_ARCS], "arcs_total": len(arcs),
            "countries": sorted(countries.values(), key=lambda c: c["count"], reverse=True)[:12],
            "ticker": ticker}


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


def api_geo(window=60, anon=False):
    window = window if window in GEO_WINDOWS_S else 60
    with _geo_lock:
        hit = _geo_cache.get(window)
        if not hit or time.time() - hit[0] >= GEO_TTL_S:
            hit = (time.time(), build_geo(window))
            _geo_cache[window] = hit
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


def api_support(anon=False):
    """Contact + health summary for the support panel. Never includes secrets or client names."""
    out = {"contact": SUPPORT, "version": VERSION, "installed": env("INSTALLED_AT") or None}
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


_layout_lock = threading.Lock()                  # one writer at a time; version check + save are atomic together


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, ctype, body, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", (extra or {}).pop("Cache-Control", "no-store"))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; "
                         "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def authorized(self):
        if not DASH_PASS:
            return True
        h = self.headers.get("Authorization", "")
        if h.startswith("Basic "):
            try:
                user, _, pw = base64.b64decode(h[6:]).decode().partition(":")
            except Exception:
                return False
            ok_u = hmac.compare_digest(user.encode(), DASH_USER.encode())
            ok_p = hmac.compare_digest(pw.encode(), DASH_PASS.encode())
            return ok_u and ok_p
        return False

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/healthz":                      # liveness only; no data, no auth
            self.send(200, "text/plain", b"ok")
            return
        if not self.authorized():
            time.sleep(0.5)                           # slow down password guessing
            self.send(401, "text/plain", b"Authentication required",
                      {"WWW-Authenticate": 'Basic realm="UTMStack Observatory", charset="UTF-8"'})
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
            "/api/support": lambda: api_support(p.get("anon") == "1"),
            "/api/geo": lambda: api_geo(int(p["window"]) if p.get("window", "").isdigit() else 60,
                                        p.get("anon") == "1"),
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
        elif u.path == "/land.json":                  # static world outline for the live map
            with open(os.path.join(HERE, "land.json"), "rb") as f:
                self.send(200, "application/json", f.read(), {"Cache-Control": "private, max-age=86400"})
        elif u.path in ("/", "/index.html"):
            with open(os.path.join(HERE, "index.html"), "rb") as f:
                self.send(200, "text/html; charset=utf-8", f.read())
        else:
            self.send(404, "text/plain", b"not found")

    def do_PUT(self):
        u = urlparse(self.path)
        if not self.authorized():
            time.sleep(0.5)
            self.send(401, "text/plain", b"Authentication required",
                      {"WWW-Authenticate": 'Basic realm="UTMStack Observatory", charset="UTF-8"'})
            return
        if u.path != "/api/layout":
            self.send(404, "text/plain", b"not found")
            return
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = -1
        if not 0 <= n <= layout_store.MAX_BYTES + 1024:
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
            with _layout_lock:
                current = layout_store.load(DATA_DIR)
                if req.get("base_version") != current.get("version"):
                    self.send(409, "application/json", json.dumps({"error": "conflict", "layout": current}).encode())
                    return
                saved = layout_store.save(DATA_DIR, req.get("layout"))
            self.send(200, "application/json", json.dumps({"layout": saved}).encode())
        except ValueError as e:
            self.send(400, "application/json", json.dumps({"error": str(e)[:200]}).encode())


if __name__ == "__main__":
    if TRANSPORT == "docker-exec" and not OS_PASS:
        OS_PASS = get_password()
    if not DASH_PASS and BIND not in ("127.0.0.1", "localhost", "::1") and env("ALLOW_NO_AUTH") != "1":
        sys.exit("Refusing to listen on %s without a login. Set DASH_PASS (or DASH_PASS_FILE), "
                 "bind to 127.0.0.1, or set ALLOW_NO_AUTH=1." % BIND)
    threading.Thread(target=refresher, daemon=True).start()
    threading.Thread(target=history_loop, daemon=True).start()
    threading.Thread(target=lag_loop, daemon=True).start()
    srv = ThreadingHTTPServer((BIND, PORT), Handler)
    scheme = "http"
    if TLS_CERT and TLS_KEY:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.minimum_version = ssl.TLSVersion.TLSv1_2
        tls.load_cert_chain(TLS_CERT, TLS_KEY)
        srv.socket = tls.wrap_socket(srv.socket, server_side=True)
        scheme = "https"
    print("UTMStack Observatory %s on %s://%s:%d  (opensearch via %s, login %s, data %s)" % (
        VERSION, scheme, BIND, PORT, "direct" if TRANSPORT == "http" else "docker-exec", "on" if DASH_PASS else "OFF", DATA_DIR), flush=True)
    srv.serve_forever()
