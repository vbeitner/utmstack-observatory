# Copyright (c) 2026 Victor Beitner. All rights reserved. See LICENSE.
"""Attacker-IP enrichment: location and VPN / hosting / Tor status.

Local first: DB-IP City Lite (location, CC BY 4.0) plus the X4BNet VPN and datacenter range lists and the Tor
Project's exit-node list, all downloaded into DATA_DIR/geoip and refreshed in the background. Only when the local
data can't place an address does an optional online lookup (proxycheck.io) run, in the background, under a daily
cap, with results cached for a week. Nothing here blocks a request: an address that isn't known yet simply
shows up on a later refresh.
"""
import bisect
import gzip
import ipaddress
import json
import os
import queue
import sqlite3
import threading
import time
import urllib.request
from urllib.parse import quote
from datetime import datetime, timedelta, timezone

try:
    import maxminddb
except ImportError:                                  # running without the dependency: online/lists only
    maxminddb = None

DBIP_URL = "https://download.db-ip.com/free/dbip-city-lite-%s.mmdb.gz"
LISTS = {
    "tor": "https://check.torproject.org/torbulkexitlist",
    "vpn": "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt",
    "hosting": "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt",
}
ONLINE_URL = "https://proxycheck.io/v2/%s?vpn=1&asn=1"
LIST_TTL_S = 7 * 86400
DB_TTL_S = 30 * 86400
CACHE_TTL_S = 7 * 86400
UA = {"User-Agent": "utmstack-observatory"}
NET_ORDER = ("tor", "vpn", "hosting")              # a Tor exit inside a datacenter range is reported as Tor


def is_public(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def parse_ranges(text):
    """Lines of IPv4 addresses or CIDRs -> sorted [(start, end)] as ints (IPv6 and junk skipped)."""
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            net = ipaddress.ip_network(line, strict=False)
        except ValueError:
            continue
        if net.version == 4:
            out.append((int(net.network_address), int(net.broadcast_address)))
    out.sort()
    return out


def in_ranges(ranges, starts, ip_int):
    i = bisect.bisect_right(starts, ip_int) - 1
    return i >= 0 and ranges[i][0] <= ip_int <= ranges[i][1]


class GeoIP:
    def __init__(self, data_dir, online_key="", online_daily=100, fetch=None):
        self.dir = os.path.join(data_dir, "geoip")
        os.makedirs(self.dir, exist_ok=True)
        self.online_key, self.online_daily = online_key, online_daily
        self.fetch = fetch or self._fetch
        self.reader = None
        self.ranges = {k: ([], []) for k in LISTS}    # kind -> (ranges, starts)
        self.status = {"db": None, "lists": {}, "online_today": 0, "error": None}
        self._day, self._used = None, 0
        self._q = queue.Queue(maxsize=500)
        self._pending = set()
        self._lock = threading.Lock()
        self._db = sqlite3.connect(os.path.join(self.dir, "cache.db"), check_same_thread=False)
        self._db.execute("CREATE TABLE IF NOT EXISTS ipcache (ip TEXT PRIMARY KEY, t REAL, data TEXT)")
        self._db.commit()

    # ------------------------------------------------------------ downloads
    @staticmethod
    def _fetch(url, timeout=120):
        with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout) as r:
            return r.read()

    def _fresh(self, path, ttl):
        return os.path.exists(path) and time.time() - os.path.getmtime(path) < ttl

    def refresh(self):
        """Download whatever is missing or stale, then (re)load. Safe to call repeatedly."""
        for kind, url in LISTS.items():
            path = os.path.join(self.dir, kind + ".txt")
            if not self._fresh(path, LIST_TTL_S):
                try:
                    self._write(path, self.fetch(url))
                except Exception as e:
                    self.status["error"] = "%s list: %s" % (kind, str(e)[:120])
        db = os.path.join(self.dir, "dbip-city-lite.mmdb")
        if maxminddb and not self._fresh(db, DB_TTL_S):
            now = datetime.now(timezone.utc)
            months = [now.strftime("%Y-%m"), (now.replace(day=1) - timedelta(days=1)).strftime("%Y-%m")]
            for ym in months:                         # this month's file appears a day or two into the month
                try:
                    self._write(db, gzip.decompress(self.fetch(DBIP_URL % ym, timeout=600)))
                    break
                except Exception as e:
                    self.status["error"] = "DB-IP %s: %s" % (ym, str(e)[:120])
        self.load()

    def _write(self, path, data):
        tmp = path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(data)
        os.replace(tmp, path)

    def load(self):
        for kind in LISTS:
            path = os.path.join(self.dir, kind + ".txt")
            if os.path.exists(path):
                with open(path, encoding="utf-8", errors="replace") as f:
                    r = parse_ranges(f.read())
                self.ranges[kind] = (r, [a for a, _ in r])
                self.status["lists"][kind] = len(r)
        db = os.path.join(self.dir, "dbip-city-lite.mmdb")
        if maxminddb and os.path.exists(db):
            try:
                old, self.reader = self.reader, maxminddb.open_database(db)
                self.status["db"] = datetime.fromtimestamp(os.path.getmtime(db), timezone.utc).strftime("%Y-%m-%d")
                if old:
                    old.close()
            except Exception as e:
                self.status["error"] = "DB-IP load: %s" % str(e)[:120]

    def loop(self, every_s=6 * 3600):
        while True:
            try:
                self.refresh()
            except Exception as e:
                self.status["error"] = str(e)[:200]
            time.sleep(every_s)

    # ------------------------------------------------------------ lookups
    def net_kind(self, ip):
        try:
            n = int(ipaddress.IPv4Address(ip))
        except ValueError:
            return None
        for kind in NET_ORDER:
            ranges, starts = self.ranges[kind]
            if ranges and in_ranges(ranges, starts, n):
                return kind
        return None

    def _local(self, ip):
        if not self.reader:
            return None
        try:
            rec = self.reader.get(ip)
        except Exception:
            return None
        loc = (rec or {}).get("location") or {}
        if loc.get("latitude") is None:
            return None
        country = (rec.get("country") or {})
        name = lambda d: ((d or {}).get("names") or {}).get("en")
        return {"lat": loc["latitude"], "lon": loc["longitude"], "city": name(rec.get("city")) or "",
                "country": name(country) or "", "cc": country.get("iso_code") or "??", "src": "local"}

    def _cached(self, ip):
        row = self._db.execute("SELECT t, data FROM ipcache WHERE ip=?", (ip,)).fetchone()
        if row and time.time() - row[0] < CACHE_TTL_S:
            return json.loads(row[1])
        return None

    def lookup(self, ip):
        """{lat, lon, city, country, cc, net, src} or None if not known (an online lookup may be queued)."""
        if not is_public(ip):
            return None
        out = self._local(ip)
        with self._lock:
            cached = None if out else self._cached(ip)
        if not out and cached and cached.get("lat") is not None:
            out = cached
        if not out:
            self._enqueue(ip)
            return None
        out = dict(out)
        out["net"] = self.net_kind(ip) or ((cached or {}).get("net") if cached else None)
        return out

    def _enqueue(self, ip):
        if self.online_daily <= 0 or ip in self._pending:
            return
        try:
            self._q.put_nowait(ip)
            self._pending.add(ip)
        except queue.Full:
            pass

    def _budget_ok(self):
        today = time.strftime("%Y-%m-%d")
        if self._day != today:
            self._day, self._used = today, 0
        return self._used < self.online_daily

    def online_loop(self):
        while True:
            ip = self._q.get()
            try:
                with self._lock:
                    if self._cached(ip) or not self._budget_ok():
                        continue
                    self._used += 1
                    self.status["online_today"] = self._used
                url = ONLINE_URL % quote(ip, safe=":.") + ("&key=" + quote(self.online_key, safe="") if self.online_key else "")
                d = json.loads(self.fetch(url, timeout=15)).get(ip) or {}
                rec = {"lat": d.get("latitude"), "lon": d.get("longitude"), "city": d.get("city") or "",
                       "country": d.get("country") or "", "cc": d.get("isocode") or "??", "src": "online",
                       "net": ("tor" if str(d.get("type", "")).upper() == "TOR" else
                               "vpn" if d.get("proxy") == "yes" else None)}
                with self._lock:
                    self._db.execute("INSERT OR REPLACE INTO ipcache VALUES (?,?,?)", (ip, time.time(), json.dumps(rec)))
                    self._db.commit()
            except Exception as e:
                self.status["error"] = "online lookup: %s" % str(e)[:120]
            finally:
                self._pending.discard(ip)
                time.sleep(1)                          # stay well inside the free tier's rate limit

    def start(self):
        threading.Thread(target=self.loop, daemon=True).start()
        threading.Thread(target=self.online_loop, daemon=True).start()
