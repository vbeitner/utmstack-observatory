# Copyright (c) 2026 Victor Beitner. All rights reserved. See LICENSE.
"""Demo mode (DEMO=1): a fictional organisation with realistic, fully synthetic SIEM data.

Used for sales demos, screenshots and the user manual. Nothing here talks to OpenSearch or to the internet.
All public addresses come from the RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24), so no screenshot can ever show a real company's or person's address. Values are seeded from
the clock, so every viewer sees the same picture and it moves forward in time like a live system.
"""
import hashlib
import math
import random
import time
import uuid
from datetime import datetime, timezone

S = {}                                           # the server module's globals (set by install)

FIREWALLS = [  # name, lat, lon, city
    ("HQ-Toronto", 43.6532, -79.3832, "Toronto"), ("Branch-Ottawa", 45.4215, -75.6972, "Ottawa"),
    ("Clinic-Hamilton", 43.2557, -79.8711, "Hamilton"), ("Warehouse-Mississauga", 43.5890, -79.6441, "Mississauga"),
    ("Office-Vancouver", 49.2827, -123.1207, "Vancouver"), ("Lab-Calgary", 51.0447, -114.0719, "Calgary"),
    ("Store-Halifax", 44.6488, -63.5752, "Halifax"), ("Plant-Montreal", 45.5017, -73.5673, "Montreal"),
]
SERVERS = [("nas01.example.lan", "syslog"), ("web01.example.lan", "linux"), ("dc01.example.lan", "wineventlog"),
           ("m365-tenant", "o365")]
TYPE_SHARE = {"firewall-sophos-xg": .52, "linux": .27, "wineventlog": .09, "syslog": .07, "o365": .05}

# city, country, cc, lat, lon, outbound weight (our users' destinations), inbound weight (attack sources)
CITIES = [
    ("Ashburn", "United States", "US", 39.04, -77.49, 30, 8), ("Seattle", "United States", "US", 47.61, -122.33, 14, 2),
    ("Dallas", "United States", "US", 32.78, -96.80, 9, 3), ("Chicago", "United States", "US", 41.88, -87.63, 8, 2),
    ("New York", "United States", "US", 40.71, -74.01, 10, 3), ("Los Angeles", "United States", "US", 34.05, -118.24, 7, 4),
    ("San Jose", "United States", "US", 37.34, -121.89, 12, 1), ("Toronto", "Canada", "CA", 43.70, -79.42, 18, 1),
    ("Montreal", "Canada", "CA", 45.50, -73.57, 8, 1), ("London", "United Kingdom", "GB", 51.51, -0.13, 6, 3),
    ("Amsterdam", "The Netherlands", "NL", 52.37, 4.90, 5, 9), ("Frankfurt am Main", "Germany", "DE", 50.11, 8.68, 5, 7),
    ("Paris", "France", "FR", 48.86, 2.35, 3, 2), ("Dublin", "Ireland", "IE", 53.35, -6.26, 7, 1),
    ("Stockholm", "Sweden", "SE", 59.33, 18.07, 1, 4), ("Warsaw", "Poland", "PL", 52.23, 21.01, 0, 2),
    ("Sofia", "Bulgaria", "BG", 42.70, 23.32, 0, 8), ("Bucharest", "Romania", "RO", 44.43, 26.10, 0, 5),
    ("Moscow", "Russia", "RU", 55.76, 37.62, 0, 6), ("Saint Petersburg", "Russia", "RU", 59.93, 30.36, 0, 3),
    ("Istanbul", "Türkiye", "TR", 41.01, 28.98, 0, 3), ("Kyiv", "Ukraine", "UA", 50.45, 30.52, 0, 2),
    ("Tehran", "Iran", "IR", 35.69, 51.39, 0, 2), ("Beijing", "China", "CN", 39.90, 116.41, 0, 6),
    ("Shanghai", "China", "CN", 31.23, 121.47, 1, 5), ("Hong Kong", "Hong Kong", "HK", 22.32, 114.17, 1, 3),
    ("Singapore", "Singapore", "SG", 1.35, 103.82, 2, 4), ("Tokyo", "Japan", "JP", 35.68, 139.69, 2, 1),
    ("Seoul", "South Korea", "KR", 37.57, 126.98, 0, 2), ("Mumbai", "India", "IN", 19.08, 72.88, 1, 4),
    ("Bengaluru", "India", "IN", 12.97, 77.59, 1, 3), ("Hanoi", "Vietnam", "VN", 21.03, 105.85, 0, 4),
    ("São Paulo", "Brazil", "BR", -23.55, -46.63, 1, 5), ("Buenos Aires", "Argentina", "AR", -34.60, -58.38, 0, 1),
    ("Lagos", "Nigeria", "NG", 6.52, 3.38, 0, 2), ("Johannesburg", "South Africa", "ZA", -26.20, 28.05, 0, 1),
    ("Sydney", "Australia", "AU", -33.87, 151.21, 1, 1), ("Mexico City", "Mexico", "MX", 19.43, -99.13, 1, 2),
]
OUT_PORTS = [(443, 70), (80, 10), (53, 9), (123, 4), (8443, 4), (587, 3)]
IN_PORTS = [(22, 30), (3389, 18), (443, 14), (445, 10), (23, 9), (8080, 8), (5060, 6), (1433, 5)]
# Tor exits and VPN providers live in a few hosting-heavy places; most attack traffic is plain "hosting".
NET_PROFILE = {"Amsterdam": (.10, .25, .45), "Frankfurt am Main": (.10, .20, .40), "Ashburn": (.03, 0, .70),
               "Stockholm": (.20, .45, .20), "Bucharest": (.05, .04, .35), "Singapore": (.05, 0, .45),
               "Los Angeles": (.08, 0, .40), "London": (.06, .02, .30), "Paris": (.03, .05, .25)}
DOC_NETS = ("203.0.113", "198.51.100", "192.0.2")

RULES = [  # name, severity, category, technique, data type, weight, description, solution
    ("Known Malicious IP Detected", "Low", "Threat Intelligence", "", "firewall-sophos-xg", 36,
     "The IP '{ip}' was found in threat-intelligence feeds (Level 1) while connecting to {site}.",
     "Keep the address blocked at the perimeter; review the rule if it is a partner or service you use."),
    ("Port Scan Detected", "Low", "Discovery", "T1046 - Network Service Discovery", "firewall-sophos-xg", 14,
     "{ip} probed many ports on {site} within a minute.", "No action needed while the firewall keeps denying it."),
    ("SSH Brute Force Attempt", "Medium", "Credential Access", "T1110.001 - Password Guessing", "syslog", 11,
     "Repeated failed SSH logins on {site} from {ip} ('Invalid user admin', 'Failed password for root').",
     "Disable password logins for SSH, allow keys only, and restrict port 22 to the VPN."),
    ("Multiple Failed Windows Logons", "Medium", "Credential Access", "T1110 - Brute Force", "wineventlog", 7,
     "Event 4625 fired repeatedly on {site} for several accounts from {ip}.",
     "Check whether the accounts are real; enable account lockout and MFA for remote access."),
    ("Office 365 Sign-in From Unusual Country", "Medium", "Initial Access", "T1078.004 - Cloud Accounts", "o365", 5,
     "A user signed in to Microsoft 365 from {city}, {country} ({ip}) for the first time.",
     "Confirm with the user; if unexpected, reset the password, revoke sessions and review MFA."),
    ("RDP Connection From Internet", "High", "Initial Access", "T1133 - External Remote Services", "firewall-sophos-xg", 3,
     "An inbound Remote Desktop connection from {ip} reached {site}.",
     "Close TCP/3389 to the internet and publish RDP only through the VPN or a gateway."),
    ("Sudo Privilege Escalation", "Medium", "Privilege Escalation", "T1548.003 - Sudo and Sudo Caching", "linux", 3,
     "An unexpected account used sudo to start a root shell on {site}.", "Confirm the change was authorised."),
    ("Audit Log Cleared", "High", "Defense Evasion", "T1070.001 - Clear Windows Event Logs", "wineventlog", 1,
     "The Security event log was cleared on {site}.", "Treat as suspicious until explained; check who was logged on."),
]
ALERT_SLOT_S = 540                               # one chance of an alert every 9 minutes
AI_HOSTS = {"llm01": "10.10.0.21", "llm02": "10.10.0.22"}


def rng(*key):
    return random.Random(int(hashlib.sha256(repr(key).encode()).hexdigest()[:16], 16))  # nosec B311: repeatable fake data, not security


def now_ms():
    return int(time.time() * 1000)


def iso(ms):
    return datetime.fromtimestamp(ms / 1000, timezone.utc).isoformat().replace("+00:00", "Z")


def diurnal(ms):
    """Busier in the Toronto working day, quieter at night (0.55 .. 1.25)."""
    hour = (datetime.fromtimestamp(ms / 1000, timezone.utc).hour - 4) % 24
    return 0.9 + 0.35 * math.sin((hour - 8) / 24 * 2 * math.pi)


def events_per_min(ms):
    return 5200 * diurnal(ms) * (0.92 + 0.16 * rng("epm", ms // 60000).random())


def pick(r, weighted):
    total = sum(w for _, w in weighted)
    x = r.random() * total
    for v, w in weighted:
        x -= w
        if x <= 0:
            return v
    return weighted[-1][0]


def city_ip(city_i, j):
    return "%s.%d" % (DOC_NETS[(city_i + j) % 3], (city_i * 37 + j * 11) % 250 + 3)


def net_of(city, j):
    vpn, tor, hosting = NET_PROFILE.get(city, (0, 0, .15))
    x = rng("net", city, j).random()
    return "tor" if x < tor else "vpn" if x < tor + vpn else "hosting" if x < tor + vpn + hosting else None


# ---------------------------------------------------------------- alerts
def alert_at(slot):
    r = rng("alert", slot)
    if r.random() > 0.55:
        return None
    rule = pick(r, [(x, x[5]) for x in RULES])
    name, sev, cat, tech, dtype, _, desc, sol = rule
    ci = pick(r, [(i, c[6] + (1 if dtype == "o365" and c[2] in ("US", "CA") else 0)) for i, c in enumerate(CITIES)])
    city = CITIES[ci]
    ip = city_ip(ci, r.randrange(6))
    site = (r.choice(FIREWALLS)[0] if dtype == "firewall-sophos-xg" else
            next(s for s, t in SERVERS if t == dtype) if dtype != "linux" else "web01.example.lan")
    t = slot * ALERT_SLOT_S * 1000 + r.randrange(ALERT_SLOT_S * 1000)
    status = "Open" if t > now_ms() - 6 * 3600 * 1000 or r.random() < .6 else "Completed"
    return {"id": str(uuid.UUID(hashlib.md5(("demo-alert-%d" % slot).encode(), usedforsecurity=False).hexdigest())), "t_ms": t, "t": iso(t),
            "sev": sev, "name": name, "source": site, "type": dtype, "status": status, "ip": ip,
            "affected": 1 + r.randrange(3), "category": cat, "lat": city[3], "lon": city[4], "technique": tech,
            "city": city[0], "country": city[1], "cc": city[2], "port": 22 if dtype in ("syslog", "linux") else
            3389 if "RDP" in name or dtype == "wineventlog" else pick(r, IN_PORTS),
            "desc": desc.format(ip=ip, site=site, city=city[0], country=city[1]), "solution": sol}


def alerts_between(start_ms, end_ms):
    out = []
    for slot in range(start_ms // 1000 // ALERT_SLOT_S, end_ms // 1000 // ALERT_SLOT_S + 1):
        a = alert_at(slot)
        if a and start_ms <= a["t_ms"] <= end_ms:
            out.append(a)
    return sorted(out, key=lambda a: a["t_ms"], reverse=True)


def row(a):
    return {k: a[k] for k in ("id", "t", "sev", "source", "name", "status", "affected", "ip", "lat", "lon", "technique")} | \
        {"desc": a["desc"]}


# ---------------------------------------------------------------- main dashboard data
def host():
    r = rng("host", now_ms() // 10000)
    cpu = 22 + 18 * diurnal(now_ms()) * r.random()
    return {"hostname": "observatory-demo", "cores": 16, "load1": round(cpu / 100 * 16, 2), "cpu_pct": cpu,
            "mem_used_gb": 18.4 + r.random(), "mem_total_gb": 32.0, "mem_pct": (18.4 + r.random()) / 32 * 100,
            "disk_used_gb": 612.0, "disk_total_gb": 1000.0, "disk_pct": 61.2}


def ai_section():
    t0 = (now_ms() // 3600000 - 24) * 3600000
    hourly = []
    for k in range(25):
        h = t0 + k * 3600000
        w = max(0, diurnal(h) - .6) * 2.2
        r = rng("ai", h)
        hourly.append({"t": h, "in": w * 2.1e8 * (0.7 + .6 * r.random()), "out": w * 6.4e8 * (0.7 + .6 * r.random())})
    tin, tout = sum(x["in"] for x in hourly), sum(x["out"] for x in hourly)
    hosts = [{"name": "llm01", "ip": AI_HOSTS["llm01"], "in": tin * .7, "out": tout * .72, "conn_in": 4210, "conn_out": 310},
             {"name": "llm02", "ip": AI_HOSTS["llm02"], "in": tin * .3, "out": tout * .28, "conn_in": 1630, "conn_out": 95}]
    peers = [{"ip": "10.10.%d.%d" % (20 + i, 40 + i * 7), "country": "", "conns": 900 - i * 140,
              "in": tin * (.3 - i * .04), "out": tout * (.3 - i * .04), "dir": "in"} for i in range(5)]
    return {"configured": True, "hosts": hosts, "in": tin, "out": tout, "conn_in": 5840, "conn_out": 405, "peers": peers,
            "ports": [{"port": "11434", "count": 4980}, {"port": "443", "count": 760}, {"port": "8000", "count": 140}],
            "hourly": hourly}


def collect(hours=24):
    now = now_ms()
    m0 = (now // 60000 - 60) * 60000
    window_alerts = alerts_between(now - hours * 3600000, now)
    minutes = []
    for k in range(60):
        t = m0 + k * 60000
        minutes.append({"t": t, "events": int(events_per_min(t)), "alerts": sum(1 for a in window_alerts if t <= a["t_ms"] < t + 60000)})
    per_hour = [events_per_min(now - h * 3600000) * 60 for h in range(hours)]
    ev = int(sum(per_hour))
    prev = int(sum(events_per_min(now - (hours + h) * 3600000) * 60 for h in range(hours)))
    sev = {}
    for a in window_alerts:
        sev[a["sev"]] = sev.get(a["sev"], 0) + 1
    rules = {}
    for a in window_alerts:
        x = rules.setdefault(a["name"], {"name": a["name"], "count": 0, "sev": a["sev"]})
        x["count"] += 1
    peak = max(minutes, key=lambda m: m["events"])
    return {
        "now": iso(now), "range_h": hours, "minutes": minutes, "demo": True,
        "kpi": {"sources_online": len(FIREWALLS) + len(SERVERS), "sources_total": len(FIREWALLS) + len(SERVERS),
                "sources_stale": [], "events_24h": ev, "events_prev_24h": prev, "alerts_24h": len(window_alerts), "sev": sev,
                "lag_s": 1.1 + rng("lag", now // 10000).random(), "eps_5m": round(sum(m["events"] for m in minutes[-5:]) / 300, 2),
                "peak": {"t": peak["t"], "n": peak["events"]}},
        "types": [{"name": t, "count": int(ev * s)} for t, s in sorted(TYPE_SHARE.items(), key=lambda x: -x[1])],
        "rules": sorted(rules.values(), key=lambda x: -x["count"])[:5],
        "alerts": [row(a) for a in window_alerts[:15]],
        "cluster": {"status": "green", "unassigned": 0, "nodes": 1, "active_pct": 100.0},
        "host": host(), "ai": ai_section(), "lag": S["lag_summary"](),
    }


# ---------------------------------------------------------------- history (30 days, hourly)
def fetch_hourly(gte):
    end = now_ms() // 3600000 * 3600000
    out = {"logs": {}, "stats": {}, "alerts": {}, "ai": {}}
    for h in range(end - 30 * 24 * 3600000, end, 3600000):
        out["logs"][h] = int(sum(events_per_min(h + m * 60000) for m in range(0, 60, 10)) * 10)
        al = alerts_between(h, h + 3599999)
        out["alerts"][h] = {"n": len(al), "high": sum(a["sev"] == "High" for a in al),
                            "med": sum(a["sev"] == "Medium" for a in al), "low": sum(a["sev"] == "Low" for a in al)}
        w = max(0, diurnal(h) - .6) * 2.2
        out["ai"][h] = [w * 2.1e8, w * 6.4e8, int(w * 400)]
    return out


# ---------------------------------------------------------------- live map
def geo(window=60, dtype="all", port=None):
    now = now_ms()
    slot = now // 10000
    scale = window / 60
    home = {"lat": FIREWALLS[0][1], "lon": FIREWALLS[0][2], "city": "Toronto"}
    arcs, sites = [], {}

    def site(name, lat, lon, city):
        return sites.setdefault(name, {"id": name, "name": name, "lat": lat, "lon": lon, "city": city,
                                       "loc_source": "configured", "total": 0, "denied": 0})

    def add(site_d, dtype_, direction, ci, count, denied, port_, j=0):
        if count <= 0 or (dtype != "all" and dtype != dtype_) or (port and port_ != port):
            return
        c = CITIES[ci]
        net = net_of(c[0], j) if direction == "in" else None
        a = {"site": site_d["id"], "dir": direction, "cc": c[2], "country": c[1], "city": c[0], "lat": c[3], "lon": c[4],
             "count": count, "denied": denied, "vpn": count if net == "vpn" else 0, "tor": count if net == "tor" else 0,
             "hosting": count if net == "hosting" else 0, "type": dtype_, "port": port_}
        arcs.append(a)
        site_d["total"] += count; site_d["denied"] += denied

    load = diurnal(now)
    for fi, (name, lat, lon, city) in enumerate(FIREWALLS):
        s = site(name, lat, lon, city)
        size = 1.0 if fi == 0 else 0.35 + 0.1 * (fi % 3)
        for ci, c in enumerate(CITIES):
            r = rng("arc", name, ci, slot)
            if c[5] and r.random() < .75:
                n = int(c[5] * 6 * size * load * scale * (0.6 + .8 * r.random()))
                add(s, "firewall-sophos-xg", "out", ci, n, int(n * .02 * r.random()), pick(r, OUT_PORTS))
            if c[6] and r.random() < .55:
                n = int(c[6] * 1.6 * size * scale * (0.5 + r.random()))
                add(s, "firewall-sophos-xg", "in", ci, n, int(n * (.75 + .25 * r.random())), pick(r, IN_PORTS), j=fi)
    servers = {n: site(n, home["lat"], home["lon"], "Toronto") for n, _ in SERVERS}
    for ci, c in enumerate(CITIES):
        r = rng("srv", ci, slot)
        if c[6] and r.random() < .35:
            n = int(1 + c[6] * .3 * scale * r.random())
            add(servers["nas01.example.lan"], "syslog", "in", ci, n, n, 22, j=7)
        if c[6] and r.random() < .30:
            n = int(1 + c[6] * .4 * scale * r.random())
            add(servers["web01.example.lan"], "linux", "in", ci, n, n, 22, j=3)
        if c[6] >= 4 and r.random() < .15:
            n = int(1 + scale * r.random() * 2)
            add(servers["dc01.example.lan"], "wineventlog", "in", ci, n, n, 3389, j=5)
        if (c[2] in ("CA", "US") and r.random() < .7) or (c[6] and r.random() < .06):
            n = int(1 + (4 if c[2] in ("CA", "US") else 1) * scale * r.random())
            add(servers["m365-tenant"], "o365", "in", ci, n, 0 if c[2] in ("CA", "US") else n, None, j=9)
    arcs.sort(key=lambda a: -a["count"])
    total = sum(a["count"] for a in arcs)
    denied = sum(a["denied"] for a in arcs)
    countries = {}
    for a in arcs:
        x = countries.setdefault(a["cc"], {"cc": a["cc"], "country": a["country"], "count": 0, "denied": 0, "in": 0, "out": 0})
        x["count"] += a["count"]; x["denied"] += a["denied"]; x[a["dir"]] += a["count"]
    ticker, r = [], rng("ticker", slot)
    blocked = [a for a in arcs if a["dir"] == "in" and a["denied"]]
    for k in range(min(14, len(blocked))):
        a = pick(r, [(x, x["denied"]) for x in blocked])
        ci = next(i for i, c in enumerate(CITIES) if c[0] == a["city"])
        j = r.randrange(5)
        ticker.append({"t": iso(now - 1500 - k * r.randrange(1500, 5000)), "ip": city_ip(ci, j), "city": a["city"],
                       "country": a["country"], "cc": a["cc"], "port": a["port"], "proto": "TCP" if a["port"] else None,
                       "site": a["site"], "type": a["type"], "lat": a["lat"], "lon": a["lon"],
                       "net": "tor" if a["tor"] else "vpn" if a["vpn"] else "hosting" if a["hosting"] else None})
    used = {a["site"] for a in arcs}
    return {"window_s": window, "type": dtype, "port": port, "generated": iso(now), "age_s": 1.4, "total": total,
            "denied": denied, "failed": 0, "per_min": round(total * 60 / window), "home": home,
            "sites": [s for s in sites.values() if s["id"] in used or s["id"] in dict((f[0], 1) for f in FIREWALLS)],
            "arcs": [{k: v for k, v in a.items() if k not in ("type", "port")} for a in arcs[:200]],
            "arcs_total": len(arcs),
            "countries": sorted(countries.values(), key=lambda x: -x["count"])[:12], "ticker": ticker,
            "geoip": {"db": time.strftime("%Y-%m-%d"), "lists": {"tor": 1204, "vpn": 11112, "hosting": 44602}, "online_today": 3}}


# ---------------------------------------------------------------- sources, alerts, lag, cluster, storage, lookups
def source_list():
    out = [(f[0], "firewall-sophos-xg") for f in FIREWALLS] + list(SERVERS)
    return out


def api_sources():
    now = now_ms()
    day = int(sum(events_per_min(now - h * 3600000) * 60 for h in range(24)))
    al = alerts_between(now - 24 * 3600000, now)
    rows = []
    for name, t in source_list():
        share = TYPE_SHARE[t] / (len(FIREWALLS) if t == "firewall-sophos-xg" else 1)
        if t == "firewall-sophos-xg":
            share *= 2.2 if name == "HQ-Toronto" else 0.83
        n = int(day * share)
        rows.append({"name": name, "events": n, "share": n / day * 100, "type": t, "types": [t],
                     "last": now - rng("last", name, now // 5000).randrange(400, 4000),
                     "alerts": sum(a["source"] == name for a in al),
                     "hourly": [int(n / 24 * diurnal(now - (24 - k) * 3600000)) for k in range(25)]})
    types = []
    for t, s in TYPE_SHARE.items():
        mine = [x for x in rows if x["type"] == t]
        types.append({"name": t, "events": sum(x["events"] for x in mine), "share": sum(x["share"] for x in mine),
                      "sources": len(mine), "top": max(mine, key=lambda x: x["events"])["name"]})
    return {"total": sum(x["events"] for x in rows), "now": now, "sources": sorted(rows, key=lambda x: -x["events"]),
            "types": sorted(types, key=lambda x: -x["events"])}


RAW = {
    "firewall-sophos-xg": 'device="SFW" log_type="Firewall" log_component="Firewall Rule" status="{status}" src_ip={ip} '
                          'dst_port={port} protocol="TCP" fw_rule_name="WAN to LAN" src_country="{cc}"',
    "syslog": "<38>1 {t} nas01.example.lan sshd-session 4120 - - Invalid user admin from {ip} port 51234",
    "linux": '{{"_HOSTNAME":"web01.example.lan","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Failed password for root from {ip} port 40122 ssh2"}}',
    "wineventlog": '{{"EventID":4625,"Computer":"dc01.example.lan","TargetUserName":"administrator","IpAddress":"{ip}","LogonType":10}}',
    "o365": '{{"Operation":"UserLoggedIn","Workload":"AzureActiveDirectory","UserId":"jane.doe@example.com","ClientIP":"{ip}","ResultStatus":"Success"}}',
}


def api_source(name):
    src = next((x for x in api_sources()["sources"] if x["name"] == name), None)
    if not src:
        return {"error": "no such source in the last 24 h"}
    now = now_ms()
    al = [a for a in alerts_between(now - 24 * 3600000, now) if a["source"] == name]
    rules = {}
    for a in al:
        x = rules.setdefault(a["name"], {"name": a["name"], "n": 0, "sev": a["sev"]})
        x["n"] += 1
    r = rng("recent", name, now // 5000)
    recent = []
    for k in range(20):
        t = iso(now - k * r.randrange(800, 4000))
        ci = r.randrange(len(CITIES))
        recent.append({"t": t, "device_t": t, "type": src["type"],
                       "raw": RAW[src["type"]].format(ip=city_ip(ci, r.randrange(5)), port=pick(r, IN_PORTS), cc=CITIES[ci][2],
                                                      status=r.choice(["Deny", "Allow"]), t=t)})
    lag = next((x for x in S["_lag"]["sources"] if x["name"] == name), None)
    return {"name": name, "events": src["events"], "alerts": len(al),
            "hourly": [{"t": (now // 3600000 - 24 + k) * 3600000, "n": n} for k, n in enumerate(src["hourly"])],
            "types": [{"name": src["type"], "n": src["events"]}], "rules": sorted(rules.values(), key=lambda x: -x["n"]),
            "recent": recent, "lag": lag}


def api_alerts(p):
    now = now_ms()
    items = alerts_between(now - 24 * 3600000, now)
    sevs, sources, rules = {}, [], []
    for a in items:
        sevs[a["sev"]] = sevs.get(a["sev"], 0) + 1
        if a["source"] not in sources:
            sources.append(a["source"])
        if a["name"] not in rules:
            rules.append(a["name"])
    q = (p.get("q") or "").lower()[:100]
    items = [a for a in items if (not p.get("sev") or a["sev"] == p["sev"]) and (not p.get("source") or a["source"] == p["source"])
             and (not p.get("rule") or a["name"] == p["rule"])
             and (not q or q in (a["name"] + " " + a["desc"] + " " + a["source"] + " " + a["type"]).lower())]
    size = max(1, min(100, int(p.get("size", 25) or 25)))
    frm = max(0, int(p.get("from", 0) or 0))
    keys = ("id", "t", "sev", "name", "source", "type", "status", "ip", "affected", "category", "lat", "lon", "technique")
    return {"total": len(items), "from": frm, "size": size, "items": [{k: a[k] for k in keys} for a in items[frm:frm + size]],
            "sev": sevs, "sources": sources[:30], "rules": rules[:30]}


def api_alert(aid):
    now = now_ms()
    a = next((x for x in alerts_between(now - 48 * 3600000, now) if x["id"] == aid), None)
    if not a:
        return {"error": "Alert not found (it may have aged out of OpenSearch)."}
    tgt = next((f for f in FIREWALLS if f[0] == a["source"]), FIREWALLS[0])
    geo_a = {"country": a["country"], "countryCode": a["cc"], "city": a["city"], "latitude": a["lat"], "longitude": a["lon"]}
    geo_t = {"country": "Canada", "countryCode": "CA", "city": tgt[3], "latitude": tgt[1], "longitude": tgt[2]}
    r = rng("detail", aid)
    n = 1 + r.randrange(3)
    events = [{"timestamp": iso(a["t_ms"] - k * 7000), "dataType": a["type"], "dataSource": a["source"],
               "origin": {"ip": a["ip"], "port": 40000 + r.randrange(20000), "geolocation": geo_a},
               "target": {"ip": "10.20.0.%d" % (10 + r.randrange(40)), "port": a["port"]},
               "severity": "info", "actionResult": "denied" if a["type"] == "firewall-sophos-xg" else "failed",
               "raw": RAW[a["type"]].format(ip=a["ip"], port=a["port"], cc=a["cc"], status="Deny", t=a["t"])}
              for k in range(n)]
    return {"id": a["id"], "_index": "v11-alert-demo", "name": a["name"], "severity": {"Low": 1, "Medium": 2, "High": 3}[a["sev"]],
            "severityLabel": a["sev"], "statusLabel": a["status"], "status": 2 if a["status"] == "Open" else 5,
            "@timestamp": a["t"], "category": a["category"], "technique": a["technique"] or "Indeterminate",
            "description": a["desc"], "solution": a["solution"], "dataSource": a["source"], "dataType": a["type"],
            "adversary": {"ip": a["ip"], "port": events[0]["origin"]["port"], "geolocation": geo_a},
            "target": {"ip": "10.20.0.15", "port": a["port"], "geolocation": geo_t},
            "impact": {"confidentiality": 1, "integrity": 1, "availability": 1 if a["sev"] != "High" else 2},
            "deduplicatedBy": ["adversary.ip", "target.ip"], "reference": ["https://attack.mitre.org/"] if a["technique"] else [],
            "notes": "", "groupedBy": None, "isIncident": False, "event_count": n, "events": events}


def compute_lag():
    now = now_ms()
    srcs = []
    for name, t in source_list():
        r = rng("lagsrc", name, now // 60000)
        p50 = 180 + 60 * r.random() if t == "o365" else 0.8 + 2 * r.random()
        docs = int(900 * 15 * TYPE_SHARE[t] * (2.2 if name == "HQ-Toronto" else 1) * (0.8 + .4 * r.random()))
        srcs.append({"name": name, "type": t, "docs": docs, "eps": docs / 900, "age_s": 0.5 + 3 * r.random(),
                     "p50": p50, "p95": p50 * 1.6})
    srcs.sort(key=lambda x: -abs(x["p50"]))
    S["_lag"].update({"computed_at": now, "sources": srcs})


def api_cluster():
    return {"status": "green", "nodes": 1, "active_pct": 100.0, "active": 64, "primaries": 64, "unassigned": 0,
            "unassigned_primaries": 0, "reasons": {}, "families": [], "decider": [], "explained": None,
            "notes": [{"level": "ok", "title": "Cluster is green", "text": "All primary and replica shards are assigned."}],
            "fix": None}


def api_storage():
    now = now_ms()
    days = []
    for d in range(5, 0, -1):
        day = datetime.fromtimestamp((now - d * 86400000) / 1000, timezone.utc).strftime("%Y-%m-%d")
        logs = int(4.1e9 * (0.9 + .2 * rng("st", day).random()))
        al = int(6.2e6 * (0.8 + .4 * rng("sta", day).random()))
        days.append({"day": day, "alerts": al, "alert_docs": 360, "logs": logs, "log_docs": 7_400_000, "total": logs + al,
                     "per_alert": al / 360})
    avg = sum(x["total"] for x in days) / len(days)
    free, tot = 388e9, 1000e9
    return {"days": days, "today_utc": time.strftime("%Y-%m-%d", time.gmtime()), "avg_daily_total": avg,
            "avg_basis": "complete days", "avg_daily_alerts": sum(x["alerts"] for x in days) / len(days),
            "disk_free": free, "disk_total": tot, "disk_used": tot - free, "days_left": free / avg,
            "note": "Sizes are primary shards"}


def api_whois(ip):
    org = rng("whois", ip).choice(("Example Hosting Ltd", "Sample Transit Networks", "Demo Cloud Services"))
    net = ip.rsplit(".", 1)[0]
    return {"ip": ip, "name": org.upper().replace(" ", "-"), "handle": "NET-%s-0-1" % net.replace(".", "-"),
            "country": "NL", "type": "ALLOCATED PA", "start": net + ".0", "end": net + ".255", "parent": None,
            "cidrs": [net + ".0/24"], "status": ["active"], "registered": "2014-03-11T00:00:00Z",
            "changed": "2025-08-02T00:00:00Z",
            "contacts": [{"roles": ["registrant"], "name": org, "email": "noc@example.net", "tel": ""},
                         {"roles": ["abuse"], "name": "Abuse Desk", "email": "abuse@example.net", "tel": "+1-555-0100"}],
            "abuse": "abuse@example.net", "source": "whois.example.net",
            "remarks": ["Documentation address range (RFC 5737) - demo data"]}


def api_reputation(ip):
    r = rng("rep", ip)
    score = r.choice([0, 12, 47, 88, 100])
    return {"ip": ip,
            "abuseipdb": {"configured": True, "score": score, "reports": score * 3, "distinct_reporters": score // 4,
                          "last_reported": iso(now_ms() - r.randrange(86400000)), "usage_type": "Data Center/Web Hosting/Transit",
                          "isp": "Example Hosting Ltd", "domain": "example.net", "whitelisted": False},
            "virustotal": {"configured": True, "malicious": score // 12, "suspicious": score // 40, "harmless": 61,
                           "undetected": 27, "reputation": -score // 5, "as_owner": "EXAMPLE-AS", "country": "NL",
                           "flagged_by": ["Demo engine %d" % k for k in range(1, score // 25 + 1)]}}


def city_of(ip):
    for i, c in enumerate(CITIES):
        for j in range(6):
            if city_ip(i, j) == ip:
                return i, c
    return None, None


def api_attacker(ip, anon=False, hours=24):
    """One remote address in demo data: the ports it tried, mostly denied, at one or two sites."""
    ip = (ip or "").strip()
    if ip.rsplit(".", 1)[0] not in DOC_NETS:
        return {"ip": ip, "private": True, "note": "Private or reserved address: an internal device, not an outside attacker."}
    r = rng("attacker", ip, now_ms() // 600000)
    ci, city = city_of(ip)
    net = net_of(city[0], 0) if city else None
    ports = []
    for port, w in sorted(IN_PORTS, key=lambda x: -x[1] * r.random())[:r.randint(2, 6)]:
        n = int(w * r.uniform(2, 40))
        ok = int(n * .04) if port == 443 and r.random() < .4 else 0
        ports.append({"port": port, "count": n, "proto": "UDP" if port == 5060 else "TCP", "denied": n - ok, "allowed": ok})
    ports.sort(key=lambda x: (x["denied"], x["count"]), reverse=True)
    total = sum(x["count"] for x in ports)
    fws = r.sample(FIREWALLS, r.randint(1, 3))
    sites, left = [], total
    for i, f in enumerate(fws):
        n = left if i == len(fws) - 1 else int(left * r.uniform(.4, .7))
        left -= n
        sites.append({"site": "" if anon else "198.51.100.%d" % (200 + FIREWALLS.index(f)), "name": "Site %s" % chr(65 + i) if anon else f[0],
                      "count": n, "denied": n, "allowed": 0})
    ssh = next((x["count"] for x in ports if x["port"] == 22), 0) // 3
    return {"ip": ip, "hours": hours, "total": total, "first": iso(now_ms() - r.randrange(3, 23) * 3600000),
            "last": iso(now_ms() - r.randrange(5, 600) * 1000), "net": net,
            "types": [{"type": "firewall-sophos-xg", "count": total - ssh}] + ([{"type": "syslog", "count": ssh}] if ssh else []),
            "ports": ports, "port_count": len(ports), "replies": r.choice([0, 0, 0, 12, 40]), "reply_ports": [443],
            "reasons": [], "sites": sites, "syslog_ssh": ssh,
            "targets": [] if anon else [{"ip": "10.%d.0.%d" % (FIREWALLS.index(f) + 1, 10 + k), "count": x["count"], "ports": [x["port"]],
                                         "denied": x["denied"], "allowed": x["allowed"]} for k, (f, x) in enumerate(zip(fws * 3, ports))][:5],
            "denied": sum(x["denied"] for x in ports), "allowed": sum(x["allowed"] for x in ports)}


def report_connections(hours=24):
    r = rng("report-conn", now_ms() // 3600000)
    scale = 24 / 24
    attackers = []
    for i, c in enumerate(CITIES):
        if c[6] <= 1:
            continue
        for j in range(2):
            ip = city_ip(i, j)
            n = int(c[6] * r.uniform(150, 900))
            ps = sorted(IN_PORTS, key=lambda x: -x[1] * r.random())[:r.randint(1, 4)]
            attackers.append({"ip": ip, "country": c[1], "count": n, "net": net_of(c[0], j), "ports": [p for p, _ in ps],
                              "sites": [f[0] for f in r.sample(FIREWALLS, r.randint(1, 3))]})
    attackers.sort(key=lambda x: x["count"], reverse=True)
    dports = [{"port": p, "proto": "UDP" if p == 5060 else "TCP", "count": int(w * r.uniform(700, 1100) * scale),
               "sources": int(w * r.uniform(8, 20))} for p, w in IN_PORTS]
    dports.sort(key=lambda x: x["count"], reverse=True)
    aports = [{"port": p, "proto": "UDP" if p in (53, 123) else "TCP", "count": int(w * r.uniform(9000, 12000)),
               "sources": int(w * r.uniform(2, 6)) + 3, "destinations": int(w * r.uniform(20, 60)) + 2} for p, w in OUT_PORTS]
    aports.sort(key=lambda x: x["count"], reverse=True)
    flows = []
    for k in range(18):
        f = FIREWALLS[k % len(FIREWALLS)]
        ci = pick(r, [(i, c[5]) for i, c in enumerate(CITIES)])
        port = pick(r, OUT_PORTS)
        flows.append({"src": "10.%d.0.%d" % (k % len(FIREWALLS) + 1, 20 + k), "src_country": None, "site": f[0], "dir": "outbound",
                      "dst": city_ip(ci, k % 6), "dst_country": CITIES[ci][1], "count": int(r.uniform(800, 9000)), "ports": [port]})
    for k in range(4):
        flows.append({"src": "10.1.0.%d" % (40 + k), "src_country": None, "site": FIREWALLS[0][0], "dir": "internal",
                      "dst": "10.%d.0.10" % (k + 2), "dst_country": None, "count": int(r.uniform(3000, 12000)), "ports": [445, 3389, 443, 53][k:k + 1]})
    flows.sort(key=lambda x: x["count"], reverse=True)
    inbound = [{"ip": city_ip(i, 1), "country": CITIES[i][1], "site": FIREWALLS[n % 3][0], "count": int(r.uniform(40, 900)),
                "net": None, "dst": ["10.%d.0.5" % (n % 3 + 1)], "ports": [443] if n else [443, 3389]}
               for n, i in enumerate((0, 7, 9, 13))]
    inbound.sort(key=lambda x: x["count"], reverse=True)
    denied_in = sum(x["count"] for x in dports)
    return {"hours": hours, "denied_total": int(denied_in * 1.8), "denied_inbound": denied_in, "denied_replies": int(denied_in * .3),
            "attackers": len(attackers) * 37, "denied_ports": dports[:15], "top_attackers": attackers[:20],
            "allowed_total": sum(x["count"] for x in aports) * 3, "allowed_ports": aports, "allowed_flows": flows[:25],
            "allowed_inbound": inbound}


def install(g):
    """Swap the server's data functions for the demo ones (called by server.py when DEMO=1)."""
    S.update(g)
    for name in ("collect", "fetch_hourly", "api_sources", "api_source", "api_alerts", "api_alert", "compute_lag",
                 "api_cluster", "api_storage", "api_whois", "api_reputation", "api_attacker", "report_connections"):
        g[name] = globals()[name]
    g["build_geo"] = geo
    g["snapshot_storage"] = lambda: None          # api_storage above already answers from demo data
    g["HOST_NAME"] = "observatory-demo"
    g["current_ai_hosts"] = lambda: dict(AI_HOSTS)
