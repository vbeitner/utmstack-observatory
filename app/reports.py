# Copyright (c) 2026 Victor Beitner. All rights reserved. See LICENSE.
"""PDF/HTML security reports: pure rendering and storage, no HTTP and no OpenSearch here.

server.py gathers the report content (reusing its own existing data_for()/build_geo()/api_storage())
into one plain dict and hands it to build(); this module only knows how to turn that dict into an
HTML page and a PDF file, and where to keep the result. Needs fpdf2 (the one non-stdlib dependency
in this project -- see requirements.txt); everything else here is stdlib.

Report dict shape (all keys optional -- a missing section is just skipped):
  {"generated_at": iso, "range_h": int, "host": str,
   "kpi": {"events_24h", "alerts_24h", "sev": {"High","Medium","Low"}, "sources_online", "sources_total",
           "sources_stale": [name,...], "eps_5m", "lag_s"},
   "trend": [{"t": epoch_ms, "events": int}, ...],   # hourly, oldest first
   "rules": [{"name","count","sev"}, ...],
   "alerts": [{"t","sev","name","source","ip","technique"}, ...],
   "types": [{"name","count"}, ...],
   "geo": {"per_min","denied","total","window_s","countries": [{"country","cc","count","denied"}, ...]},
   "cluster": {"status","nodes","active_pct","unassigned"},
   "resources": {"cpu_pct","load1","cores","mem_pct","mem_used_gb","mem_total_gb","disk_pct","disk_used_gb","disk_total_gb"},
   "storage": {"disk_free","disk_total","days_left","avg_daily_total"}}
"""
import base64
import html
import os
import re
import tempfile
from datetime import datetime, timezone
from fpdf import FPDF
from fpdf.fonts import FontFace

DIR_NAME = "reports"
KEEP = 30
SEV_COLOR = {"High": "#c0392b", "Critical": "#c0392b", "Medium": "#b8860b", "Low": "#2d6a4f"}


def reports_dir(data_dir):
    d = os.path.join(data_dir, DIR_NAME)
    os.makedirs(d, exist_ok=True)
    return d


def _stamp(generated_at):
    return re.sub(r"[^0-9TZ]", "", generated_at[:19] + "Z")   # 2026-10-17T20:00:00+.. -> 20261017T200000Z


def _fmt_bytes(n):
    if n is None:
        return "–"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return "%.1f %s" % (n, unit) if unit != "B" else "%d B" % n
        n /= 1024.0


def _fmt_dt(iso):
    if not iso:
        return "–"
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M UTC")
    except ValueError:
        return iso


def _fmt_ms(ms):
    return _fmt_dt(datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat())


def _trend_svg(trend, w=860, h=110):
    vals = [p["events"] for p in trend]
    maxv = max(vals) or 1
    n = len(trend)
    bw = w / n
    bars = []
    for i, p in enumerate(trend):
        bar_h = (p["events"] / maxv) * (h - 20)
        bars.append('<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" fill="#0a9fc4"/>' %
                    (i * bw + 0.5, h - 20 - bar_h, max(0.5, bw - 1), bar_h))
    return ('<svg viewBox="0 0 %d %d" width="100%%" height="%d" style="display:block;background:#fafafa">'
            % (w, h, h) + "".join(bars) +
            '<line x1="0" y1="%d" x2="%d" y2="%d" stroke="#ccc"/></svg>' % (h - 20, w, h - 20))


# --------------------------------------------------------------------------------------- HTML
SERVICES = {20: "FTP data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP", 80: "HTTP", 110: "POP3",
            123: "NTP", 135: "MS RPC", 137: "NetBIOS", 139: "NetBIOS", 143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS",
            445: "SMB", 465: "SMTPS", 500: "IPsec IKE", 514: "Syslog", 587: "SMTP submission", 993: "IMAPS", 995: "POP3S",
            1194: "OpenVPN", 1433: "MS SQL", 1723: "PPTP", 1900: "SSDP", 3306: "MySQL", 3389: "RDP", 4500: "IPsec NAT-T",
            5060: "SIP", 5061: "SIP TLS", 5353: "mDNS", 5432: "PostgreSQL", 5900: "VNC", 6881: "BitTorrent",
            7680: "Windows Delivery Optimization", 8000: "HTTP alt", 8080: "HTTP proxy", 8443: "HTTPS alt",
            9200: "OpenSearch", 11211: "Memcached", 27017: "MongoDB"}


def service(port):
    return SERVICES.get(port, "")


def _port_label(port, proto=None):
    if port is None:
        return "-"
    name = service(port)
    return "%s%s%s" % (port, "/" + proto.lower() if proto else "", " (%s)" % name if name else "")


def _ports(ports):
    return ", ".join(_port_label(p) for p in ports or []) or "-"


def _n(v):
    return "{:,}".format(v) if isinstance(v, int) else str(v if v is not None else "-")


def _net(v):
    return {"vpn": "VPN", "tor": "Tor", "hosting": "Hosting"}.get(v or "", "")


def render_html(data):
    e = html.escape
    k = data.get("kpi") or {}
    sev = k.get("sev") or {}
    rows = []
    tiles = "".join("<div class='tile' style='border-top-color:rgb%s'><div class='tl'>%s</div><div class='tv'>%s</div><div class='ts'>%s</div></div>"
                    % (str(rgb), e(label), e(value), e(sub)) for label, value, sub, rgb in _summary_tiles(data))
    rows.append("<div class='tiles'>%s</div>" % tiles)
    rows.append("<h2>Key findings</h2><ul class='findings'>%s</ul>" % "".join(
        "<li class='f-%s'>%s</li>" % (e(level), e(text)) for level, text in key_findings(data)))
    rows.append("<h2>Summary — last %s</h2>" % e(str(data.get("range_h", 24)) + "h"))
    rows.append(
        "<table class='kv'><tr><td>Events</td><td>%s</td></tr><tr><td>Alerts</td><td>%s</td></tr>"
        "<tr><td>Severity</td><td>High %s &middot; Medium %s &middot; Low %s</td></tr>"
        "<tr><td>Data sources online</td><td>%s / %s</td></tr>"
        "<tr><td>Ingest lag</td><td>%s</td></tr></table>"
        % (e(_n(k.get("events_24h", "–"))), e(_n(k.get("alerts_24h", "–"))),
           e(str(sev.get("High", 0))), e(str(sev.get("Medium", 0))), e(str(sev.get("Low", 0))),
           e(str(k.get("sources_online", "–"))), e(str(k.get("sources_total", "–"))),
           e("%.1fs" % k["lag_s"] if k.get("lag_s") is not None else "–")))
    if k.get("sources_stale"):
        rows.append("<p class='warn'>Silent sources (no data in 10 min): %s</p>" % e(", ".join(k["sources_stale"])))

    trend = data.get("trend")
    if trend:
        rows.append("<h2>Hourly events</h2>" + _trend_svg(trend) +
                    "<p class='caption'>%s &rarr; %s</p>" % (e(_fmt_ms(trend[0]["t"])), e(_fmt_ms(trend[-1]["t"]))))

    if data.get("rules"):
        rows.append("<h2>Top alert rules</h2><table><tr><th>Rule</th><th>Count</th><th>Severity</th></tr>")
        for r in data["rules"]:
            rows.append("<tr><td>%s</td><td>%s</td><td class='sev-%s'>%s</td></tr>" %
                        (e(r["name"]), r["count"], e(r["sev"].lower()), e(r["sev"])))
        rows.append("</table>")

    if data.get("alerts"):
        rows.append("<h2>Recent alerts</h2><table><tr><th>Time</th><th>Severity</th><th>Name</th>"
                    "<th>Source</th><th>IP</th><th>MITRE technique</th></tr>")
        for a in data["alerts"]:
            rows.append("<tr><td>%s</td><td class='sev-%s'>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" %
                        (e(_fmt_dt(a.get("t"))), e(a["sev"].lower()), e(a["sev"]), e(a["name"]),
                         e(a.get("source", "")), e(a.get("ip", "")), e(a.get("technique") or "–")))
        rows.append("</table>")

    if data.get("types"):
        rows.append("<h2>Event source distribution</h2><table><tr><th>Type</th><th>Events</th></tr>")
        for t in data["types"]:
            rows.append("<tr><td>%s</td><td>%s</td></tr>" % (e(t["name"]), t["count"]))
        rows.append("</table>")

    geo = data.get("geo") or {}
    if geo.get("countries"):
        rows.append("<h2>Blocked inbound — top countries</h2>"
                    "<p>%s connections/min &middot; %s denied of %s total in the window</p>"
                    "<table><tr><th>Country</th><th>Connections</th><th>Denied</th></tr>" %
                    (e(str(geo.get("per_min", "–"))), e(str(geo.get("denied", "–"))), e(str(geo.get("total", "–")))))
        for c in geo["countries"]:
            rows.append("<tr><td>%s</td><td>%s</td><td>%s</td></tr>" %
                        (e(c.get("country") or c.get("cc", "")), c.get("count", 0), c.get("denied", 0)))
        rows.append("</table>")

    con = data.get("connections")
    if con:
        rows.append("<h2>Denied connections — last %sh</h2><table class='kv'>"
                    "<tr><td>Denied connections (all)</td><td>%s</td></tr>"
                    "<tr><td>Inbound attempts from the internet</td><td>%s from %s addresses</td></tr>"
                    "<tr><td>Late replies to your own connections (dropped, not attacks)</td><td>%s</td></tr></table>" %
                    (e(str(con.get("hours", 24))), _n(con.get("denied_total")), _n(con.get("denied_inbound")),
                     _n(con.get("attackers")), _n(con.get("denied_replies"))))
        if con.get("denied_ports"):
            rows.append("<h3>Ports attackers tried (denied)</h3><table><tr><th>Port</th><th>Service</th><th>Attempts</th><th>Attacker addresses</th></tr>")
            for x in con["denied_ports"]:
                rows.append("<tr><td>%s%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" %
                            (e(str(x["port"])), e("/" + x["proto"].lower() if x.get("proto") else ""), e(service(x["port"])),
                             _n(x["count"]), _n(x["sources"])))
            rows.append("</table>")
        if con.get("top_attackers"):
            rows.append("<h3>Top attackers</h3><table><tr><th>Address</th><th>Country</th><th>Network</th><th>Denied</th>"
                        "<th>Ports used</th><th>Sites targeted</th></tr>")
            for x in con["top_attackers"]:
                rows.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" %
                            (e(x["ip"]), e(x.get("country") or ""), e(_net(x.get("net"))), _n(x["count"]),
                             e(_ports(x.get("ports"))), e(", ".join(x.get("sites") or []))))
            rows.append("</table>")
        rows.append("<h2>Successful connections — last %sh</h2><table class='kv'><tr><td>Allowed connections</td><td>%s</td></tr></table>" %
                    (e(str(con.get("hours", 24))), _n(con.get("allowed_total"))))
        if con.get("allowed_ports"):
            rows.append("<h3>Ports in use</h3><table><tr><th>Port</th><th>Service</th><th>Connections</th><th>Sources</th><th>Destinations</th></tr>")
            for x in con["allowed_ports"]:
                rows.append("<tr><td>%s%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" %
                            (e(str(x["port"])), e("/" + x["proto"].lower() if x.get("proto") else ""), e(service(x["port"])),
                             _n(x["count"]), _n(x["sources"]), _n(x["destinations"])))
            rows.append("</table>")
        if con.get("allowed_inbound"):
            rows.append("<h3>Allowed in from the internet</h3><table><tr><th>From</th><th>Country</th><th>Site</th><th>To</th>"
                        "<th>Ports</th><th>Connections</th></tr>")
            for x in con["allowed_inbound"]:
                rows.append("<tr><td>%s%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" %
                            (e(x["ip"]), e(" (" + _net(x["net"]) + ")" if x.get("net") else ""), e(x.get("country") or ""),
                             e(x.get("site") or ""), e(", ".join(x.get("dst") or [])), e(_ports(x.get("ports"))), _n(x["count"])))
            rows.append("</table>")
        if con.get("allowed_flows"):
            rows.append("<h3>Busiest connections — who to whom</h3><table><tr><th>From</th><th>To</th><th>Direction</th>"
                        "<th>Ports</th><th>Firewall</th><th>Connections</th></tr>")
            for x in con["allowed_flows"]:
                rows.append("<tr><td>%s</td><td>%s%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" %
                            (e(x["src"]), e(x["dst"]), e(" (" + x["dst_country"] + ")" if x.get("dst_country") else ""),
                             e(x.get("dir") or ""), e(_ports(x.get("ports"))), e(x.get("site") or ""), _n(x["count"])))
            rows.append("</table>")

    cluster, res = data.get("cluster") or {}, data.get("resources") or {}
    if cluster or res:
        rows.append("<h2>OpenSearch &amp; host health</h2><table class='kv'>")
        if cluster:
            rows.append("<tr><td>OpenSearch status</td><td>%s &middot; %s node(s) &middot; %s%% shards active &middot; %s unassigned</td></tr>" %
                        (e(str(cluster.get("status") or "–").upper()), cluster.get("nodes", "–"),
                         ("%.0f" % cluster["active_pct"]) if cluster.get("active_pct") is not None else "–", cluster.get("unassigned", "–")))
        if res:
            rows.append("<tr><td>Host CPU</td><td>%.0f%% (load %.2f on %s cores)</td></tr>"
                        "<tr><td>Host memory</td><td>%.0f%% (%.1f of %.1f GB)</td></tr>"
                        "<tr><td>Host disk</td><td>%.0f%% (%.1f of %.1f GB)</td></tr>" %
                        (res.get("cpu_pct", 0), res.get("load1", 0), res.get("cores", "–"),
                         res.get("mem_pct", 0), res.get("mem_used_gb", 0), res.get("mem_total_gb", 0),
                         res.get("disk_pct", 0), res.get("disk_used_gb", 0), res.get("disk_total_gb", 0)))
        rows.append("</table>")

    store = data.get("storage") or {}
    if store:
        rows.append("<h2>Storage &amp; retention</h2><table class='kv'>"
                    "<tr><td>Disk free</td><td>%s of %s</td></tr>"
                    "<tr><td>Average daily volume</td><td>%s</td></tr>"
                    "<tr><td>Estimated days of storage left</td><td>%s</td></tr></table>" %
                    (_fmt_bytes(store.get("disk_free")), _fmt_bytes(store.get("disk_total")),
                     _fmt_bytes(store.get("avg_daily_total")),
                     ("%.0f" % store["days_left"]) if store.get("days_left") else "–"))

    logo = ""
    if os.path.exists(LOGO_PNG):
        with open(LOGO_PNG, "rb") as f:
            logo = "<img class='logo' alt='UTMStack Observatory' src='data:image/png;base64,%s'>" % base64.b64encode(f.read()).decode()
    return """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>UTMStack Observatory - Security Operations Report</title>
<style>
:root{--navy:#0E1A26;--accent:#0A9FC4;--muted:#5B7083;--line:#D6E0E8;--zebra:#F4F7FA}
*{box-sizing:border-box}
body{font:14px/1.55 -apple-system,"Segoe UI",Helvetica,Arial,sans-serif;color:#1a2633;background:#fff;max-width:960px;margin:0 auto;padding:0 24px 40px}
header.top{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:18px 0 12px;border-bottom:3px solid var(--accent)}
.logo{height:44px}
.meta{text-align:right;color:var(--muted);font-size:12px}
h1{font-size:26px;color:var(--navy);margin:22px 0 2px} .sub{color:var(--muted);margin:0 0 18px}
h2{font-size:17px;color:var(--navy);margin:30px 0 8px;padding-left:10px;border-left:4px solid var(--accent)}
h3{font-size:14.5px;color:var(--navy);margin:18px 0 6px}
.tiles{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}
.tile{background:var(--zebra);border-top:4px solid var(--accent);padding:10px 12px}
.tl{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)} .tv{font-size:24px;font-weight:700;color:var(--navy)} .ts{font-size:11.5px;color:var(--muted)}
ul.findings{list-style:none;padding:0;margin:0} ul.findings li{padding:7px 10px 7px 26px;position:relative;border-bottom:1px solid var(--line)}
ul.findings li:before{content:"";position:absolute;left:8px;top:14px;width:9px;height:9px;border-radius:2px;background:var(--accent)}
li.f-bad:before{background:#c0392b} li.f-warn:before{background:#b8860b} li.f-ok:before{background:#22b573}
table{border-collapse:collapse;width:100%%;margin:8px 0 18px;font-size:13px}
th{background:var(--navy);color:#fff;text-align:left;font-weight:600;padding:7px 10px}
td{padding:6px 10px;border-bottom:1px solid var(--line);vertical-align:top} tr:nth-child(even) td{background:var(--zebra)}
table.kv td:first-child{color:var(--muted);width:280px}
.sev-high,.sev-critical{color:#c0392b;font-weight:600} .sev-medium{color:#b8860b;font-weight:600} .sev-low{color:#2d6a4f}
.warn{color:#b8860b} .caption{color:#888;font-size:11px;margin-top:-14px}
footer.foot{display:flex;justify-content:space-between;gap:12px;color:var(--muted);font-size:11.5px;margin-top:40px;border-top:1px solid var(--line);padding-top:10px}
@media (max-width:700px){.tiles{grid-template-columns:repeat(2,1fr)} .meta{display:none}}
@media print{body{max-width:none;padding:0 0 60px} header.top{position:fixed;top:0;left:0;right:0;background:#fff}
  footer.foot{position:fixed;bottom:0;left:0;right:0;background:#fff;margin:0} main{margin-top:80px}
  h2,h3{break-after:avoid} tr{break-inside:avoid} @page{margin:14mm 12mm}}
</style></head><body>
<header class="top">%s<div class="meta">Security Operations Report<br>%s &middot; %s</div></header>
<main>
<h1>Security Operations Report</h1>
<p class="sub">Last %s hours &middot; generated %s</p>
%s
<p class="caption" style="margin-top:28px">Generated automatically by UTMStack Observatory from the SIEM's own data. Counts and aggregates only &mdash; see the dashboard for detail.</p>
</main>
<footer class="foot"><span>%s &middot; Confidential</span><span>UTMStack Observatory</span></footer>
</body></html>""" % (logo, e(data.get("host") or ""), e(_fmt_dt(data.get("generated_at"))), e(str(data.get("range_h", 24))),
                       e(_fmt_dt(data.get("generated_at"))), "".join(rows), e(copyright_line(data)))


def _trend_chart(pdf, trend, width=180, height=28):
    vals = [p["events"] for p in trend]
    maxv = max(vals) or 1
    x0, y0 = pdf.get_x(), pdf.get_y()
    n = len(trend)
    bw = width / n
    pdf.set_fill_color(*ACCENT)
    for i, p in enumerate(trend):
        bar_h = (p["events"] / maxv) * height
        pdf.rect(x0 + i * bw, y0 + height - bar_h, max(0.3, bw - 0.3), bar_h, style="F")
    pdf.set_draw_color(200, 200, 200)
    pdf.line(x0, y0 + height, x0 + width, y0 + height)
    pdf.set_font("helvetica", "", 7)
    pdf.set_text_color(120, 120, 120)
    pdf.set_xy(x0, y0 + height + 1)
    pdf.cell(width / 2, 4, _fmt_ms(trend[0]["t"]))
    pdf.set_xy(x0 + width / 2, y0 + height + 1)
    pdf.cell(width / 2, 4, _fmt_ms(trend[-1]["t"]), align="R")
    pdf.set_text_color(0, 0, 0)
    pdf.set_fill_color(255, 255, 255)   # bar fill leaks into later tables' default cell fill otherwise
    pdf.set_draw_color(0, 0, 0)
    pdf.set_xy(x0, y0 + height + 7)


# --------------------------------------------------------------------------------------- branding
HERE = os.path.dirname(os.path.abspath(__file__))
LOGO_PNG = os.path.join(HERE, "brand", "report-logo.png")
COPYRIGHT_HOLDER = "Victor Beitner"
NAVY, ACCENT, MUTED, ZEBRA, LINE = (14, 26, 38), (10, 159, 196), (91, 112, 131), (244, 247, 250), (214, 224, 232)
RISKY_PORTS = {22: "SSH", 23: "Telnet", 445: "SMB", 1433: "MS SQL", 3306: "MySQL", 3389: "RDP", 5900: "VNC", 5432: "PostgreSQL"}


def copyright_line(data):
    year = (data.get("generated_at") or datetime.now(timezone.utc).isoformat())[:4]
    return "© %s %s. All rights reserved." % (year, COPYRIGHT_HOLDER)


def key_findings(data):
    """Up to six plain-language points a manager should read first: (level, text), level in bad/warn/info/ok."""
    out = []
    k, con, cl = data.get("kpi") or {}, data.get("connections") or {}, data.get("cluster") or {}
    if cl.get("status") and cl["status"] != "green":
        out.append(("bad" if cl["status"] == "red" else "warn",
                    "OpenSearch is %s with %s unassigned shard(s). Open the SIEM-health panel (status badge) to see why and "
                    "apply the fix." % (cl["status"].upper(), cl.get("unassigned", "?"))))
    if k.get("sources_stale"):
        out.append(("warn", "%d data source(s) sent nothing in the last 10 minutes: %s."
                    % (len(k["sources_stale"]), ", ".join(k["sources_stale"][:5]))))
    high = (k.get("sev") or {}).get("High", 0)
    if high:
        out.append(("bad", "%s high-severity alert(s) in the period: review them in the dashboard's alert list." % high))
    exposed = [x for x in con.get("allowed_inbound") or [] if any(p in RISKY_PORTS for p in x.get("ports") or [])]
    for x in exposed[:2]:
        names = ", ".join("%s (%s)" % (RISKY_PORTS[p], p) for p in x["ports"] if p in RISKY_PORTS)
        out.append(("warn", "Allowed in from the internet on %s: %s%s reached %s %s times. Check that this service "
                    "should be reachable from outside." % (names, x["ip"], " (%s)" % x["country"] if x.get("country") else "",
                                                           x.get("site") or "a site", _n(x["count"]))))
    if con.get("denied_ports"):
        top = con["denied_ports"][0]
        out.append(("info", "%s inbound attempts from %s addresses were blocked; the most-tried port was %s."
                    % (_n(con.get("denied_inbound")), _n(con.get("attackers")), _port_label(top["port"], top.get("proto")))))
    if con.get("top_attackers"):
        a = con["top_attackers"][0]
        out.append(("info", "Busiest attacker: %s%s, %s blocked attempts on %s." % (
            a["ip"], " (%s%s)" % (a.get("country") or "", ", " + _net(a["net"]) if a.get("net") else "") if a.get("country") else "",
            _n(a["count"]), _ports(a.get("ports")))))
    if not out:
        out.append(("ok", "No issues stood out in this period."))
    return out[:6]


# --------------------------------------------------------------------------------------- PDF
def _latin(text):
    """fpdf's core fonts are Latin-1: keep accents, replace anything else (e.g. Türkiye stays, emoji go)."""
    return str(text).replace("—", "-").replace("–", "-").replace("→", "->").replace("…", "...") \
        .encode("latin-1", "replace").decode("latin-1")


class ReportPDF(FPDF):
    def __init__(self, data):
        super().__init__()
        self.data = data
        self.set_margins(15, 26, 15)
        self.set_auto_page_break(True, 18)
        self.alias_nb_pages()

    def header(self):
        if os.path.exists(LOGO_PNG):
            self.image(LOGO_PNG, x=15, y=8, h=9)
        self.set_font("helvetica", "", 8)
        self.set_text_color(*MUTED)
        self.set_xy(110, 9)
        self.cell(85, 4, _latin("Security Operations Report"), align="R")
        self.set_xy(110, 13)
        host = self.data.get("host") or ""
        self.cell(85, 4, _latin("%s%s%s" % (host, "  |  " if host else "", _fmt_dt(self.data.get("generated_at")))), align="R")
        self.set_draw_color(*ACCENT)
        self.set_line_width(0.6)
        self.line(15, 20, 195, 20)
        self.set_line_width(0.2)
        self.set_text_color(0, 0, 0)
        self.set_xy(15, 26)

    def footer(self):
        self.set_y(-12)
        self.set_draw_color(*LINE)
        self.line(15, self.get_y() - 1, 195, self.get_y() - 1)
        self.set_font("helvetica", "", 7.5)
        self.set_text_color(*MUTED)
        self.cell(120, 5, _latin(copyright_line(self.data) + "  |  Confidential"))
        self.cell(60, 5, "Page %s of {nb}" % self.page_no(), align="R")
        self.set_text_color(0, 0, 0)


def _h2(pdf, text):
    if pdf.get_y() > 245:
        pdf.add_page()
    pdf.ln(3)
    pdf.set_fill_color(*ACCENT)
    pdf.rect(15, pdf.get_y() + 1, 1.6, 6, style="F")
    pdf.set_x(19)
    pdf.set_font("helvetica", "B", 13)
    pdf.set_text_color(*NAVY)
    pdf.cell(0, 8, _latin(text), new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.set_fill_color(255, 255, 255)
    pdf.set_font("helvetica", "", 9.5)
    pdf.ln(1)


def _h3(pdf, text):
    if pdf.get_y() > 250:
        pdf.add_page()
    pdf.ln(1.5)
    pdf.set_font("helvetica", "B", 10.5)
    pdf.set_text_color(*NAVY)
    pdf.cell(0, 6.5, _latin(text), new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("helvetica", "", 9)


def _table(pdf, widths, head, rows, align=None, font=8.5):
    pdf.set_font("helvetica", "", font)
    pdf.set_draw_color(*LINE)
    pdf.set_fill_color(*ZEBRA)                   # fpdf fills alternate rows with the current colour
    heading = FontFace(emphasis="B", color=(255, 255, 255), fill_color=NAVY)
    with pdf.table(col_widths=widths, text_align=align or "LEFT", headings_style=heading, line_height=font * 0.55,
                   cell_fill_color=ZEBRA, cell_fill_mode="ROWS", borders_layout="HORIZONTAL_LINES") as t:
        r = t.row()
        for c in head:
            r.cell(_latin(c))
        for line in rows:
            r = t.row()
            for c in line:
                r.cell(_latin(c))
    pdf.set_font("helvetica", "", 9.5)
    pdf.set_fill_color(255, 255, 255)
    pdf.ln(2)


def _kv(pdf, rows):
    _table(pdf, (70, 110), ("Item", "Value"), rows)


def _tiles(pdf, tiles):
    """Four key figures in a row: (label, value, sub, rgb)."""
    w, gap, y = 43, 2.67, pdf.get_y()
    for i, (label, value, sub, rgb) in enumerate(tiles):
        x = 15 + i * (w + gap)
        pdf.set_fill_color(*ZEBRA)
        pdf.rect(x, y, w, 22, style="F")
        pdf.set_fill_color(*rgb)
        pdf.rect(x, y, w, 1.2, style="F")
        pdf.set_xy(x + 3, y + 3)
        pdf.set_font("helvetica", "", 7)
        pdf.set_text_color(*MUTED)
        pdf.cell(w - 6, 4, _latin(label.upper()))
        pdf.set_xy(x + 3, y + 7.5)
        pdf.set_font("helvetica", "B", 15)
        pdf.set_text_color(*NAVY)
        pdf.cell(w - 6, 7, _latin(value))
        pdf.set_xy(x + 3, y + 15.5)
        pdf.set_font("helvetica", "", 7)
        pdf.set_text_color(*MUTED)
        pdf.cell(w - 6, 4, _latin(sub))
    pdf.set_text_color(0, 0, 0)
    pdf.set_fill_color(255, 255, 255)
    pdf.set_xy(15, y + 26)


LEVEL_RGB = {"bad": (192, 57, 43), "warn": (184, 134, 11), "info": ACCENT, "ok": (34, 181, 115)}


def _summary_tiles(data):
    k, con = data.get("kpi") or {}, data.get("connections") or {}
    sev = k.get("sev") or {}
    return [("Events", _n(k.get("events_24h")), "stored in the period", ACCENT),
            ("Alerts", _n(k.get("alerts_24h")), "High %s  Medium %s  Low %s" % (sev.get("High", 0), sev.get("Medium", 0), sev.get("Low", 0)),
             (192, 57, 43) if sev.get("High") else (184, 134, 11)),
            ("Data sources", "%s / %s" % (k.get("sources_online", "-"), k.get("sources_total", "-")), "reporting in the last 10 min",
             (184, 134, 11) if k.get("sources_stale") else (34, 181, 115)),
            ("Blocked attempts", _n(con.get("denied_inbound")) if con else "-",
             "from %s addresses" % _n(con.get("attackers")) if con else "inbound, denied", NAVY)]


def render_pdf(data):
    pdf = ReportPDF(data)
    pdf.add_page()
    pdf.set_font("helvetica", "B", 20)
    pdf.set_text_color(*NAVY)
    pdf.cell(0, 10, "Security Operations Report", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("helvetica", "", 10)
    pdf.set_text_color(*MUTED)
    rh = data.get("range_h", 24)
    pdf.cell(0, 6, _latin("Last %s hours  |  generated %s  |  %s" % (rh, _fmt_dt(data.get("generated_at")), data.get("host") or "")),
             new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.ln(3)
    _tiles(pdf, _summary_tiles(data))

    _h2(pdf, "Key findings")
    for level, text in key_findings(data):
        y = pdf.get_y()
        pdf.set_fill_color(*LEVEL_RGB.get(level, ACCENT))
        pdf.rect(15, y + 1.3, 2.2, 2.2, style="F")
        pdf.set_x(20)
        pdf.set_font("helvetica", "", 9.5)
        pdf.multi_cell(175, 5, _latin(text), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(0.8)
    pdf.set_fill_color(255, 255, 255)

    k = data.get("kpi") or {}
    sev = k.get("sev") or {}
    _h2(pdf, "Summary")
    _kv(pdf, [("Events", _n(k.get("events_24h"))), ("Alerts", _n(k.get("alerts_24h"))),
              ("Severity", "High %s  |  Medium %s  |  Low %s" % (sev.get("High", 0), sev.get("Medium", 0), sev.get("Low", 0))),
              ("Data sources online", "%s / %s" % (k.get("sources_online", "-"), k.get("sources_total", "-"))),
              ("Ingest lag", ("%.1f s" % k["lag_s"]) if k.get("lag_s") is not None else "-")])
    if k.get("sources_stale"):
        pdf.set_text_color(150, 100, 0)
        pdf.multi_cell(0, 5, _latin("Silent sources (no data in 10 min): " + ", ".join(k["sources_stale"])))
        pdf.set_text_color(0, 0, 0)

    trend = data.get("trend")
    if trend:
        _h2(pdf, "Hourly events")
        _trend_chart(pdf, trend)

    if data.get("rules"):
        _h2(pdf, "Top alert rules")
        _table(pdf, (120, 25, 35), ("Rule", "Count", "Severity"), [(r["name"], _n(r["count"]), r["sev"]) for r in data["rules"]])
    if data.get("alerts"):
        _h2(pdf, "Recent alerts")
        _table(pdf, (28, 16, 52, 30, 26, 28), ("Time", "Sev", "Alert", "Source", "IP", "MITRE ATT&CK"),
               [(_fmt_dt(a.get("t"))[:16], a["sev"], a["name"][:48], (a.get("source") or "")[:22], (a.get("ip") or "")[:22],
                 (a.get("technique") or "-")[:34]) for a in data["alerts"][:20]], font=7.8)
    if data.get("types"):
        _h2(pdf, "Event source distribution")
        _table(pdf, (110, 70), ("Type", "Events"), [(t["name"], _n(t["count"])) for t in data["types"]])

    geo = data.get("geo") or {}
    if geo.get("countries"):
        _h2(pdf, "Traffic by country")
        pdf.multi_cell(0, 5, _latin("%s connections a minute; %s denied of %s in the window." % (
            _n(geo.get("per_min")), _n(geo.get("denied")), _n(geo.get("total")))), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1)
        _table(pdf, (90, 45, 45), ("Country", "Connections", "Denied"),
               [(c.get("country") or c.get("cc", ""), _n(c.get("count", 0)), _n(c.get("denied", 0))) for c in geo["countries"]])

    con = data.get("connections")
    if con:
        _h2(pdf, "Denied connections - last %sh" % con.get("hours", 24))
        _kv(pdf, [("Denied connections (all)", _n(con.get("denied_total"))),
                  ("Inbound attempts from the internet", "%s from %s addresses" % (_n(con.get("denied_inbound")), _n(con.get("attackers")))),
                  ("Late replies to your own connections", "%s (dropped, not attacks)" % _n(con.get("denied_replies")))])
        if con.get("denied_ports"):
            _h3(pdf, "Ports attackers tried")
            _table(pdf, (30, 70, 40, 40), ("Port", "Service", "Attempts", "Attacker addresses"),
                   [("%s%s" % (x["port"], "/" + x["proto"].lower() if x.get("proto") else ""), service(x["port"]) or "-",
                     _n(x["count"]), _n(x["sources"])) for x in con["denied_ports"]])
        if con.get("top_attackers"):
            _h3(pdf, "Top attackers")
            _table(pdf, (30, 24, 16, 18, 52, 40), ("Address", "Country", "Network", "Denied", "Ports used", "Sites targeted"),
                   [(x["ip"], x.get("country") or "", _net(x.get("net")) or "-", _n(x["count"]), _ports(x.get("ports")),
                     ", ".join(x.get("sites") or [])) for x in con["top_attackers"]], font=7.8)
        _h2(pdf, "Successful connections - last %sh" % con.get("hours", 24))
        _kv(pdf, [("Allowed connections", _n(con.get("allowed_total")))])
        if con.get("allowed_ports"):
            _h3(pdf, "Ports in use")
            _table(pdf, (30, 60, 34, 28, 28), ("Port", "Service", "Connections", "Sources", "Destinations"),
                   [("%s%s" % (x["port"], "/" + x["proto"].lower() if x.get("proto") else ""), service(x["port"]) or "-",
                     _n(x["count"]), _n(x["sources"]), _n(x["destinations"])) for x in con["allowed_ports"]])
        if con.get("allowed_inbound"):
            _h3(pdf, "Allowed in from the internet")
            _table(pdf, (32, 24, 34, 30, 40, 20), ("From", "Country", "Site", "To", "Ports", "Conns"),
                   [(x["ip"] + (" (%s)" % _net(x["net"]) if x.get("net") else ""), x.get("country") or "", x.get("site") or "",
                     ", ".join(x.get("dst") or []), _ports(x.get("ports")), _n(x["count"])) for x in con["allowed_inbound"]], font=7.8)
        if con.get("allowed_flows"):
            _h3(pdf, "Busiest connections - who to whom")
            _table(pdf, (28, 38, 18, 40, 34, 22), ("From", "To", "Direction", "Ports", "Firewall", "Conns"),
                   [(x["src"], x["dst"] + (" (%s)" % x["dst_country"] if x.get("dst_country") else ""), x.get("dir") or "",
                     _ports(x.get("ports")), x.get("site") or "", _n(x["count"])) for x in con["allowed_flows"]], font=7.8)

    cluster, res = data.get("cluster") or {}, data.get("resources") or {}
    if cluster or res:
        _h2(pdf, "OpenSearch and host health")
        rows = []
        if cluster:
            rows.append(("OpenSearch status", "%s  |  %s node(s)  |  %s%% shards active  |  %s unassigned" % (
                str(cluster.get("status") or "-").upper(), cluster.get("nodes", "-"),
                ("%.0f" % cluster["active_pct"]) if cluster.get("active_pct") is not None else "-", cluster.get("unassigned", "-"))))
        if res:
            rows += [("Host CPU", "%.0f%% (load %.2f on %s cores)" % (res.get("cpu_pct", 0), res.get("load1", 0), res.get("cores", "-"))),
                     ("Host memory", "%.0f%% (%.1f of %.1f GB)" % (res.get("mem_pct", 0), res.get("mem_used_gb", 0), res.get("mem_total_gb", 0))),
                     ("Host disk", "%.0f%% (%.1f of %.1f GB)" % (res.get("disk_pct", 0), res.get("disk_used_gb", 0), res.get("disk_total_gb", 0)))]
        _kv(pdf, rows)
    store = data.get("storage") or {}
    if store:
        _h2(pdf, "Storage and retention")
        _kv(pdf, [("Disk free", "%s of %s" % (_fmt_bytes(store.get("disk_free")), _fmt_bytes(store.get("disk_total")))),
                  ("Average daily volume", _fmt_bytes(store.get("avg_daily_total"))),
                  ("Estimated days of storage left", ("%.0f" % store["days_left"]) if store.get("days_left") else "-")])
    pdf.ln(4)
    pdf.set_font("helvetica", "I", 8)
    pdf.set_text_color(*MUTED)
    pdf.multi_cell(0, 4.2, _latin("Generated automatically by UTMStack Observatory from the SIEM's own data. Counts and aggregates "
                                  "only; see the dashboard for detail. " + copyright_line(data)))
    return bytes(pdf.output())


def generate(data_dir, data):
    """Render both formats and write them atomically; returns this run's metadata."""
    d = reports_dir(data_dir)
    stamp = _stamp(data.get("generated_at") or datetime.now(timezone.utc).isoformat())
    html_body = render_html(data).encode()
    pdf_body = render_pdf(data)
    for ext, body in ((".html", html_body), (".pdf", pdf_body)):
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".report-")
        with os.fdopen(fd, "wb") as f:
            f.write(body)
        os.replace(tmp, os.path.join(d, "report-%s%s" % (stamp, ext)))
    prune(data_dir)
    return {"stamp": stamp, "generated_at": data.get("generated_at"), "pdf": "report-%s.pdf" % stamp,
            "html": "report-%s.html" % stamp, "pdf_bytes": len(pdf_body), "html_bytes": len(html_body)}


_NAME_RE = re.compile(r"^report-\d{8}T\d{6}Z\.(pdf|html)$")


def safe_path(data_dir, filename):
    """The on-disk path for a report filename, or None if it isn't one of ours (no path traversal)."""
    if not _NAME_RE.match(filename or ""):
        return None
    return os.path.join(reports_dir(data_dir), filename)


def list_reports(data_dir):
    d = reports_dir(data_dir)
    by_stamp = {}
    for name in os.listdir(d):
        m = _NAME_RE.match(name)
        if not m:
            continue
        stamp = name.split(".")[0].split("-", 1)[1]
        e = by_stamp.setdefault(stamp, {"stamp": stamp})
        try:
            e[m.group(1)] = {"name": name, "bytes": os.path.getsize(os.path.join(d, name))}
        except OSError:
            pass
    out = sorted(by_stamp.values(), key=lambda x: x["stamp"], reverse=True)
    for e in out:
        try:
            e["generated_at"] = datetime.strptime(e["stamp"], "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            e["generated_at"] = None
    return out


def prune(data_dir, keep=KEEP):
    reports = list_reports(data_dir)
    for e in reports[keep:]:
        for kind in ("pdf", "html"):
            f = e.get(kind)
            if f:
                try:
                    os.remove(os.path.join(reports_dir(data_dir), f["name"]))
                except OSError:
                    pass
