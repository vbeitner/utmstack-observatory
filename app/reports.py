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
        bars.append('<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" fill="#2c7a9e"/>' %
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
    rows.append("<h2>Summary — last %s</h2>" % e(str(data.get("range_h", 24)) + "h"))
    rows.append(
        "<table class='kv'><tr><td>Events</td><td>%s</td></tr><tr><td>Alerts</td><td>%s</td></tr>"
        "<tr><td>Severity</td><td>High %s &middot; Medium %s &middot; Low %s</td></tr>"
        "<tr><td>Data sources online</td><td>%s / %s</td></tr>"
        "<tr><td>Ingest lag</td><td>%s</td></tr></table>"
        % (e(str(k.get("events_24h", "–"))), e(str(k.get("alerts_24h", "–"))),
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

    return """<!doctype html><html><head><meta charset="utf-8"><title>UTMStack Observatory report</title>
<style>
body{font:14px/1.5 -apple-system,Segoe UI,Arial,sans-serif;color:#1a1a1a;background:#fff;max-width:900px;margin:40px auto;padding:0 20px}
h1{font-size:22px;margin-bottom:0} .sub{color:#666;margin-top:4px}
h2{font-size:16px;border-bottom:2px solid #1a1a1a;padding-bottom:4px;margin-top:32px} h3{font-size:14px;margin:18px 0 4px}
table{border-collapse:collapse;width:100%%;margin:10px 0 20px}
table.kv td:first-child{color:#555;width:260px}
th,td{border:1px solid #ddd;padding:6px 10px;text-align:left;font-size:13px}
th{background:#f3f3f3}
.sev-high,.sev-critical{color:#c0392b;font-weight:600} .sev-medium{color:#b8860b;font-weight:600} .sev-low{color:#2d6a4f}
.warn{color:#b8860b} .caption{color:#888;font-size:11px;margin-top:-14px}
.foot{color:#999;font-size:11px;margin-top:40px;border-top:1px solid #eee;padding-top:10px}
</style></head><body>
<h1>UTMStack Observatory — Security Report</h1>
<div class="sub">%s &middot; generated %s</div>
%s
<div class="foot">Generated automatically from UTMStack's own OpenSearch data. Summary counts only — see the dashboard for detail.</div>
</body></html>""" % (e(data.get("host") or ""), e(_fmt_dt(data.get("generated_at"))), "".join(rows))


def _trend_chart(pdf, trend, width=180, height=28):
    vals = [p["events"] for p in trend]
    maxv = max(vals) or 1
    x0, y0 = pdf.get_x(), pdf.get_y()
    n = len(trend)
    bw = width / n
    pdf.set_fill_color(44, 122, 158)
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


# --------------------------------------------------------------------------------------- PDF
def _latin(text):
    """fpdf's core fonts are Latin-1: keep accents, replace anything else (e.g. Türkiye stays, emoji go)."""
    return text.encode("latin-1", "replace").decode("latin-1")


def render_pdf(data):
    pdf = FPDF()
    pdf.set_margin(15)
    pdf.add_page()
    pdf.set_font("helvetica", "B", 18)
    pdf.cell(0, 10, "UTMStack Observatory - Security Report", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("helvetica", "", 10)
    pdf.set_text_color(90, 90, 90)
    host = data.get("host") or ""
    pdf.cell(0, 6, "%s%sgenerated %s" % (host, " - " if host else "", _fmt_dt(data.get("generated_at"))),
             new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)

    def h2(text):
        pdf.ln(4)
        pdf.set_font("helvetica", "B", 13)
        pdf.cell(0, 8, text, new_x="LMARGIN", new_y="NEXT")
        pdf.set_draw_color(20, 20, 20)
        pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
        pdf.ln(2)
        pdf.set_font("helvetica", "", 10)

    def kv_table(rows):
        head = FontFace(emphasis="B", fill_color=(243, 243, 243))
        with pdf.table(col_widths=(70, 120), text_align="LEFT", first_row_as_headings=False, headings_style=head) as t:
            for label, value in rows:
                r = t.row()
                r.cell(label)
                r.cell(str(value))

    k = data.get("kpi") or {}
    sev = k.get("sev") or {}
    h2("Summary - last %sh" % data.get("range_h", 24))
    kv_table([
        ("Events", k.get("events_24h", "-")), ("Alerts", k.get("alerts_24h", "-")),
        ("Severity", "High %s | Medium %s | Low %s" % (sev.get("High", 0), sev.get("Medium", 0), sev.get("Low", 0))),
        ("Data sources online", "%s / %s" % (k.get("sources_online", "-"), k.get("sources_total", "-"))),
        ("Ingest lag", ("%.1fs" % k["lag_s"]) if k.get("lag_s") is not None else "-"),
    ])
    if k.get("sources_stale"):
        pdf.set_text_color(150, 100, 0)
        pdf.multi_cell(0, 6, "Silent sources (no data in 10 min): " + ", ".join(k["sources_stale"]))
        pdf.set_text_color(0, 0, 0)

    trend = data.get("trend")
    if trend:
        h2("Hourly events")
        _trend_chart(pdf, trend)

    if data.get("rules"):
        h2("Top alert rules")
        with pdf.table(col_widths=(110, 30, 40), text_align="LEFT") as t:
            r = t.row(); r.cell("Rule"); r.cell("Count"); r.cell("Severity")
            for rule in data["rules"]:
                r = t.row(); r.cell(rule["name"]); r.cell(str(rule["count"])); r.cell(rule["sev"])

    if data.get("alerts"):
        h2("Recent alerts")
        with pdf.table(col_widths=(32, 20, 50, 30, 28, 40), text_align="LEFT") as t:
            r = t.row()
            for c in ("Time", "Sev", "Name", "Source", "IP", "MITRE"):
                r.cell(c)
            for a in data["alerts"][:20]:
                r = t.row()
                r.cell(_fmt_dt(a.get("t"))[:16]); r.cell(a["sev"]); r.cell(a["name"][:40])
                r.cell(a.get("source", "")[:20]); r.cell(a.get("ip", "")[:20]); r.cell((a.get("technique") or "-")[:30])

    if data.get("types"):
        h2("Event source distribution")
        with pdf.table(col_widths=(100, 40), text_align="LEFT") as t:
            r = t.row(); r.cell("Type"); r.cell("Events")
            for ty in data["types"]:
                r = t.row(); r.cell(ty["name"]); r.cell(str(ty["count"]))

    geo = data.get("geo") or {}
    if geo.get("countries"):
        h2("Blocked inbound - top countries")
        pdf.multi_cell(0, 6, "%s connections/min, %s denied of %s total in the window." %
                       (geo.get("per_min", "-"), geo.get("denied", "-"), geo.get("total", "-")))
        with pdf.table(col_widths=(80, 40, 40), text_align="LEFT") as t:
            r = t.row(); r.cell("Country"); r.cell("Connections"); r.cell("Denied")
            for c in geo["countries"]:
                r = t.row(); r.cell(c.get("country") or c.get("cc", "")); r.cell(str(c.get("count", 0))); r.cell(str(c.get("denied", 0)))

    con = data.get("connections")
    if con:
        def h3(text):
            pdf.ln(2)
            pdf.set_font("helvetica", "B", 11)
            pdf.cell(0, 7, text, new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("helvetica", "", 9)

        def table(widths, head, body):
            pdf.set_font("helvetica", "", 8.5)
            with pdf.table(col_widths=widths, text_align="LEFT") as t:
                r = t.row()
                for c in head:
                    r.cell(c)
                for line in body:
                    r = t.row()
                    for c in line:
                        r.cell(_latin(str(c)))
            pdf.set_font("helvetica", "", 10)

        h2("Denied connections - last %sh" % con.get("hours", 24))
        kv_table([("Denied connections (all)", _n(con.get("denied_total"))),
                  ("Inbound attempts from the internet", "%s from %s addresses" % (_n(con.get("denied_inbound")), _n(con.get("attackers")))),
                  ("Late replies to your own connections", "%s (dropped, not attacks)" % _n(con.get("denied_replies")))])
        if con.get("denied_ports"):
            h3("Ports attackers tried (denied)")
            table((30, 60, 40, 50), ("Port", "Service", "Attempts", "Attacker addresses"),
                  [("%s%s" % (x["port"], "/" + x["proto"].lower() if x.get("proto") else ""), service(x["port"]) or "-",
                    _n(x["count"]), _n(x["sources"])) for x in con["denied_ports"]])
        if con.get("top_attackers"):
            h3("Top attackers")
            table((30, 24, 16, 18, 52, 40), ("Address", "Country", "Network", "Denied", "Ports used", "Sites targeted"),
                  [(x["ip"], x.get("country") or "", _net(x.get("net")) or "-", _n(x["count"]), _ports(x.get("ports")),
                    ", ".join(x.get("sites") or [])) for x in con["top_attackers"]])
        h2("Successful connections - last %sh" % con.get("hours", 24))
        kv_table([("Allowed connections", _n(con.get("allowed_total")))])
        if con.get("allowed_ports"):
            h3("Ports in use")
            table((30, 60, 34, 28, 28), ("Port", "Service", "Connections", "Sources", "Destinations"),
                  [("%s%s" % (x["port"], "/" + x["proto"].lower() if x.get("proto") else ""), service(x["port"]) or "-",
                    _n(x["count"]), _n(x["sources"]), _n(x["destinations"])) for x in con["allowed_ports"]])
        if con.get("allowed_inbound"):
            h3("Allowed in from the internet")
            table((32, 24, 34, 30, 40, 20), ("From", "Country", "Site", "To", "Ports", "Conns"),
                  [(x["ip"] + (" (%s)" % _net(x["net"]) if x.get("net") else ""), x.get("country") or "", x.get("site") or "",
                    ", ".join(x.get("dst") or []), _ports(x.get("ports")), _n(x["count"])) for x in con["allowed_inbound"]])
        if con.get("allowed_flows"):
            h3("Busiest connections - who to whom")
            table((28, 38, 18, 40, 34, 22), ("From", "To", "Direction", "Ports", "Firewall", "Conns"),
                  [(x["src"], x["dst"] + (" (%s)" % x["dst_country"] if x.get("dst_country") else ""), x.get("dir") or "",
                    _ports(x.get("ports")), x.get("site") or "", _n(x["count"])) for x in con["allowed_flows"]])

    cluster, res = data.get("cluster") or {}, data.get("resources") or {}
    if cluster or res:
        h2("OpenSearch & host health")
        kv_rows = []
        if cluster:
            kv_rows.append(("OpenSearch status", "%s | %s node(s) | %s%% shards active | %s unassigned" %
                            (str(cluster.get("status") or "-").upper(), cluster.get("nodes", "-"),
                             ("%.0f" % cluster["active_pct"]) if cluster.get("active_pct") is not None else "-",
                             cluster.get("unassigned", "-"))))
        if res:
            kv_rows += [
                ("Host CPU", "%.0f%% (load %.2f on %s cores)" % (res.get("cpu_pct", 0), res.get("load1", 0), res.get("cores", "-"))),
                ("Host memory", "%.0f%% (%.1f of %.1f GB)" % (res.get("mem_pct", 0), res.get("mem_used_gb", 0), res.get("mem_total_gb", 0))),
                ("Host disk", "%.0f%% (%.1f of %.1f GB)" % (res.get("disk_pct", 0), res.get("disk_used_gb", 0), res.get("disk_total_gb", 0))),
            ]
        kv_table(kv_rows)

    store = data.get("storage") or {}
    if store:
        h2("Storage & retention")
        kv_table([
            ("Disk free", "%s of %s" % (_fmt_bytes(store.get("disk_free")), _fmt_bytes(store.get("disk_total")))),
            ("Average daily volume", _fmt_bytes(store.get("avg_daily_total"))),
            ("Estimated days of storage left", ("%.0f" % store["days_left"]) if store.get("days_left") else "-"),
        ])

    return bytes(pdf.output())


# --------------------------------------------------------------------------------------- storage
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
