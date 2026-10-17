"""PDF/HTML security reports: pure rendering and storage, no HTTP and no OpenSearch here.

server.py gathers the report content (reusing its own existing data_for()/build_geo()/api_storage())
into one plain dict and hands it to build(); this module only knows how to turn that dict into an
HTML page and a PDF file, and where to keep the result. Needs fpdf2 (the one non-stdlib dependency
in this project -- see requirements.txt); everything else here is stdlib.

Report dict shape (all keys optional -- a missing section is just skipped):
  {"generated_at": iso, "range_h": int, "host": str,
   "kpi": {"events_24h", "alerts_24h", "sev": {"High","Medium","Low"}, "sources_online", "sources_total",
           "sources_stale": [name,...], "eps_5m", "lag_s"},
   "rules": [{"name","count","sev"}, ...],
   "alerts": [{"t","sev","name","source","ip","technique"}, ...],
   "geo": {"per_min","denied","total","window_s","countries": [{"country","cc","count","denied"}, ...]},
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


# --------------------------------------------------------------------------------------- HTML
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
h2{font-size:16px;border-bottom:2px solid #1a1a1a;padding-bottom:4px;margin-top:32px}
table{border-collapse:collapse;width:100%%;margin:10px 0 20px}
table.kv td:first-child{color:#555;width:260px}
th,td{border:1px solid #ddd;padding:6px 10px;text-align:left;font-size:13px}
th{background:#f3f3f3}
.sev-high,.sev-critical{color:#c0392b;font-weight:600} .sev-medium{color:#b8860b;font-weight:600} .sev-low{color:#2d6a4f}
.warn{color:#b8860b} .foot{color:#999;font-size:11px;margin-top:40px;border-top:1px solid #eee;padding-top:10px}
</style></head><body>
<h1>UTMStack Observatory — Security Report</h1>
<div class="sub">%s &middot; generated %s</div>
%s
<div class="foot">Generated automatically from UTMStack's own OpenSearch data. Summary counts only — see the dashboard for detail.</div>
</body></html>""" % (e(data.get("host") or ""), e(_fmt_dt(data.get("generated_at"))), "".join(rows))


# --------------------------------------------------------------------------------------- PDF
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

    geo = data.get("geo") or {}
    if geo.get("countries"):
        h2("Blocked inbound - top countries")
        pdf.multi_cell(0, 6, "%s connections/min, %s denied of %s total in the window." %
                       (geo.get("per_min", "-"), geo.get("denied", "-"), geo.get("total", "-")))
        with pdf.table(col_widths=(80, 40, 40), text_align="LEFT") as t:
            r = t.row(); r.cell("Country"); r.cell("Connections"); r.cell("Denied")
            for c in geo["countries"]:
                r = t.row(); r.cell(c.get("country") or c.get("cc", "")); r.cell(str(c.get("count", 0))); r.cell(str(c.get("denied", 0)))

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
