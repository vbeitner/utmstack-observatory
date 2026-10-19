# Copyright (c) 2026 Victor Beitner. All rights reserved. See LICENSE.
"""Markdown -> print-ready HTML (for PDF via Chrome). Usage: md2html.py in.md out.html "Title" "Subtitle"."""
import re, sys, markdown
src, out, title, sub = sys.argv[1:5]
import base64, os
_logo = sys.argv[5] if len(sys.argv) > 5 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "docs", "media", "brand", "logo.png")
logo_tag = ("<img src='data:image/png;base64,%s' style='height:16mm;margin-bottom:10mm;border:0'>" % base64.b64encode(open(_logo, "rb").read()).decode()
            if os.path.exists(_logo) else "<div class='k'>UTMSTACK OBSERVATORY</div>")
text = open(src).read()
text = re.sub(r'\(([^)\s]+)\.gif\)', r'(\1.gif)', text)
body = markdown.markdown(text, extensions=["tables", "fenced_code", "toc", "sane_lists", "attr_list"])
css = """
@page{size:Letter;margin:22mm 16mm 18mm 16mm}
body{font:10.5pt/1.5 -apple-system,"Segoe UI",Helvetica,Arial,sans-serif;color:#13202c;margin:0}
.cover{height:205mm;display:flex;flex-direction:column;justify-content:center;border-left:6px solid #0A7FA0;padding-left:14mm;page-break-after:always}
.cover .k{color:#0A7FA0;font-weight:700;letter-spacing:.14em;font-size:10pt}
.cover h1{font-size:30pt;margin:6mm 0 3mm;border:0}
.cover .s{font-size:13pt;color:#41566a} .cover .c{margin-top:14mm;font-size:9.5pt;color:#5B7083}
h1{font-size:20pt;border-bottom:2px solid #0A7FA0;padding-bottom:4px;margin-top:0}
h2{font-size:15pt;margin:22px 0 8px;color:#0b4f63;page-break-after:avoid}
h3{font-size:12pt;margin:16px 0 6px;page-break-after:avoid}
h2{page-break-before:auto}
table{border-collapse:collapse;width:100%;margin:8px 0 12px;font-size:9.2pt;page-break-inside:auto}
th,td{border:1px solid #cfdae3;padding:4px 6px;text-align:left;vertical-align:top}
th{background:#eaf2f7}
tr{page-break-inside:avoid}
code{font:8.8pt ui-monospace,Menlo,monospace;background:#f0f4f7;padding:1px 3px;border-radius:3px}
pre{background:#f0f4f7;padding:8px;border-radius:4px;white-space:pre-wrap;page-break-inside:avoid}
pre code{background:none;padding:0}
img{max-width:100%;border:1px solid #cfdae3;border-radius:4px;page-break-inside:avoid;display:block;margin:6px auto}
p>img{margin:6px auto}
blockquote{margin:8px 0;padding:6px 12px;border-left:4px solid #0A7FA0;background:#f2f8fb;color:#2b4153}
a{color:#0A7FA0;text-decoration:none}
hr{border:0;border-top:1px solid #cfdae3;margin:16px 0}
"""
html = ("<!doctype html><html><head><meta charset='utf-8'><title>%s</title><style>%s</style></head><body>"
        "<div class='cover'>%s<h1>%s</h1><div class='s'>%s</div><div class='c'>© 2026 Victor Beitner. All rights reserved.</div></div>%s</body></html>") % (title, css, logo_tag, title, sub, body)
open(out, "w").write(html)
