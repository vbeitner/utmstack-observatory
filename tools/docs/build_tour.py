"""Build docs/tour/index.html: a standalone click-through feature tour from tour-steps.json + the capture's rects.json.
Usage: python3 build_tour.py <steps.json> <rects.json> <out.html> <version>"""
import html
import json
import sys

steps_f, rects_f, out_f, version = sys.argv[1:5]
steps = json.load(open(steps_f))
rects = json.load(open(rects_f))
tour = []
for st in steps:
    r = rects.get(st["img"], {})
    spots = [{"label": lab, "text": txt, "box": r[sel]} for sel, lab, txt in st["spots"] if sel in r]
    tour.append({"img": "../media/screens/%s.jpg" % st["img"], "title": st["title"], "text": st["text"],
                 "mobile": bool(st.get("mobile")), "spots": spots})

PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Observatory Feature Tour</title>
<style>
:root{--bg:#F4F7FA;--panel:#FFFFFF;--ink:#0E1A26;--ink2:#41566A;--muted:#6B8193;--line:#D6E0E8;--accent:#0A7FA0;--accent-ink:#FFFFFF;--spot:#0A7FA0;--shadow:0 6px 24px rgba(14,26,38,.10)}
@media (prefers-color-scheme: dark){:root:not([data-theme="light"]){--bg:#070A0F;--panel:#0E1620;--ink:#EAF7FF;--ink2:#B9CCD8;--muted:#8299AB;--line:#1F3142;--accent:#35E7FF;--accent-ink:#04121A;--spot:#35E7FF;--shadow:0 6px 24px rgba(0,0,0,.5)}}
:root[data-theme="dark"]{--bg:#070A0F;--panel:#0E1620;--ink:#EAF7FF;--ink2:#B9CCD8;--muted:#8299AB;--line:#1F3142;--accent:#35E7FF;--accent-ink:#04121A;--spot:#35E7FF;--shadow:0 6px 24px rgba(0,0,0,.5)}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Helvetica,Arial,sans-serif}
header{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:16px 24px;border-bottom:1px solid var(--line);background:var(--panel)}
header h1{margin:0;font-size:17px;letter-spacing:.04em}
header .sub{color:var(--muted);font-size:13px}
.wrap{display:grid;grid-template-columns:minmax(0,1fr) 340px;gap:20px;padding:20px 24px;max-width:1500px;margin:0 auto}
.stage{position:relative;background:#000;border-radius:8px;overflow:hidden;box-shadow:var(--shadow);align-self:start}
.stage.mobile{max-width:390px;justify-self:center;width:100%}
.stage img{display:block;width:100%;height:auto}
.spot{position:absolute;border:2px solid var(--spot);border-radius:6px;background:transparent;cursor:pointer;padding:0;transition:box-shadow .2s,background .2s}
.spot:hover,.spot.on{background:rgba(53,231,255,.12);box-shadow:0 0 0 4px rgba(53,231,255,.25)}
.spot .n{position:absolute;left:-11px;top:-11px;width:22px;height:22px;border-radius:50%;background:var(--spot);color:var(--accent-ink);font:700 12px/22px system-ui,sans-serif;text-align:center}
aside{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:18px;box-shadow:var(--shadow);align-self:start;position:sticky;top:16px}
aside .step{color:var(--muted);font-size:12.5px;letter-spacing:.06em;text-transform:uppercase}
aside h2{margin:4px 0 8px;font-size:20px;line-height:1.25}
aside p{margin:0 0 12px;color:var(--ink2)}
ol.notes{margin:0 0 14px;padding:0;list-style:none;display:flex;flex-direction:column;gap:6px}
ol.notes li{display:flex;gap:10px;padding:8px;border-radius:6px;cursor:pointer;border:1px solid transparent}
ol.notes li:hover,ol.notes li.on{border-color:var(--line);background:var(--bg)}
ol.notes .n{flex:none;width:22px;height:22px;border-radius:50%;background:var(--accent);color:var(--accent-ink);font:700 12px/22px system-ui,sans-serif;text-align:center}
ol.notes b{display:block;font-size:14px}
ol.notes span{color:var(--ink2);font-size:13.5px}
.nav{display:flex;gap:8px;align-items:center}
.nav button{height:38px;padding:0 16px;border-radius:6px;border:1px solid var(--line);background:var(--panel);color:var(--ink);font:600 14px system-ui,sans-serif;cursor:pointer}
.nav button.primary{background:var(--accent);border-color:var(--accent);color:var(--accent-ink)}
.nav button:disabled{opacity:.4;cursor:default}
.dots{display:flex;flex-wrap:wrap;gap:6px;margin-top:14px}
.dots button{width:10px;height:10px;border-radius:50%;border:0;background:var(--line);cursor:pointer;padding:0}
.dots button.on{background:var(--accent)}
.foot{color:var(--muted);font-size:12.5px;margin-top:14px}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
@media (max-width:980px){.wrap{grid-template-columns:1fr;padding:16px}aside{position:static}}
</style>
</head>
<body>
<header>
  <div><h1>UTMSTACK OBSERVATORY</h1><div class="sub">Feature tour · version __VERSION__ · sample data</div></div>
  <div class="sub">← → keys to move</div>
</header>
<div class="wrap">
  <div class="stage" id="stage"><img id="shot" alt=""></div>
  <aside>
    <div class="step" id="stepNo"></div>
    <h2 id="title"></h2>
    <p id="text"></p>
    <ol class="notes" id="notes"></ol>
    <div class="nav"><button id="prev">Back</button><button id="next" class="primary">Next</button></div>
    <div class="dots" id="dots"></div>
    <div class="foot">All screens use the built-in demo mode: a fictional organisation and documentation-range IP addresses.</div>
  </aside>
</div>
<script>
var TOUR = __TOUR__;
var i = 0, stage = document.getElementById('stage'), shot = document.getElementById('shot');
function el(tag, cls, text){ var e = document.createElement(tag); if(cls) e.className = cls; if(text!=null) e.textContent = text; return e; }
function highlight(k){
  stage.querySelectorAll('.spot').forEach(function(s, j){ s.classList.toggle('on', j===k); });
  document.querySelectorAll('#notes li').forEach(function(s, j){ s.classList.toggle('on', j===k); });
}
function show(n){
  i = Math.max(0, Math.min(TOUR.length-1, n)); var t = TOUR[i];
  stage.classList.toggle('mobile', t.mobile);
  shot.src = t.img; shot.alt = t.title;
  document.getElementById('stepNo').textContent = 'Step ' + (i+1) + ' of ' + TOUR.length;
  document.getElementById('title').textContent = t.title;
  document.getElementById('text').textContent = t.text;
  stage.querySelectorAll('.spot').forEach(function(s){ s.remove(); });
  var notes = document.getElementById('notes'); notes.textContent = '';
  t.spots.forEach(function(sp, k){
    var b = el('button', 'spot'); b.setAttribute('aria-label', sp.label);
    b.style.left = sp.box.x + '%'; b.style.top = sp.box.y + '%'; b.style.width = sp.box.w + '%'; b.style.height = sp.box.h + '%';
    b.appendChild(el('span', 'n', k+1));
    b.addEventListener('click', function(){ highlight(k); });
    b.addEventListener('mouseenter', function(){ highlight(k); });
    stage.appendChild(b);
    var li = el('li'); li.appendChild(el('span', 'n', k+1));
    var d = el('div'); d.appendChild(el('b', null, sp.label)); d.appendChild(el('span', null, sp.text)); li.appendChild(d);
    li.addEventListener('mouseenter', function(){ highlight(k); }); li.addEventListener('click', function(){ highlight(k); });
    notes.appendChild(li);
  });
  document.getElementById('prev').disabled = i === 0;
  document.getElementById('next').textContent = i === TOUR.length-1 ? 'Start again' : 'Next';
  document.querySelectorAll('#dots button').forEach(function(d, j){ d.classList.toggle('on', j===i); d.setAttribute('aria-current', j===i ? 'step' : 'false'); });
  try { history.replaceState(null, '', '#' + (i+1)); } catch(_){}
}
TOUR.forEach(function(t, j){ var d = el('button'); d.setAttribute('aria-label', 'Step ' + (j+1) + ': ' + t.title); d.addEventListener('click', function(){ show(j); }); document.getElementById('dots').appendChild(d); });
document.getElementById('prev').addEventListener('click', function(){ show(i-1); });
document.getElementById('next').addEventListener('click', function(){ show(i === TOUR.length-1 ? 0 : i+1); });
document.addEventListener('keydown', function(e){ if(e.key==='ArrowRight') show(i+1); if(e.key==='ArrowLeft') show(i-1); });
TOUR.forEach(function(t){ new Image().src = t.img; });
show((parseInt(location.hash.slice(1), 10) || 1) - 1);
</script>
</body>
</html>
"""
page = PAGE.replace("__TOUR__", json.dumps(tour, ensure_ascii=False).replace("</", "<\\/")).replace("__VERSION__", html.escape(version))
open(out_f, "w").write(page)
print("tour:", len(tour), "steps,", sum(len(t["spots"]) for t in tour), "hotspots")
