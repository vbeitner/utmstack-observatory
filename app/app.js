// Copyright (c) 2026 Victor Beitner. All rights reserved. See LICENSE.
(function(){
  'use strict';
  var $  = function(s,r){return (r||document).querySelector(s)};
  var $$ = function(s,r){return Array.prototype.slice.call((r||document).querySelectorAll(s))};
  function pad(n){return String(n).padStart(2,'0')}
  function hhmm(d){return pad(d.getHours())+':'+pad(d.getMinutes())}
  function hhmmss(d){return hhmm(d)+':'+pad(d.getSeconds())}
  var nf0 = new Intl.NumberFormat('en-US',{maximumFractionDigits:0});
  function compact(v){
    if(v>=1e6) return (v/1e6).toFixed(1)+'M';
    if(v>=1e3) return (v/1e3).toFixed(v>=1e4?0:1)+'k';
    return String(Math.round(v));
  }
  function clamp(v,a,b){return Math.max(a,Math.min(b,v))}
  function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
  function fit(cv, maxD){
    var r = cv.getBoundingClientRect(), d = Math.min(window.devicePixelRatio||1, maxD||2);
    var w = Math.max(1,r.width), h = Math.max(1,r.height);
    if(cv.width !== Math.round(w*d) || cv.height !== Math.round(h*d)){ cv.width = Math.round(w*d); cv.height = Math.round(h*d); }
    var ctx = cv.getContext('2d'); ctx.setTransform(d,0,0,d,0,0);
    return {ctx:ctx,w:w,h:h};
  }

  /* ---------- time range (header picker) ---------- */
  var RANGE = 24;
  try { var savedR = parseInt(localStorage.getItem('obsRange'),10); if([1,6,24].indexOf(savedR)>=0) RANGE = savedR; } catch(e){}
  function rl(){ return RANGE+' h'; }

  /* ---------- source filter: [{id, name, type}] the viewer picked; empty = every source. Kept in localStorage. ---------- */
  var SRC = [];
  try {
    var savedS = JSON.parse(localStorage.getItem('obsSources') || '[]');
    if(Array.isArray(savedS)) SRC = savedS.filter(function(x){ return x && typeof x.id === 'string' && x.id; }).slice(0, 25)
      .map(function(x){ return {id: x.id, name: String(x.name || x.id), type: String(x.type || '')}; });
  } catch(e){}
  function srcIds(){ return SRC.map(function(x){ return x.id; }).sort(); }
  function srcQuery(){ return srcIds().map(function(id){ return '&src='+encodeURIComponent(id); }).join(''); }
  function sameSrc(list){ return JSON.stringify((list||[]).slice().sort()) === JSON.stringify(srcIds()); }   // stale-answer check

  /* ---------- who is signed in: an invited user (email link) or the installer password ---------- */
  var ME = {role: 'admin', method: 'none', name: ''};
  function signedIn(r){ if(r.status === 401){ location.href = '/login'; throw new Error('signed out'); } return r; }
  fetch('/api/me', {cache:'no-store'}).then(signedIn).then(function(r){ return r.json(); }).then(function(m){ ME = m; }).catch(function(){});

  /* ---------- state ---------- */
  var D = null;                 // latest API payload
  var points = [];              // [{t:Date,total,fail}]
  var showSeries = {total:true, fail:true};
  var hoverIdx = null, liveOn = true, drawerInterval = 1;
  var trendCanvas = $('#trendCanvas'), sparkCanvas = $('#sparkCanvas'), donutCanvas = $('#donutCanvas'), detailCanvas = $('#detailCanvas');
  var tooltip = $('#tooltip'), drawer = $('#drawer'), overlay = $('#overlay');

  function visible(){ return points.slice(-30); }

  /* ---------- chart renderer ---------- */
  function drawChart(cv, data, cfg){
    var f = fit(cv), ctx = f.ctx, w = f.w, h = f.h;
    ctx.clearRect(0,0,w,h);
    var padL=cfg.padL, padR=cfg.padR, padT=cfg.padT, padB=cfg.padB, pw=w-padL-padR, ph=h-padT-padB;
    if(pw<=8 || ph<=8 || data.length<2) return;
    var N = data.length-1;
    function X(i){return padL+(i/N)*pw}
    function YT(v){return padT+ph-(v/cfg.maxTotal)*ph}
    function YF(v){return padT+ph-(v/cfg.maxFail)*ph}
    ctx.lineWidth = 1; ctx.font = '600 11.5px ui-monospace, monospace';
    for(var k=0;k<=4;k++){
      var yy = Math.round(padT+ph*k/4)+.5;
      ctx.strokeStyle = k===4 ? '#284056' : '#1B2A3A';
      ctx.beginPath(); ctx.moveTo(padL,yy); ctx.lineTo(padL+pw,yy); ctx.stroke();
      ctx.fillStyle = '#8299AB'; ctx.textAlign = 'right'; ctx.textBaseline = 'middle';
      ctx.fillText(compact(cfg.maxTotal*(1-k/4)), padL-8, yy);
      ctx.fillStyle = '#7A4750'; ctx.textAlign = 'left';
      ctx.fillText(compact(cfg.maxFail*(1-k/4)), padL+pw+8, yy);
    }
    ctx.textAlign = 'center'; ctx.textBaseline = 'top';
    for(var i=0;i<data.length;i+=cfg.vStep){
      var x = Math.round(X(i))+.5;
      ctx.strokeStyle = '#1B2A3A'; ctx.beginPath(); ctx.moveTo(x,padT); ctx.lineTo(x,padT+ph); ctx.stroke();
      ctx.fillStyle = '#8299AB'; ctx.fillText(hhmm(data[i].t), x, padT+ph+7);
    }
    ctx.save(); ctx.beginPath(); ctx.rect(padL-1,padT-3,pw+2,ph+6); ctx.clip();
    if(cfg.show.total){
      var grad = ctx.createLinearGradient(0,padT,0,padT+ph);
      grad.addColorStop(0,'rgba(53,231,255,.08)'); grad.addColorStop(1,'rgba(53,231,255,0)');
      ctx.beginPath();
      data.forEach(function(d,i){ if(i===0) ctx.moveTo(X(i),YT(d.total)); else ctx.lineTo(X(i),YT(d.total)); });
      ctx.lineTo(X(N),padT+ph); ctx.lineTo(X(0),padT+ph); ctx.closePath(); ctx.fillStyle = grad; ctx.fill();
      ctx.beginPath();
      data.forEach(function(d,i){ if(i===0) ctx.moveTo(X(i),YT(d.total)); else ctx.lineTo(X(i),YT(d.total)); });
      ctx.strokeStyle = '#35E7FF'; ctx.lineWidth = 2; ctx.lineJoin = 'round'; ctx.stroke();
    }
    if(cfg.show.fail){
      ctx.beginPath();
      data.forEach(function(d,i){ if(i===0) ctx.moveTo(X(i),YF(d.fail)); else ctx.lineTo(X(i),YF(d.fail)); });
      ctx.strokeStyle = 'rgba(255,77,94,.55)'; ctx.lineWidth = 1.5; ctx.lineJoin = 'round'; ctx.stroke();
      data.forEach(function(d,i){
        if(d.fail > 0){ ctx.beginPath(); ctx.arc(X(i),YF(d.fail),2.4,0,Math.PI*2); ctx.fillStyle = '#FF4D5E'; ctx.fill(); }
      });
    }
    if(cfg.show.total){
      var last = data[N];
      ctx.beginPath(); ctx.arc(X(N),YT(last.total),3.2,0,Math.PI*2); ctx.fillStyle = '#35E7FF'; ctx.fill();
      ctx.globalAlpha = .18; ctx.beginPath(); ctx.arc(X(N),YT(last.total),8,0,Math.PI*2); ctx.fill(); ctx.globalAlpha = 1;
    }
    if(cfg.hover != null && cfg.hover >= 0 && cfg.hover < data.length){
      var hx = X(cfg.hover);
      ctx.strokeStyle = 'rgba(53,231,255,.55)'; ctx.lineWidth = 1; ctx.setLineDash([3,3]);
      ctx.beginPath(); ctx.moveTo(Math.round(hx)+.5,padT); ctx.lineTo(Math.round(hx)+.5,padT+ph); ctx.stroke(); ctx.setLineDash([]);
      if(cfg.show.total){
        ctx.beginPath(); ctx.arc(hx,YT(data[cfg.hover].total),4,0,Math.PI*2); ctx.fillStyle = '#070A0F'; ctx.fill();
        ctx.strokeStyle = '#35E7FF'; ctx.lineWidth = 1.5; ctx.stroke();
      }
    }
    ctx.restore();
  }
  function maxima(data){
    var mt=0, mf=0;
    data.forEach(function(d){ if(d.total>mt) mt=d.total; if(d.fail>mf) mf=d.fail; });
    var stepT = mt > 40000 ? 20000 : (mt > 4000 ? 2000 : 200);
    return {total:Math.max(stepT*2, Math.ceil(mt*1.12/stepT)*stepT), fail:Math.max(4, Math.ceil(mf*1.3/2)*2)};
  }
  function renderTrend(){
    if(points.length<2) return;
    var data = visible(), m = maxima(data);
    drawChart(trendCanvas, data, {padL:52,padR:44,padT:12,padB:22,maxTotal:m.total,maxFail:m.fail,vStep:5,show:showSeries,hover:hoverIdx});
  }
  function renderSpark(){
    var f = fit(sparkCanvas), ctx = f.ctx, w = f.w, h = f.h; ctx.clearRect(0,0,w,h);
    var data = points.slice(-60); if(data.length<2) return;
    var padT=6, padB=6, min=Infinity, max=-Infinity;
    data.forEach(function(d){ if(d.total<min) min=d.total; if(d.total>max) max=d.total; });
    var span = Math.max(1, max-min);
    function X(i){return (i/(data.length-1))*w}
    function Y(v){return padT+(h-padT-padB)-((v-min)/span)*(h-padT-padB)}
    var g = ctx.createLinearGradient(0,padT,0,h); g.addColorStop(0,'rgba(53,231,255,.40)'); g.addColorStop(1,'rgba(53,231,255,0)');
    ctx.beginPath(); data.forEach(function(d,i){ if(i===0) ctx.moveTo(X(i),Y(d.total)); else ctx.lineTo(X(i),Y(d.total)); });
    ctx.lineTo(w,h-padB); ctx.lineTo(0,h-padB); ctx.closePath(); ctx.fillStyle = g; ctx.fill();
    ctx.beginPath(); data.forEach(function(d,i){ if(i===0) ctx.moveTo(X(i),Y(d.total)); else ctx.lineTo(X(i),Y(d.total)); });
    ctx.strokeStyle = '#35E7FF'; ctx.lineWidth = 1.5; ctx.lineJoin = 'round'; ctx.stroke();
    var last = data[data.length-1]; ctx.beginPath(); ctx.arc(X(data.length-1),Y(last.total),2.6,0,Math.PI*2); ctx.fillStyle = '#35E7FF'; ctx.fill();
  }

  /* ---------- donut ---------- */
  var PALETTE = ['#35E7FF','#2AA7D8','#2C7A9E','#28566E','#22394A','#1B2E3C'];
  var TYPE_LABEL = {'firewall-sophos-xg':'Sophos XG firewall','linux':'Linux auditd','o365':'Microsoft 365','syslog':'Syslog','wineventlog':'Windows events'};
  function renderDonut(){
    var f = fit(donutCanvas), ctx = f.ctx, w = f.w, h = f.h; ctx.clearRect(0,0,w,h);
    var types = (D && D.types) || [], total = types.reduce(function(s,t){return s+t.count},0);
    if(!total) return;
    var cx=w/2, cy=h/2, r=Math.min(w,h)/2-12, sw=8, a=-Math.PI/2, gap=.018;
    if(r <= sw) return;                      // canvas hidden or tiny (e.g. wall mode): nothing to draw
    types.forEach(function(t,i){
      var sweep = t.count/total*Math.PI*2;
      ctx.beginPath(); ctx.arc(cx,cy,r-sw/2,a+gap,a+sweep-gap); ctx.strokeStyle = PALETTE[i%PALETTE.length]; ctx.lineWidth = sw; ctx.stroke(); a += sweep;
    });
    ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
    ctx.fillStyle = '#EAF7FF'; ctx.font = '700 '+Math.round(Math.min(34,r*.62))+'px "Saira Condensed", Arial Narrow, sans-serif';
    ctx.fillText(compact(total), cx, cy-6);
    ctx.fillStyle = '#8299AB'; ctx.font = '600 11.5px ui-monospace, monospace';
    ctx.fillText('EVENTS · '+RANGE+' H', cx, cy+Math.min(18,r*.28));
  }
  function renderLegend(){
    var types = (D && D.types) || [], total = types.reduce(function(s,t){return s+t.count},0) || 1;
    $('#donutLegend').innerHTML = types.map(function(t,i){
      return '<div class="dl"><i style="background:'+PALETTE[i%PALETTE.length]+'"></i><span class="n">'+esc(TYPE_LABEL[t.name]||t.name)+'</span><span class="p">'+(t.count/total*100).toFixed(t.count/total<.01?1:0)+'%</span></div>';
    }).join('');
  }

  /* ---------- top rules ---------- */
  function sevColor(s){return s==='High'||s==='Critical' ? '#FF4D5E' : (s==='Medium' ? '#FFC857' : '#68F5B1')}
  function renderRules(){
    var rules = (D && D.rules) || [], body = $('#top5Body');
    if(!rules.length){ body.innerHTML = '<div class="empty">No alerts in the last '+rl()+'.</div>'; return; }
    var max = rules[0].count || 1;
    body.innerHTML = rules.map(function(r){
      return '<div class="bar-row clk" tabindex="0" data-rule="'+esc(r.name)+'"><div><div class="bar-name"><span title="'+esc(r.name)+'">'+esc(r.name)+'</span></div>'+
        '<div class="track"><div class="fill" style="width:'+Math.max(6,r.count/max*100)+'%;background:'+sevColor(r.sev)+'"></div></div></div>'+
        '<div><div class="bar-val" style="color:'+sevColor(r.sev)+'">'+nf0.format(r.count)+'</div><div class="bar-state">'+esc(String(r.sev).toUpperCase())+'</div></div></div>';
    }).join('');
  }

  /* ---------- AI traffic tab ---------- */
  var sideTab = 'rules';
  function fmtBytes(n){
    if(n>=1e9) return (n/1e9).toFixed(2)+' GB';
    if(n>=1e6) return (n/1e6).toFixed(1)+' MB';
    if(n>=1e3) return (n/1e3).toFixed(1)+' KB';
    return Math.round(n)+' B';
  }
  function setSideTab(t){
    sideTab = t;
    $$('#sideTabs button').forEach(function(b){ var on = b.dataset.tab===t; b.setAttribute('aria-pressed',String(on)); b.setAttribute('aria-selected',String(on)); });
    $('#top5Body').hidden = t!=='rules'; $('#aiBody').hidden = t!=='ai';
    $('#sideMeta').textContent = t==='rules' ? 'By alert count · '+rl() : 'Firewall-visible · 24 h';
    if(t==='ai') renderAI();
  }
  $$('#sideTabs button').forEach(function(b){ b.addEventListener('click', function(){ setSideTab(b.dataset.tab); }); });
  function renderAI(){
    var box = $('#aiBody'), ai = D && D.ai;
    if(!ai){ box.innerHTML = '<div class="empty">Waiting for data…</div>'; return; }
    if(ai.configured===false){ box.innerHTML = '<div class="empty">AI traffic is not configured on this install. Set AI_HOSTS (name=ip,name=ip) to watch specific servers.</div>'; return; }
    if(ai.error){ box.innerHTML = '<div class="empty">AI traffic unavailable: '+esc(ai.error)+'</div>'; return; }
    var hosts = ai.hosts.map(function(h){
      return '<div class="ai-row"><span class="n">'+esc(h.name)+'<small>'+esc(h.ip)+' · '+(h.conn_in+h.conn_out)+' conn</small></span>'+
        '<span class="in">↓ '+fmtBytes(h.in)+'</span><span class="out">↑ '+fmtBytes(h.out)+'</span></div>';
    }).join('');
    var peers = ai.peers.length ? ai.peers.map(function(p){
      return '<div class="ai-row"><span class="n">'+esc(p.ip)+'<small>'+esc(p.country)+' · '+p.conns+' conn · '+(p.dir==='out'?'AI→':p.dir==='in'?'→AI':'both')+'</small></span>'+
        '<span class="in">↓ '+fmtBytes(p.in)+'</span><span class="out">↑ '+fmtBytes(p.out)+'</span></div>';
    }).join('') : '<div class="ai-note">No external peers in the last 24 h.</div>';
    var ports = ai.ports.length ? ai.ports.map(function(p){ return esc(p.port)+' ×'+p.count; }).join(' · ') : '–';
    box.innerHTML =
      '<div class="ai-io"><div><div class="k">TO AI SERVERS ↓</div><div class="v" style="color:#35E7FF">'+fmtBytes(ai.in)+'</div><div class="s">'+nf0.format(ai.conn_in)+' inbound conn</div></div>'+
      '<div><div class="k">FROM AI SERVERS ↑</div><div class="v" style="color:#68F5B1">'+fmtBytes(ai.out)+'</div><div class="s">'+nf0.format(ai.conn_out)+' outbound conn</div></div></div>'+
      '<canvas class="ai-cv" id="aiCanvas" role="img" aria-label="Hourly bytes to and from the AI servers over the last 24 hours."></canvas>'+
      '<div class="ai-sec">AI SERVERS</div>'+hosts+
      '<div class="ai-sec">TOP EXTERNAL PEERS</div>'+peers+
      '<div class="ai-sec">TOP PORTS</div><div class="ai-note">'+ports+'</div>'+
      '<div class="ai-note">↓ = bytes received by the AI host, ↑ = bytes it sent. Only traffic crossing the Sophos firewall is logged.</div>';
    drawAiHourly(ai.hourly);
  }
  function drawAiHourly(hourly){
    var cv = $('#aiCanvas'); if(!cv || !hourly || !hourly.length) return;
    var f = fit(cv), ctx = f.ctx, w = f.w, h = f.h; ctx.clearRect(0,0,w,h);
    var max = 1; hourly.forEach(function(x){ max = Math.max(max, x.in, x.out); });
    var n = hourly.length, slot = w/n, bw = Math.max(1,(slot-2)/2), base = h-12;
    ctx.strokeStyle = '#284056'; ctx.beginPath(); ctx.moveTo(0,base+.5); ctx.lineTo(w,base+.5); ctx.stroke();
    hourly.forEach(function(x,i){
      var inH = x.in/max*(base-4), outH = x.out/max*(base-4);
      ctx.fillStyle = '#35E7FF'; ctx.fillRect(i*slot+1, base-inH, bw, inH);
      ctx.fillStyle = '#68F5B1'; ctx.fillRect(i*slot+1+bw, base-outH, bw, outH);
    });
    ctx.fillStyle = '#8299AB'; ctx.font = '600 11.5px ui-monospace, monospace'; ctx.textBaseline = 'top';
    [0, Math.floor(n/2), n-1].forEach(function(i, k){
      ctx.textAlign = k===0 ? 'left' : (k===2 ? 'right' : 'center');
      ctx.fillText(hhmm(new Date(hourly[i].t)), k===0 ? 0 : (k===2 ? w : w/2), base+3);
    });
    ctx.textAlign = 'right'; ctx.textBaseline = 'top'; ctx.fillText('peak '+fmtBytes(max)+'/h', w, 0);
  }

  /* ---------- resources ---------- */
  var ICONS = {cpu:'<rect x="3.5" y="3.5" width="9" height="9"/><path d="M6 1.5v2M10 1.5v2M6 12.5v2M10 12.5v2M1.5 6h2M1.5 10h2M12.5 6h2M12.5 10h2"/>',
    mem:'<rect x="1.5" y="3.5" width="13" height="7"/><path d="M4 5.5v3M7 5.5v3M10 5.5v3"/>',
    disk:'<ellipse cx="8" cy="4" rx="5.5" ry="2"/><path d="M2.5 4v8c0 1.1 2.5 2 5.5 2s5.5-.9 5.5-2V4"/>'};
  function resColor(p){return p<70 ? '#35E7FF' : (p<=85 ? '#FFC857' : '#FF4D5E')}
  function resState(p){return p<70 ? 'NORMAL' : (p<=85 ? 'ELEVATED' : 'OVER LIMIT')}
  function renderRes(){
    if(!D || !D.host) return; var h = D.host;
    $('#resHost').textContent = 'Host ' + h.hostname;
    var rows = [
      {n:'CPU load', i:'cpu', p:h.cpu_pct, sub:h.load1.toFixed(2)+' load / '+h.cores+' cores'},
      {n:'Memory',   i:'mem', p:h.mem_pct, sub:h.mem_used_gb.toFixed(1)+' / '+h.mem_total_gb.toFixed(0)+' GB'},
      {n:'Disk /',   i:'disk',p:h.disk_pct,sub:h.disk_used_gb.toFixed(0)+' / '+h.disk_total_gb.toFixed(0)+' GB'}
    ];
    $('#resBody').innerHTML = rows.map(function(r){
      var c = resColor(r.p);
      return '<div class="res"><div><div class="res-head"><svg width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="'+c+'" stroke-width="1.2" aria-hidden="true">'+ICONS[r.i]+'</svg>'+r.n+
        '<span class="state" style="color:'+c+';border-color:'+c+'44">'+resState(r.p)+'</span></div><div class="track"><div class="fill" style="width:'+clamp(r.p,0,100)+'%;background:'+c+'"></div></div></div>'+
        '<div><div class="res-val" style="color:'+c+'">'+r.p.toFixed(1)+'%</div><div class="res-sub">'+esc(r.sub)+'</div></div></div>';
    }).join('');
  }

  /* ---------- alerts + timeline ---------- */
  var activeAlert = 0, lastAlertsHtml = '';
  function lvlClass(s){return s==='High'||s==='Critical' ? 'sev' : (s==='Medium' ? 'warn' : 'info')}
  function lvlDot(s){return s==='High'||s==='Critical' ? 'red' : (s==='Medium' ? 'yellow' : 'gray')}
  function renderAlerts(){
    var al = (D && D.alerts) || [], k = (D && D.kpi) || {sev:{}};
    $('#alertMeta').textContent = (k.alerts_24h||0)+' in '+rl()+' · '+(k.sev.High||0)+' high';
    var body = $('#alertBody');
    if(!al.length){ body.innerHTML = '<tr><td colspan="6" class="empty">No alerts in the last '+rl()+'.</td></tr>'; lastAlertsHtml = ''; $('#timeline').innerHTML = ''; return; }
    var html = al.slice(0,12).map(function(a){
      var geo = a.lat!=null && a.lon!=null ? ' data-lat="'+esc(a.lat)+'" data-lon="'+esc(a.lon)+'" data-ip="'+esc(a.ip||'')+'" data-sub="'+esc(a.name||'')+'"' : '';
      return '<tr tabindex="0" data-id="'+esc(a.id)+'"'+geo+'><td class="t">'+hhmmss(new Date(a.t))+'</td>'+
        '<td><span class="lvl '+lvlClass(a.sev)+'"><i class="d '+lvlDot(a.sev)+'"></i>'+esc(a.sev)+'</span></td>'+
        '<td class="svc" title="'+esc(a.source)+'">'+esc(a.source)+'</td><td title="'+esc(a.desc)+'">'+esc(a.name)+'</td>'+
        '<td class="impact">'+a.affected+'</td><td class="state">'+esc(a.status)+'</td></tr>';
    }).join('');
    if(html !== lastAlertsHtml){ lastAlertsHtml = html; body.innerHTML = html; }   // never replace rows under the cursor unless data changed
    $('#timeline').innerHTML = al.map(function(a,i){
      return '<div class="tl-item'+(i===activeAlert?' hl':'')+'" data-i="'+i+'"><div class="time">'+hhmmss(new Date(a.t))+'</div>'+
        '<div><span class="lvl '+lvlClass(a.sev)+'"><i class="d '+lvlDot(a.sev)+'"></i>'+esc(a.sev)+'</span></div>'+
        '<div><div class="svc">'+esc(a.source)+' · '+esc(a.name)+'</div><div class="note">'+esc(a.desc)+(a.ip?' · '+esc(a.ip):'')+'</div></div>'+
        '<div class="res-sub" style="margin:0">'+a.affected+' evt</div></div>';
    }).join('');
  }

  /* ---------- KPIs and header ---------- */
  function setText(id,v){ var e = $(id); if(e.textContent !== v) e.textContent = v; }
  function renderKpis(){
    var k = D.kpi, c = D.cluster || {};
    setText('#kSrc', String(k.sources_online)); setText('#kSrcOf', '/ '+k.sources_total+' sources');
    $('#kSrcSub').innerHTML = k.sources_total ? 'Reporting in last 10 min ' + '<span class="'+(k.sources_online===k.sources_total?'good':'warn')+'">'+(k.sources_online/k.sources_total*100).toFixed(1)+'%</span>' : '&nbsp;';
    $('#kSrcSec').textContent = k.sources_stale.length ? 'Silent: '+k.sources_stale.join(', ') : 'No silent sources';
    setText('#kEv', nf0.format(k.events_24h));
    if(k.events_prev_24h > 0){
      var ch = (k.events_24h-k.events_prev_24h)/k.events_prev_24h*100;
      $('#kEvSub').innerHTML = '<span class="'+(ch>=0?'good':'warn')+'">'+(ch>=0?'↑ ':'↓ ')+Math.abs(ch).toFixed(1)+'%</span> vs previous '+rl();
    } else $('#kEvSub').textContent = 'No previous-'+rl()+' data retained';
    $('#kEvSec').textContent = k.peak ? 'Peak '+nf0.format(k.peak.n)+' events/min · '+hhmm(new Date(k.peak.t)) : '';
    setText('#kAl', nf0.format(k.alerts_24h));
    $('#kAlSub').innerHTML = '<span class="bad">High '+(k.sev.High||0)+'</span> · Medium '+(k.sev.Medium||0)+' · Low '+(k.sev.Low||0);
    $('#kAlSec').textContent = k.events_24h ? (k.alerts_24h/k.events_24h*100).toFixed(3)+'% of events raised an alert' : '';
    setText('#kLag', k.lag_s==null ? '–' : k.lag_s.toFixed(1));
    var lg = D.lag || {};
    $('#kLagSub').innerHTML = k.lag_s==null ? '&nbsp;' : (k.lag_s>=10 ? '<span class="warn">Ingest delayed</span>' :
      (lg.delayed ? '<span class="warn">Newest event fresh · '+lg.delayed+' feeds late</span>' : '<span class="good">Ingest keeping up</span>'));
    $('#kLagSec').textContent = lg.delayed ? 'Worst: '+lg.worst+' · median '+(lg.worst_p50/60).toFixed(1)+' min behind' : 'Newest event vs now';
    var badge = $('#envBadge'); badge.textContent = 'OPENSEARCH ' + String(c.status||'?').toUpperCase();
    badge.style.color = c.status==='green' ? '#68F5B1' : (c.status==='yellow' ? '#FFC857' : '#FF4D5E');
    $('#epsNum').textContent = k.eps_5m.toFixed(1);
  }
  function interpret(){
    var p = points; if(p.length<10) return;
    function avg(a,f){var s=0;a.forEach(function(d){s+=f(d)});return s/a.length}
    var l5 = p.slice(-5), p5 = p.slice(-10,-5), a1 = avg(l5,function(d){return d.total}), a0 = avg(p5,function(d){return d.total});
    var chg = a0 ? (a1-a0)/a0*100 : 0, dir = chg>1 ? 'rose' : (chg<-1 ? 'fell' : 'held steady');
    var al5 = l5.reduce(function(s,d){return s+d.fail},0);
    $('#sparkText').innerHTML = 'Over the past 5 minutes event volume '+dir+' <span class="hi">'+Math.abs(chg).toFixed(1)+'%</span>, averaging '+nf0.format(a1)+' events/min, with '+al5+' alert'+(al5===1?'':'s')+' raised.';
    var vis = visible(), worst = 0, wi = -1;
    vis.forEach(function(d,i){ if(d.fail > worst){ worst = d.fail; wi = i; } });
    $('#annotText').textContent = wi>=0 ? hhmm(vis[wi].t)+' · '+worst+' alert'+(worst===1?'':'s')+' in one minute (window peak)' : 'No alerts in window';
    var tot = vis.reduce(function(s,d){return s+d.total},0);
    $('#trendSummary').textContent = 'Last 30 minutes: '+nf0.format(tot)+' events and '+vis.reduce(function(s,d){return s+d.fail},0)+' alerts.';
  }

  function apply(data){
    if(data && data.range_h && data.range_h !== RANGE) return;   // answer to an earlier range choice
    if(data && data.sources && !sameSrc(data.sources)) return;    // answer to an earlier source choice
    D = data;
    $('#demoTag').hidden = !data.demo;
    var err = data.error, hasData = !!data.minutes;
    var aiOff = !!(data.ai && data.ai.configured===false);
    $('#tabAi').hidden = aiOff; if(aiOff && sideTab==='ai') setSideTab('rules');
    var dot = $('#liveDot');
    if(!liveOn){ dot.className = 'live-dot paused'; }
    else if(err){ dot.className = 'live-dot err'; }
    else dot.className = 'live-dot';
    if(!liveOn) pausedStatus();                     // paused: re-render the frozen data (resize, screen switch), never new data
    else $('#statusText').textContent = err ? (hasData ? 'Stale · '+err.slice(0,60) : 'Error · '+err.slice(0,60)) : 'Running · LIVE';
    if(!hasData) return;
    points = data.minutes.map(function(m){return {t:new Date(m.t), total:m.events, fail:m.alerts}});
    var now = new Date(data.now);
    $('#lastUpdate').textContent = hhmmss(now); $('#trendUpdated').textContent = 'Updated '+hhmmss(now);
    $('#lagText').textContent = data.took_ms!=null ? (data.took_ms/1000).toFixed(1)+' s' : '–';
    renderKpis(); interpret(); renderTrend(); renderSpark(); renderDonut(); renderLegend(); renderRules(); renderRes(); renderAlerts();
    if(sideTab==='ai') renderAI();
    if(drawer.classList.contains('on')) renderDetail();
  }

  /* ---------- polling ---------- */
  /* Pause freezes the display only: the feeds keep polling in the background and the newest answers are held
     (pendingD / pendingG), then shown at once on resume. */
  var pendingD = null, pendingG = null, heldUpdates = 0, pauseT = 0;
  function frameT(){ return liveOn ? performance.now() : pauseT; }   // a frozen map redraws at the moment it was paused
  function pausedStatus(){
    $('#statusText').textContent = 'Paused · display frozen · ' + (heldUpdates ? heldUpdates+' update'+(heldUpdates===1?'':'s')+' collected in the background' : 'still collecting in the background');
  }
  function poll(){
    fetch('/api/data?range='+RANGE+srcQuery(), {cache:'no-store'}).then(signedIn).then(function(r){ if(!r.ok) throw new Error('HTTP '+r.status); return r.json(); })
      .then(function(d){
        if(liveOn) return apply(d);
        if((!d.range_h || d.range_h === RANGE) && (!d.sources || sameSrc(d.sources))){ pendingD = d; heldUpdates++; pausedStatus(); }
      }).catch(function(e){ if(liveOn) apply(Object.assign({}, D||{}, {error:'server unreachable ('+e.message+')'})); });
  }
  setInterval(poll, 3000);

  function setRange(h){
    RANGE = h;
    try { localStorage.setItem('obsRange', String(h)); } catch(e){}
    $$('#rangeSeg button').forEach(function(b){ b.setAttribute('aria-pressed', String(+b.dataset.r===h)); });
    $('#kEvLbl').textContent = 'EVENTS ('+h+' H)'; $('#kAlLbl').textContent = 'ALERTS ('+h+' H)';
    $('#donutMeta').textContent = 'Share · '+rl();
    if(sideTab==='rules') $('#sideMeta').textContent = 'By alert count · '+rl();
    poll(); if(typeof pollPorts === 'function') pollPorts();
  }
  $$('#rangeSeg button').forEach(function(b){ b.addEventListener('click', function(){ setRange(+b.dataset.r); }); });
  setRange(RANGE);

  /* ---------- live firewall map ---------- */
  var mapCv = $('#mapCanvas'), mapTip = $('#mapTip'), mapWrap = $('#mapWrap');
  var LAND = null, G = null, mapWin = 60, mapAnon = false, mapHits = [], landCache = null, seenTicks = {};
  var mapType = 'all', mapDir = 'all', mapOut = 'all', mapNet = 'all', mapPort = null;
  // types whose logs carry origin/target geolocation (keep in step with GEO_TYPES in server.py); the rest get a note
  var GEO_TYPES = {'all': true, 'firewall-sophos-xg': true, 'o365': true, 'google': true, 'linux': true, 'syslog': true, 'wineventlog': true};
  var NET_LABEL = {vpn: 'VPN', tor: 'Tor', hosting: 'Hosting'};
  function netBadge(n){ return n ? ' <span class="netb netb-'+n+'" title="'+(n==='hosting' ? 'Datacenter / hosting range (often a VPN or VPS)' : n==='tor' ? 'Tor exit node' : 'Known VPN range')+'">'+NET_LABEL[n]+'</span>' : ''; }
  var MAP_TYPE_LABEL = {'all': 'all sources', 'firewall-sophos-xg': 'firewall', 'o365': 'Microsoft 365', 'google': 'Google',
                        'wineventlog': 'Windows', 'linux': 'Linux', 'syslog': 'syslog'};
  var reduceMotion = !!(window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches);
  var C_OUT = '#35E7FF', C_IN = '#68F5B1', C_DENY = '#FF4D5E', C_VPN = '#FFD23F', C_TOR = '#B97CFF', C_PIN = '#EAF7FF';
  var HOVER_ZOOM = 3.2;
  var hoverPin = null;                             // {lat, lon, label} while a row with coordinates is hovered
  var camX = 0, camY = 0, camZ = 1;                 // eased camera focus (base-projection pixels) and zoom
  var userZ = 1, userX = null, userY = null, viewW = 0, viewH = 0, snapCam = false, MAX_ZOOM = 8;   // user's own zoom/pan
  var BASE = null, pinPrevView = null;
  var MAP_DPR = Math.min(window.devicePixelRatio || 1, 1.25);   // street map + arc layer resolution: lighter on GPUs   // MapLibre street map, once it has loaded
  fetch('/land.json', {cache:'force-cache'}).then(function(r){ return r.json(); })
    .then(function(d){ LAND = d.rings; landCache = null; drawMap(frameT()); }).catch(function(){});

  function view(w, h){
    // Equirectangular, lat 78°N..56°S. In a tall slot the map zooms to fill the height, but always keeps at least
    // 230° of longitude in view, centred on the Atlantic, so North America, Europe and Africa stay on screen.
    var latN = 78, latSpan = 134, minLon = 230, lonC = -25;
    var s = Math.min(Math.max(w/360, h/latSpan), w/minLon);
    var c = w/s >= 360 ? 0 : lonC;
    var ox = w/2 - (c+180)*s, oy = (h - latSpan*s)/2;
    return function(lon, lat){ return [ox + (lon+180)*s, oy + (latN-lat)*s]; };
  }
  function drawLand(ctx, P, z){
    ctx.strokeStyle = 'rgba(53,231,255,.06)'; ctx.lineWidth = 1/z;        // graticule
    for(var lo=-180; lo<=180; lo+=30){ var a=P(lo,78), b=P(lo,-56); ctx.beginPath(); ctx.moveTo(a[0],a[1]); ctx.lineTo(b[0],b[1]); ctx.stroke(); }
    for(var la=-30; la<=60; la+=30){ var c=P(-180,la), e=P(180,la); ctx.beginPath(); ctx.moveTo(c[0],c[1]); ctx.lineTo(e[0],e[1]); ctx.stroke(); }
    if(LAND){
      ctx.fillStyle = '#0F2131'; ctx.strokeStyle = '#1E3A50'; ctx.lineWidth = .8/z;
      LAND.forEach(function(r){
        ctx.beginPath();
        for(var i=0;i<r.length;i+=2){ var p = P(r[i], r[i+1]); if(i) ctx.lineTo(p[0],p[1]); else ctx.moveTo(p[0],p[1]); }
        ctx.closePath(); ctx.fill(); ctx.stroke();
      });
    }
  }
  function landLayer(w, h, d){
    if(landCache && landCache.w===w && landCache.h===h) return landCache.cv;
    var cv = document.createElement('canvas'); cv.width = Math.round(w*d); cv.height = Math.round(h*d);
    var ctx = cv.getContext('2d'); ctx.setTransform(d,0,0,d,0,0);
    drawLand(ctx, view(w, h), 1);
    landCache = {w:w, h:h, cv:cv};
    return cv;
  }
  function anonColor(x){                             // mostly from Tor exits or known VPN ranges: whichever is larger
    var v = x.vpn||0, t = x.tor||0;
    return (v + t) > 0 && (v + t)*2 >= x.count ? (t > v ? C_TOR : C_VPN) : null;
  }
  function arcColor(a){ return anonColor(a) || (a.denied*2 >= a.count ? C_DENY : (a.dir==='in' ? C_IN : C_OUT)); }
  function dirArcs(){
    if(!G) return [];
    var out = [];
    G.arcs.forEach(function(a){
      if(mapDir!=='all' && a.dir!==mapDir) return;
      if(mapNet!=='all'){                             // keep only the VPN / Tor / hosting part of this route
        var m = a[mapNet]||0; if(!m) return;
        var b = Object.assign({}, a, {count:m, denied: Math.round(a.denied*m/a.count), vpn:0, tor:0, hosting:0});
        b[mapNet] = m; a = b;
      }
      if(mapOut==='all'){ out.push(a); return; }
      var n = mapOut==='denied' ? a.denied : a.count - a.denied;
      var k = a.count ? n/a.count : 0;                // VPN/hosting shares scale with the part kept
      if(n > 0) out.push(Object.assign({}, a, {count:n, denied: mapOut==='denied' ? n : 0,
                                                vpn: Math.round((a.vpn||0)*k), tor: Math.round((a.tor||0)*k), hosting: Math.round((a.hosting||0)*k)}));
    });
    return out;
  }
  function dirCountries(){
    if(!G) return [];
    if(mapDir==='all' && mapOut==='all' && mapNet==='all') return G.countries;
    var by = {};
    dirArcs().forEach(function(a){
      var c = by[a.cc] || (by[a.cc] = {cc:a.cc, country:a.country, count:0, denied:0, 'in':0, out:0});
      c.count += a.count; c.denied += a.denied; c[a.dir] += a.count;
    });
    return Object.keys(by).map(function(k){ return by[k]; }).sort(function(a,b){ return b.count-a.count; }).slice(0,12);
  }
  function bez(p0, p1, c, t){
    var u = 1-t; return [u*u*p0[0]+2*u*t*c[0]+t*t*p1[0], u*u*p0[1]+2*u*t*c[1]+t*t*p1[1]];
  }
  function ctrl(p0, p1){
    var mx=(p0[0]+p1[0])/2, my=(p0[1]+p1[1])/2, dx=p1[0]-p0[0], dy=p1[1]-p0[1], L=Math.sqrt(dx*dx+dy*dy)||1;
    var lift = Math.min(160, L*.28); return [mx + (dy/L)*lift*(dx>0?-1:1), my - Math.abs(dx/L)*lift - lift*.25];
  }
  function hexA(hex, a){ var n=parseInt(hex.slice(1),16); return 'rgba('+(n>>16)+','+((n>>8)&255)+','+(n&255)+','+a+')'; }

  function drawMap(now){
    if(!mapCv.offsetParent) return;                     // panel hidden (wall mode on another view)
    var f = fit(mapCv, BASE ? MAP_DPR : 2), ctx = f.ctx, w = f.w, h = f.h, d = Math.min(window.devicePixelRatio||1,2);
    ctx.clearRect(0,0,w,h);
    var P, tz, tx, ty;
    if(BASE){                                            // street basemap owns zoom/pan: project through it, no camera
      P = function(lon, lat){ var q = BASE.project([lon, lat]); return [q.x, q.y]; };
      camZ = 1; camX = tx = w/2; camY = ty = h/2; viewW = w; viewH = h;
      if(hoverPin && hoverPin.lat!=null && hoverPin.lon!=null){ var bp = P(hoverPin.lon, hoverPin.lat); tx = bp[0]; ty = bp[1]; }
    } else {
      P = view(w, h);
      if(userX==null || viewW!==w || viewH!==h){ userZ = 1; userX = w/2; userY = h/2; viewW = w; viewH = h; }
      tz = userZ; tx = userX; ty = userY;
      if(hoverPin && hoverPin.lat!=null && hoverPin.lon!=null){
        var fp = P(hoverPin.lon, hoverPin.lat); tz = Math.max(HOVER_ZOOM, userZ); tx = fp[0]; ty = fp[1];
      }
      if(liveOn && !snapCam){ camZ += (tz-camZ)*.15; camX += (tx-camX)*.15; camY += (ty-camY)*.15; }
      else { camZ = tz; camX = tx; camY = ty; snapCam = false; }
    }
    var toScr = function(p){ return [w/2 + camZ*(p[0]-camX), h/2 + camZ*(p[1]-camY)]; };
    ctx.save(); ctx.translate(w/2, h/2); ctx.scale(camZ, camZ); ctx.translate(-camX, -camY);
    if(!BASE){
      if(camZ > 1.05) drawLand(ctx, P, camZ);             // vector land stays sharp when zoomed in
      else ctx.drawImage(landLayer(w,h,d), 0, 0, w, h);
    }
    if(!G || !G.sites){ ctx.restore(); return; }
    var byId = {}, maxC = 1, t = (now||0)/1000, arcs = dirArcs();
    G.sites.forEach(function(s){ byId[s.id] = s; s._p = P(s.lon, s.lat); });
    arcs.forEach(function(a){ if(a.count>maxC) maxC = a.count; });
    if(!hoverPin) mapHits = [];                          // hit targets are kept in screen pixels (see toScr)
    var ends = {};
    arcs.forEach(function(a, i){
      var s = byId[a.site]; if(!s) return;
      var p0 = s._p, p1 = P(a.lon, a.lat), col = arcColor(a), wgt = Math.log(1+a.count)/Math.log(1+maxC);
      var key = a.lat+','+a.lon, e = ends[key] || (ends[key] = {p:p1, count:0, denied:0, vpn:0, tor:0, hosting:0, city:a.city, country:a.country, cc:a.cc, sites:{}});
      e.count += a.count; e.denied += a.denied; e.vpn += a.vpn||0; e.tor += a.tor||0; e.hosting += a.hosting||0; e.sites[s.name] = (e.sites[s.name]||0) + a.count;
      var dx = p1[0]-p0[0], dy = p1[1]-p0[1];
      if(dx*dx+dy*dy < 9) return;                        // same metro area: endpoint dot only
      var c = ctrl(p0, p1);
      ctx.beginPath(); ctx.moveTo(p0[0],p0[1]); ctx.quadraticCurveTo(c[0],c[1],p1[0],p1[1]);
      ctx.strokeStyle = hexA(col, .16 + .34*wgt); ctx.lineWidth = (.6 + 1.8*wgt)/camZ; ctx.stroke();
      if(!reduceMotion){                                 // comet travels in the direction the connection was made
        var speed = .18 + .5*wgt, ph = ((i*0.6180339) % 1), k = (t*speed + ph) % 1;
        var from = a.dir==='in' ? p1 : p0, to = a.dir==='in' ? p0 : p1;
        for(var j=0;j<5;j++){
          var kk = Math.max(0, k - j*.025), q = bez(from, to, c, kk);
          ctx.beginPath(); ctx.arc(q[0], q[1], (2.2+1.6*wgt)*(1-j*.18)/camZ, 0, Math.PI*2);
          ctx.fillStyle = hexA(col, (.9 - j*.18)); ctx.fill();
        }
      }
    });
    Object.keys(ends).forEach(function(k){                // remote endpoints
      var e = ends[k], col = anonColor(e) || (e.denied*2 >= e.count ? C_DENY : C_OUT), r = (1.6 + 3.2*Math.log(1+e.count)/Math.log(1+maxC))/camZ;
      if(e.denied && !reduceMotion){
        var pulse = ((t*.9 + (e.p[0]%7)/7) % 1 + 1) % 1;     // kept in 0..1 for western longitudes too
        ctx.beginPath(); ctx.arc(e.p[0], e.p[1], r + pulse*14/camZ, 0, Math.PI*2);
        ctx.strokeStyle = hexA(C_DENY, .55*(1-pulse)); ctx.lineWidth = 1.2/camZ; ctx.stroke();
      }
      ctx.beginPath(); ctx.arc(e.p[0], e.p[1], r, 0, Math.PI*2); ctx.fillStyle = hexA(col, .85); ctx.fill();
      if(!hoverPin){ var q = toScr(e.p); mapHits.push({x:q[0], y:q[1], r:Math.max(7, r*camZ+3), kind:'remote', e:e}); }
    });
    G.sites.forEach(function(s){                          // firewalls on top
      var p = s._p, busy = s.total ? Math.min(1, Math.log(1+s.total)/Math.log(1+3000)) : 0, r = (3.5 + 3*busy)/camZ;
      if(!reduceMotion && s.total){
        var pl = ((t*.6 + (p[1]%5)/5) % 1 + 1) % 1;          // % keeps the sign: a site south of the equator gave a negative radius
        ctx.beginPath(); ctx.arc(p[0], p[1], r + pl*18/camZ, 0, Math.PI*2); ctx.strokeStyle = 'rgba(234,247,255,'+(.4*(1-pl))+')'; ctx.lineWidth = 1/camZ; ctx.stroke();
      }
      ctx.beginPath(); ctx.arc(p[0], p[1], r+3/camZ, 0, Math.PI*2); ctx.fillStyle = 'rgba(53,231,255,.18)'; ctx.fill();
      ctx.beginPath(); ctx.arc(p[0], p[1], r, 0, Math.PI*2); ctx.fillStyle = s.total ? '#EAF7FF' : '#8299AB'; ctx.fill();
      if(!hoverPin){ var q2 = toScr(p); mapHits.push({x:q2[0], y:q2[1], r:Math.max(9, r*camZ+4), kind:'site', s:s}); }
    });
    ctx.restore();
    if(hoverPin){                                         // the focus point rides toward screen centre as the camera eases in
      var mx = w/2 + camZ*(tx-camX), my = h/2 + camZ*(ty-camY), pulse2 = ((now||0)/1000*1.1) % 1;
      ctx.beginPath(); ctx.arc(mx, my, 6+pulse2*18, 0, Math.PI*2); ctx.strokeStyle = hexA(C_PIN, .85*(1-pulse2)); ctx.lineWidth = 2; ctx.stroke();
      ctx.beginPath(); ctx.arc(mx, my, 5, 0, Math.PI*2); ctx.fillStyle = C_PIN; ctx.fill();
      positionPinTip(mx, my);
    }
  }
  var lastMapDraw = 0;
  function mapLoop(now){                                // ~30 fps idle animation; while the street map moves, its render event draws
    if(liveOn && !(BASE && BASE.isMoving()) && now - lastMapDraw >= 32){ lastMapDraw = now; drawMap(now); }
    if(!reduceMotion) requestAnimationFrame(mapLoop);
  }
  requestAnimationFrame(mapLoop);
  window.addEventListener('resize', function(){ landCache = null; drawMap(frameT()); });

  function flag(cc){ return /^[A-Z]{2}$/.test(cc||'') ? String.fromCodePoint(127397+cc.charCodeAt(0), 127397+cc.charCodeAt(1)) : '·'; }
  function renderMapSide(){
    var g = G, act = g.sites.filter(function(s){ return s.total; }).length, dr = g.total ? g.denied/g.total*100 : 0;
    var winLbl = g.window_s>=120 ? (g.window_s/60)+' min' : g.window_s+' s';
    $('#mapStats').innerHTML =
      '<div><div class="k">CONNS / MIN</div><div class="v">'+nf0.format(g.per_min)+'</div></div>'+
      '<div><div class="k">DENIED</div><div class="v" style="color:'+(dr>=30?'#FF8A95':'#EAF7FF')+'">'+dr.toFixed(1)+'<span class="unit">%</span></div></div>'+
      '<div><div class="k">'+(mapType==='firewall-sophos-xg' ? 'FIREWALLS' : 'SOURCES')+' ACTIVE</div><div class="v">'+act+'<span class="unit">/ '+g.sites.length+'</span></div></div>'+
      '<div><div class="k">DATA AGE</div><div class="v">'+(g.age_s==null?'–':ago(g.age_s))+'</div></div>';
    var countries = dirCountries();
    var maxC = countries.length ? countries[0].count : 1;
    $('#mapCountries').innerHTML = countries.length ? countries.slice(0,8).map(function(c){
      return '<div class="mc-row" title="'+esc(c.country)+': '+nf0.format(c.count)+' connections, '+nf0.format(c.denied)+' denied (in '+c['in']+' / out '+c.out+')">'+
        '<span>'+flag(c.cc)+'</span><span class="n">'+esc(c.country||c.cc)+'</span><span class="c">'+compact(c.count)+'</span>'+
        '<span class="dbar" title="denied share"><i style="width:'+(c.count? c.denied/c.count*100 : 0)+'%"></i></span></div>';
    }).join('') : '<div class="map-note">No geolocated traffic in the last '+winLbl+'.</div>';
    var fresh = {};
    $('#mapTickerTitle').textContent = mapType==='firewall-sophos-xg' ? 'Latest blocked inbound' : 'Latest blocked / failed inbound';
    var tk = mapNet==='all' ? g.ticker : g.ticker.filter(function(x){ return x.net===mapNet; });
    $('#mapTicker').innerHTML = tk.length ? tk.slice(0,10).map(function(x){
      var key = x.t+x.ip, isNew = !seenTicks[key]; fresh[key] = 1;
      var where = [x.city, x.country].filter(Boolean).join(', ') || x.cc || '';
      var geo = x.lat!=null && x.lon!=null ? ' data-lat="'+esc(x.lat)+'" data-lon="'+esc(x.lon)+'" data-ip="'+esc(x.ip||'')+'" data-sub="'+esc(where+' → '+x.site)+'" tabindex="0" role="button" aria-label="Look up '+esc(x.ip||'')+'"' : '';
      return '<div class="tk'+(isNew && Object.keys(seenTicks).length ? ' new' : '')+'"'+geo+'><span class="t">'+hhmmss(new Date(x.t))+'</span>'+
        '<span class="w"><span class="ip">'+esc(x.ip)+'</span>'+netBadge(x.net)+' '+flag(x.cc)+' '+esc(where)+' → '+esc(x.site)+(x.port?' :'+esc(x.port):'')+
        (mapType==='all' && x.type ? ' <span class="tk-type">'+esc(MAP_TYPE_LABEL[x.type]||x.type)+'</span>' : '')+'</span></div>';
    }).join('') : '<div class="map-note">No blocked inbound connections'+(mapNet!=='all' ? ' from '+NET_LABEL[mapNet]+' addresses' : '')+
                  (mapPort ? ' on port '+mapPort : '')+' in the last '+winLbl+'.</div>';
    seenTicks = fresh;
    var home = g.sites.filter(function(s){ return s.loc_source==='home'; });
    $('#mapNote').textContent = (g.anonymized ? 'Wall mode: firewall names hidden. ' : '') +
      (home.length && !g.anonymized ? home.length+' source'+(home.length>1?'s have':' has')+' no known location and '+(home.length>1?'are':'is')+' shown at '+(g.home.city||'home')+' ('+home.slice(0,6).map(function(s){return s.name;}).join(', ')+(home.length>6?', …':'')+'). Set it with install.sh --sites. ' : '') +
      (g.arcs_total > g.arcs.length ? 'Showing the busiest '+g.arcs.length+' of '+g.arcs_total+' routes. ' : '') +
      'Locations from UTMStack GeoIP and IP Geolocation by DB-IP (db-ip.com, CC BY 4.0); VPN/hosting ranges from X4BNet, Tor exits from the Tor Project. Private addresses are not mapped.' +
      (g.geoip && !g.geoip.db ? ' The location database is still downloading — attackers from Linux, Syslog and Windows appear once it is ready.' : '');
    $('#mapMeta').textContent = 'Last '+winLbl+(mapPort ? ' · port '+mapPort : '')+(SRC.length ? ' · '+SRC.length+' source'+(SRC.length===1?'':'s') : '')+
      ' · updated '+hhmmss(new Date(g.generated));
    $('#mapSummary').textContent = nf0.format(g.per_min)+' firewall connections per minute, '+dr.toFixed(1)+'% denied. Top country: '+(countries[0] ? countries[0].country : 'none')+'.';
  }
  function showMapFallback(show){
    $('#mapFallback').hidden = !show;
    if(show){
      var label = MAP_TYPE_LABEL[mapType] || mapType;
      $('#mapFallbackText').textContent = 'No geolocated traffic for '+label+' — only firewall and some cloud logs carry origin/destination locations.';
      $('#mapMeta').textContent = label+': no map data';
      $('#mapStats').innerHTML = ''; $('#mapCountries').innerHTML = ''; $('#mapTicker').innerHTML = '';
      $('#mapNote').textContent = 'See that source’s own events and rules instead.';
    }
  }
  function pollGeo(){
    if(!GEO_TYPES[mapType]){ showMapFallback(true); return; }
    showMapFallback(false);
    fetch('/api/geo?window='+mapWin+'&type='+encodeURIComponent(mapType)+(mapPort?'&port='+mapPort:'')+(mapAnon?'&anon=1':'')+srcQuery(), {cache:'no-store'}).then(function(r){ return r.json(); }).then(function(g){
      if(g.error){ $('#mapMeta').textContent = 'Map unavailable: '+g.error.slice(0,80); return; }
      if(!!g.anonymized !== mapAnon || g.window_s !== mapWin || g.type !== mapType || (g.port||null) !== mapPort ||
         (g.sources && !sameSrc(g.sources))) return;   // stale answer after a toggle
      if(!liveOn){ pendingG = g; return; }
      G = g; renderMapSide(); if(reduceMotion) drawMap(0);
    }).catch(function(e){ $('#mapMeta').textContent = 'Map unreachable ('+e.message+')'; });
  }
  setInterval(pollGeo, 10000); pollGeo();
  $$('#mapWin button').forEach(function(b){ b.addEventListener('click', function(){
    mapWin = +b.dataset.w; $$('#mapWin button').forEach(function(x){ x.setAttribute('aria-pressed', String(x===b)); }); pollGeo();
  }); });
  $$('#mapTypeSeg button').forEach(function(b){ b.addEventListener('click', function(){
    mapType = b.dataset.type; $$('#mapTypeSeg button').forEach(function(x){ x.setAttribute('aria-pressed', String(x===b)); });
    G = null; seenTicks = {}; drawMap(frameT());       // drop the previous type's arcs right away, don't wait for the answer
    $('#mapMeta').textContent = 'Loading '+(MAP_TYPE_LABEL[mapType]||mapType)+'…';
    pollGeo();
  }); });
  $$('#mapDirSeg button').forEach(function(b){ b.addEventListener('click', function(){
    mapDir = b.dataset.dir; $$('#mapDirSeg button').forEach(function(x){ x.setAttribute('aria-pressed', String(x===b)); });
    if(G){ renderMapSide(); drawMap(frameT()); }
  }); });
  $$('#mapOutSeg button').forEach(function(b){ b.addEventListener('click', function(){
    mapOut = b.dataset.out; $$('#mapOutSeg button').forEach(function(x){ x.setAttribute('aria-pressed', String(x===b)); });
    if(G){ renderMapSide(); drawMap(frameT()); }
  }); });
  $$('#mapNetSeg button').forEach(function(b){ b.addEventListener('click', function(){
    mapNet = b.dataset.net; $$('#mapNetSeg button').forEach(function(x){ x.setAttribute('aria-pressed', String(x===b)); });
    if(G){ renderMapSide(); drawMap(frameT()); }
  }); });
  /* ---------- firewall ports: busiest blocked and allowed ports for the time range and source filter ---------- */
  var PORTS = null;
  function portRows(rows, kind){
    if(!rows.length) return '<div class="empty">No '+(kind==='denied' ? 'blocked' : 'allowed')+' firewall connections in the last '+rl()+(SRC.length ? ' for the selected sources' : '')+'.</div>';
    var max = rows[0].count || 1;
    return rows.map(function(r){
      var label = r.port+(r.proto ? '/'+r.proto.toLowerCase() : '')+(r.service ? ' · '+r.service : '');
      var call = kind==='denied' ? nf0.format(r.remote_ips)+' address'+(r.remote_ips===1?'':'es') : r.inbound ? nf0.format(r.inbound)+' from internet' : 'outbound / internal';
      var hot = kind==='allowed' && r.risky && r.inbound > 0;
      var color = kind==='denied' ? C_DENY : (hot ? C_DENY : C_IN);
      var tip = label+': '+nf0.format(r.count)+(kind==='denied' ? ' blocked attempts' : ' allowed connections')+', '+nf0.format(r.inbound)+
        ' started from the internet by '+nf0.format(r.remote_ips)+' address'+(r.remote_ips===1?'':'es')+(hot ? '. Risky service reachable from the internet.' : '')+' Click to show this port on the map.';
      return '<div class="bar-row clk" tabindex="0" role="button" data-port="'+r.port+'" title="'+esc(tip)+'"><div><div class="bar-name"><span>'+esc(label)+'</span><span class="call">'+esc(call)+'</span></div>'+
        '<div class="track"><div class="fill" style="width:'+Math.max(6, r.count/max*100)+'%;background:'+color+'"></div></div></div>'+
        '<div><div class="bar-val" style="color:'+color+'">'+compact(r.count)+'</div><div class="bar-state'+(hot?' hot':'')+'">'+(hot ? 'EXPOSED' : kind==='denied' ? 'BLOCKED' : 'ALLOWED')+'</div></div></div>';
    }).join('');
  }
  function renderPorts(){
    if(!PORTS) return;
    var p = PORTS;
    $('#portsDeniedTot').textContent = compact(p.denied_total - p.denied_replies);
    $('#portsAllowedTot').textContent = compact(p.allowed_total);
    $('#portsDenied').innerHTML = portRows(p.denied, 'denied');
    $('#portsAllowed').innerHTML = portRows(p.allowed, 'allowed');
    $('#portsMeta').textContent = 'Last '+p.hours+' h'+(SRC.length ? ' · '+SRC.length+' source'+(SRC.length===1?'':'s') : '')+' · updated '+hhmmss(new Date(p.generated));
    $('#portsNote').textContent = (p.denied_replies ? nf0.format(p.denied_replies)+' denied late replies to our own connections are not counted as attempts. ' : '')+
      'Sophos firewall logs only. Click a port to show it on the map.';
  }
  function pollPorts(){
    fetch('/api/ports?range='+RANGE+srcQuery(), {cache:'no-store'}).then(signedIn).then(function(r){ return r.json(); }).then(function(p){
      if(p.error){ $('#portsMeta').textContent = 'Unavailable: '+p.error.slice(0,80); return; }
      if(p.hours !== RANGE || !sameSrc(p.sources)) return;              // answer to an earlier choice
      PORTS = p; if(liveOn) renderPorts();
    }).catch(function(e){ $('#portsMeta').textContent = 'Unreachable ('+e.message+')'; });
  }
  setInterval(pollPorts, 30000); pollPorts();
  function portClick(e){
    var row = e.target.closest && e.target.closest('[data-port]'); if(!row) return;
    if(e.type==='keydown' && e.key!=='Enter' && e.key!==' ') return;
    e.preventDefault(); setMapPort(+row.getAttribute('data-port'));
  }
  ['#portsDenied', '#portsAllowed'].forEach(function(id){ $(id).addEventListener('click', portClick); $(id).addEventListener('keydown', portClick); });

  function setMapPort(v){
    mapPort = v >= 1 && v <= 65535 ? v : null;
    $('#mapPort').value = mapPort || ''; $('#mapPortForm').classList.toggle('on', !!mapPort);
    G = null; seenTicks = {}; drawMap(frameT());
    $('#mapMeta').textContent = mapPort ? 'Loading port '+mapPort+'…' : 'Loading…';
    pollGeo();
  }
  $('#mapPortForm').addEventListener('submit', function(e){ e.preventDefault(); setMapPort(parseInt($('#mapPort').value, 10)); });
  $('#mapPortClear').addEventListener('click', function(){ setMapPort(null); });
  $('#mapFallbackBtn').addEventListener('click', function(){ openDig({name:'sources', tab:'source', type:mapType}, true); });
  function tipAt(x, y, r){
    var best = null, bd = 1e9;
    mapHits.forEach(function(hh){ var dx=hh.x-x, dy=hh.y-y, dd=dx*dx+dy*dy; if(dd < hh.r*hh.r && dd < bd){ bd = dd; best = hh; } });
    if(!best){ mapTip.classList.remove('on'); return; }
    var html;
    if(best.kind==='site'){
      var s = best.s;
      html = '<b style="color:#EAF7FF">'+esc(s.name)+'</b><br>'+esc(s.city||'')+(s.loc_source==='home'?' (location not known)':'')+'<br>'+nf0.format(s.total)+' connections · '+nf0.format(s.denied)+' denied';
    } else {
      var e = best.e, top = Object.keys(e.sites).sort(function(a,b){ return e.sites[b]-e.sites[a]; }).slice(0,3);
      html = '<b style="color:#EAF7FF">'+flag(e.cc)+' '+esc([e.city, e.country].filter(Boolean).join(', '))+'</b><br>'+nf0.format(e.count)+' connections · '+
        '<span style="color:'+(e.denied?'#FF8A95':'inherit')+'">'+nf0.format(e.denied)+' blocked</span>'+
        (e.vpn ? '<br><span style="color:'+C_VPN+'">'+nf0.format(e.vpn)+' from known VPN addresses</span>' : '')+
        (e.tor ? '<br><span style="color:'+C_TOR+'">'+nf0.format(e.tor)+' from Tor exit nodes</span>' : '')+
        (e.hosting ? '<br><span style="color:#8FB8D0">'+nf0.format(e.hosting)+' from hosting / datacenter addresses</span>' : '')+'<br>via '+top.map(esc).join(', ');
    }
    mapTip.innerHTML = html; mapTip.classList.add('on');
    var tw = mapTip.offsetWidth, th = mapTip.offsetHeight;
    mapTip.style.left = Math.max(6, Math.min(r.width-tw-6, x+14))+'px'; mapTip.style.top = Math.max(6, Math.min(r.height-th-6, y-th-8))+'px';
  }
  mapCv.addEventListener('mousemove', function(ev){
    if(hoverPin || drag) return;                       // a hovered row owns the tooltip and the camera; no tips mid-drag
    var r = mapCv.getBoundingClientRect();
    tipAt(ev.clientX-r.left, ev.clientY-r.top, r);
  });
  mapCv.addEventListener('mouseleave', function(){ if(!hoverPin) mapTip.classList.remove('on'); });

  /* ---- zoom and pan: buttons, wheel, double-click, drag, pinch; a tap shows the tooltip on touch screens ---- */
  function redrawMap(){ mapCv.style.touchAction = userZ > 1 ? 'none' : 'pan-y'; mapCv.classList.toggle('zoomed', userZ > 1);
                        if(!liveOn || reduceMotion) drawMap(frameT()); }
  function clampView(){
    var hw = viewW/(2*userZ), hh = viewH/(2*userZ);
    userX = Math.max(hw, Math.min(viewW-hw, userX)); userY = Math.max(hh, Math.min(viewH-hh, userY));
  }
  function zoomAt(f, sx, sy, snap){                   // keep the map point under (sx, sy) fixed while zooming
    if(userX==null || !viewW) return;
    var nz = Math.max(1, Math.min(MAX_ZOOM, userZ*f));
    var bx = userX + (sx - viewW/2)/userZ, by = userY + (sy - viewH/2)/userZ;
    userZ = nz; userX = bx - (sx - viewW/2)/nz; userY = by - (sy - viewH/2)/nz;
    clampView(); if(snap) snapCam = true; redrawMap();
  }
  $('#mapZoomIn').addEventListener('click', function(){ if(BASE) BASE.zoomIn(); else zoomAt(1.6, viewW/2, viewH/2); });
  $('#mapZoomOut').addEventListener('click', function(){ if(BASE) BASE.zoomOut(); else zoomAt(1/1.6, viewW/2, viewH/2); });
  $('#mapZoomReset').addEventListener('click', function(){
    if(BASE){ BASE.easeTo(coverView(BASE.getContainer())); return; }
    userZ = 1; userX = viewW/2; userY = viewH/2; redrawMap();
  });
  mapCv.addEventListener('wheel', function(e){
    e.preventDefault();
    var r = mapCv.getBoundingClientRect();
    zoomAt(Math.exp(-e.deltaY * (e.deltaMode ? 0.05 : 0.0015)), e.clientX-r.left, e.clientY-r.top, true);
  }, {passive:false});
  mapCv.addEventListener('dblclick', function(e){ var r = mapCv.getBoundingClientRect(); zoomAt(2, e.clientX-r.left, e.clientY-r.top); });
  var ptrs = {}, drag = null;
  function ptrList(){ return Object.keys(ptrs).map(function(k){ return ptrs[k]; }); }
  mapCv.addEventListener('pointerdown', function(e){
    if(e.pointerType==='mouse' && e.button!==0) return;
    try { mapCv.setPointerCapture(e.pointerId); } catch(_) {}
    ptrs[e.pointerId] = {x:e.clientX, y:e.clientY};
    var l = ptrList();
    drag = {moved:false, sx:e.clientX, sy:e.clientY, dist: l.length===2 ? Math.hypot(l[0].x-l[1].x, l[0].y-l[1].y) : 0};
  });
  mapCv.addEventListener('pointermove', function(e){
    var p = ptrs[e.pointerId]; if(!p || !drag) return;
    var dx = e.clientX-p.x, dy = e.clientY-p.y; p.x = e.clientX; p.y = e.clientY;
    if(Math.abs(e.clientX-drag.sx) + Math.abs(e.clientY-drag.sy) > 6) drag.moved = true;
    var l = ptrList(), r = mapCv.getBoundingClientRect();
    if(l.length===2){                                  // pinch: zoom around the midpoint
      var dist = Math.hypot(l[0].x-l[1].x, l[0].y-l[1].y);
      if(drag.dist) zoomAt(dist/drag.dist, (l[0].x+l[1].x)/2-r.left, (l[0].y+l[1].y)/2-r.top, true);
      drag.dist = dist; drag.moved = true;
    } else if(l.length===1 && userZ > 1 && drag.moved){
      userX -= dx/userZ; userY -= dy/userZ; clampView(); snapCam = true; mapTip.classList.remove('on'); redrawMap();
    }
  });
  function ptrEnd(e){
    if(!ptrs[e.pointerId]) return;
    delete ptrs[e.pointerId];
    if(drag && !drag.moved && e.type==='pointerup' && e.pointerType!=='mouse' && !hoverPin){
      var r = mapCv.getBoundingClientRect(); tipAt(e.clientX-r.left, e.clientY-r.top, r);
    }
    if(!ptrList().length) drag = null;
    else drag.dist = 0;                                // one finger lifted from a pinch: restart the distance
  }
  mapCv.addEventListener('pointerup', ptrEnd);
  mapCv.addEventListener('pointercancel', ptrEnd);
  redrawMap();

  /* ---- street basemap (MapLibre + OpenFreeMap tiles); the outline map above stays as the fallback ---- */
  function coverView(el){
    // Smallest zoom at which the world (512 px square at zoom 0) covers the whole panel, so a tall or square
    // panel never shows empty bands; centred on the Atlantic like the outline map.
    var size = Math.max(el.clientWidth || 1, el.clientHeight || 1);
    return {center: [-20, 28], zoom: Math.max(0, Math.log2(size / 512))};
  }
  // Credit as fixed text of our own: the tile provider's attribution strings are third-party HTML, and MapLibre
  // 4.x's AttributionControl renders them with innerHTML (GHSA-jrc7-96c5-q579), so that control is not used.
  var MAP_CREDIT = 'OpenFreeMap · © OpenMapTiles · © OpenStreetMap contributors';
  var PENDING = null;                                  // the street map between creation and its 'load' event
  function syncBaseSize(m){
    // MapLibre measures its container once when created; if that happened before the layout settled (some browsers),
    // it keeps a tiny canvas and the arcs, projected through it, crowd into one corner. Re-measure when they differ.
    var el = $('#mapBase'), c = m.getCanvas();
    if(Math.abs(c.clientWidth - el.clientWidth) > 2 || Math.abs(c.clientHeight - el.clientHeight) > 2){
      m.resize(); m.setMinZoom(coverView(el).zoom); landCache = null; drawMap(frameT());
    }
  }
  function initBase(){
    // the map library is an ES module and loads after this script: wait for it (no module support: outline map stays)
    if(!window.maplibregl){ window.addEventListener('maplibre-ready', initBase, {once: true}); return; }
    var t0 = Date.now();
    fetch('https://tiles.openfreemap.org/styles/dark', {credentials: 'omit', referrerPolicy: 'no-referrer'})
      .then(function(r){ if(!r.ok) throw new Error('HTTP '+r.status); return r.json(); })
      .then(function(style){
        Object.keys(style.sources || {}).forEach(function(k){ delete style.sources[k].attribution; });
        buildBase(style, Math.max(1000, 12000 - (Date.now() - t0)));
      })
      .catch(function(){});                            // style unreachable: keep the outline map
  }
  function buildBase(style, budget){
    var ready = false, m;
    try {
      var start = coverView($('#mapBase'));
      m = new maplibregl.Map({container: 'mapBase', style: style,
        center: start.center, zoom: start.zoom, minZoom: start.zoom,
        pixelRatio: MAP_DPR, fadeDuration: 0, renderWorldCopies: false, attributionControl: false, maxZoom: 18,
        dragRotate: false, pitchWithRotate: false, touchPitch: false,
        cooperativeGestures: !!(window.matchMedia && matchMedia('(pointer: coarse)').matches)});   // phones: 2 fingers move the map
    } catch(e){ return; }                              // no WebGL
    PENDING = m;
    m.touchZoomRotate.disableRotation();
    // the tile style names two icons it does not ship: hand MapLibre a blank one instead of a console warning
    var blank = function(id){ if(!m.hasImage(id)) m.addImage(id, {width: 1, height: 1, data: new Uint8Array(4)}); };
    if(m.setMissingStyleImageResolver) m.setMissingStyleImageResolver(blank);
    else m.on('styleimagemissing', function(e){ blank(e.id); });
    var credit = document.createElement('a');
    credit.className = 'map-credit'; credit.textContent = MAP_CREDIT;
    credit.href = 'https://www.openstreetmap.org/copyright'; credit.target = '_blank'; credit.rel = 'noopener noreferrer';
    m.on('load', function(){
      ready = true; BASE = m; PENDING = null; mapWrap.classList.add('has-base'); $('#mapBase').__map = m;   // handle for scripted demos/captures
      m.resize(); m.setMinZoom(coverView(m.getContainer()).zoom);
      mapTip.classList.remove('on'); drawMap(frameT());
      mapWrap.appendChild(credit);
    });
    m.on('render', function(){ if(BASE && (m.isMoving() || !liveOn || reduceMotion)) drawMap(frameT()); });   // same frame as the map
    var tip = function(e){ if(BASE && !hoverPin) tipAt(e.point.x, e.point.y, mapCv.getBoundingClientRect()); };
    m.on('mousemove', tip); m.on('click', tip);
    m.on('mouseout', function(){ if(!hoverPin) mapTip.classList.remove('on'); });
    m.on('dragstart', function(){ mapTip.classList.remove('on'); });
    setTimeout(function(){ if(!ready){ try { m.remove(); } catch(_) {} } }, budget);   // tiles unreachable: keep the outline map
  }
  if(window.ResizeObserver) new ResizeObserver(function(){
    var m = BASE || PENDING;
    if(m){ m.resize(); m.setMinZoom(coverView(m.getContainer()).zoom); }   // still covers after a resize
    landCache = null; drawMap(frameT());
  }).observe(mapWrap);
  initBase();
  setInterval(function(){ if(BASE && !document.hidden) syncBaseSize(BASE); }, 1000);   // safety net, see syncBaseSize

  /* ---- hover a Latest-Alerts or Latest-blocked-inbound row: zoom the map to its location ---- */
  function positionPinTip(mx, my){
    var r = mapCv.getBoundingClientRect(), tw = mapTip.offsetWidth, th = mapTip.offsetHeight;
    mapTip.style.left = Math.max(6, Math.min(r.width-tw-6, mx+14))+'px';
    mapTip.style.top = Math.max(6, Math.min(r.height-th-6, my-th-8))+'px';
  }
  function pinOn(lat, lon, label){
    if(isNaN(lat) || isNaN(lon)) return;
    hoverPin = {lat:lat, lon:lon};
    mapTip.innerHTML = label; mapTip.classList.add('on');
    if(BASE){
      if(!pinPrevView) pinPrevView = {center: BASE.getCenter(), zoom: BASE.getZoom()};
      BASE.easeTo({center: [lon, lat], zoom: Math.max(BASE.getZoom(), 5), duration: reduceMotion ? 0 : 700});
    }
    if(!liveOn || reduceMotion) drawMap(frameT());       // snap at once when nothing else is driving redraws
  }
  function pinOff(){
    if(!hoverPin) return;
    hoverPin = null; mapTip.classList.remove('on');
    if(BASE && pinPrevView){ BASE.easeTo({center: pinPrevView.center, zoom: pinPrevView.zoom, duration: reduceMotion ? 0 : 700}); pinPrevView = null; }
    if(!liveOn || reduceMotion) drawMap(frameT());
  }
  function rowPin(el){
    var label = '<b style="color:#EAF7FF">'+esc(el.dataset.ip||el.dataset.sub||'')+'</b>'+(el.dataset.sub?'<br>'+esc(el.dataset.sub):'');
    pinOn(parseFloat(el.dataset.lat), parseFloat(el.dataset.lon), label);
  }
  $('#alertBody').addEventListener('mouseover', function(e){ var tr = e.target.closest('tr[data-lat]'); if(tr) rowPin(tr); });
  $('#alertBody').addEventListener('mouseout', function(e){ var tr = e.target.closest('tr[data-lat]'); if(tr && !tr.contains(e.relatedTarget)) pinOff(); });
  $('#mapTicker').addEventListener('mouseover', function(e){ var tk = e.target.closest('.tk[data-lat]'); if(tk) rowPin(tk); });
  $('#mapTicker').addEventListener('mouseout', function(e){ var tk = e.target.closest('.tk[data-lat]'); if(tk && !tk.contains(e.relatedTarget)) pinOff(); });
  $('#mapTicker').addEventListener('click', function(e){
    var tk = e.target.closest('.tk[data-lat]'); if(tk) openDig({name:'ip', ip:tk.dataset.ip, sub:tk.dataset.sub}, true);
  });
  $('#mapTicker').addEventListener('keydown', function(e){
    if((e.key==='Enter'||e.key===' ') && e.target.matches('.tk[data-lat]')){ e.preventDefault(); e.target.click(); }
  });

  /* ---------- wall display mode ---------- */
  var wallOn = false, wallTimer = null, wallIdx = 0, preWallScreen = null;
  function wallScreens(){
    var ids = (BOARD.shared ? BOARD.shared.screens : []).filter(function(s){ return s.wall; }).map(function(s){ return s.id; });
    return ids.length ? ids : (BOARD.shared ? [BOARD.shared.screens[0].id] : []);
  }
  function wallStep(){
    if(!liveOn) return;
    var ids = wallScreens(); if(!ids.length) return;
    wallIdx = wallIdx % ids.length; showScreen(ids[wallIdx]); wallIdx++;
  }
  function setWall(on){
    wallOn = on; mapAnon = on;
    document.body.classList.toggle('wall', on);
    renderSrcState();
    $('#wallBtn').setAttribute('aria-pressed', String(on));
    clearInterval(wallTimer);
    if(on){ preWallScreen = BOARD.screenId; wallIdx = 0; wallStep(); wallTimer = setInterval(wallStep, 30000); }
    else if(BOARD.shared){ showScreen(preWallScreen || activeLayout().screens[0].id); }
    try { var u = new URL(location.href); if(on) u.searchParams.set('wall','1'); else u.searchParams.delete('wall'); history.replaceState(null,'',u); } catch(e){}
    G = null; pollGeo();
  }
  $('#wallBtn').addEventListener('click', function(){ setWall(!wallOn); if(wallOn && document.documentElement.requestFullscreen) document.documentElement.requestFullscreen().catch(function(){}); });
  document.addEventListener('keydown', function(e){ if(e.key==='Escape' && wallOn && !document.querySelector('.drawer.on')) setWall(false); });

  /* ---------- widget board: screens and placement ---------- */
  var L = window.ObsLayout, boardEl = $('#board');
  var BOARD = {shared: null, personal: null, layout: null, screenId: null, notes: []};
  try { BOARD.personal = JSON.parse(localStorage.getItem('obsPersonalLayout') || 'null'); } catch(e){}
  try { BOARD.screenId = localStorage.getItem('obsScreen'); } catch(e){}
  function widgetEl(type){ return boardEl.querySelector('[data-widget="'+type+'"]'); }
  function activeLayout(){ return (!wallOn && BOARD.personal) ? BOARD.personal.layout : BOARD.shared; }
  function currentScreen(){
    var lay = activeLayout(), s = lay.screens.filter(function(x){ return x.id === BOARD.screenId; })[0];
    return s || lay.screens[0];
  }
  function renderTabs(){
    var lay = activeLayout(), cur = currentScreen();
    $('#screenTabs').innerHTML = lay.screens.map(function(s){
      return '<button class="tab" role="tab" data-id="'+esc(s.id)+'" aria-selected="'+(s.id===cur.id)+'">'+esc(s.name)+
        (s.wall ? '<i class="wall-dot" title="Shown in wall mode"></i>' : '')+'</button>';
    }).join('');
    $$('#screenTabs .tab').forEach(function(b){ b.addEventListener('click', function(){ showScreen(b.dataset.id); }); });
    var wb = $('#wallScreenBtn'); if(wb) wb.setAttribute('aria-pressed', String(!!cur.wall));
  }
  function renderBoard(){
    var s = currentScreen(), on = {};
    s.widgets.forEach(function(w){
      var el = widgetEl(w.type); if(!el) return;
      on[w.type] = 1; el.hidden = false;
      if(wallOn && L.WIDGETS[w.type].wallSafe === false) el.setAttribute('data-wall-hidden',''); else el.removeAttribute('data-wall-hidden');
      el.style.gridColumn = (w.x+1)+' / span '+w.w; el.style.gridRow = (w.y+1)+' / span '+w.h;
      el.style.order = String(w.y*100 + w.x);          // reading order for the single-column (mobile) view
    });
    $$('#board > [data-widget]').forEach(function(el){ if(!on[el.dataset.widget]) el.hidden = true; });
    fitRows(s);
    renderTabs();
    setTimeout(function(){ landCache = null; if(D) apply(D); drawMap(frameT()); }, 30);   // canvases resize to the new cells
  }
  function fitRows(s){
    // Wall screens (Live map, Activity) are meant to be one screenful: stretch their rows to the window height.
    // Wall mode has its own CSS for this; edit mode keeps 40 px rows so dragging snaps predictably.
    var b = $('#board'), rows = s.widgets.reduce(function(m, w){ return Math.max(m, w.y + w.h); }, 0);
    if(!s.wall || wallOn || editing || window.innerWidth < 1100 || !rows){ b.style.gridAutoRows = ''; return; }
    var top = b.getBoundingClientRect().top + window.scrollY, avail = window.innerHeight - top - 20;
    b.style.gridAutoRows = Math.max(40, Math.floor((avail - (rows - 1) * 12) / rows)) + 'px';
  }
  function showScreen(id){
    BOARD.screenId = id; try { localStorage.setItem('obsScreen', id); } catch(e){}
    renderBoard();
  }
  function loadSharedLayout(){
    return fetch('/api/layout', {cache:'no-store'}).then(function(r){ return r.json(); }).then(function(j){
      var res = L.sanitizeLayout(j.layout);
      BOARD.shared = res.layout; BOARD.notes = (j.notes||[]).concat(res.notes);
      if(BOARD.personal){
        var p = L.sanitizeLayout(BOARD.personal && BOARD.personal.layout);
        if(p.empty){                                  // corrupt or empty personal layout: drop it, never leave the page stuck
          BOARD.personal = null; try { localStorage.removeItem('obsPersonalLayout'); } catch(e){}
          BOARD.notes.push('Your personal layout could not be used and was discarded; showing the shared layout.');
        } else { BOARD.personal.layout = p.layout; BOARD.notes = BOARD.notes.concat(p.notes); }
      }
      var n = $('#boardNotes'); n.hidden = !BOARD.notes.length; n.textContent = BOARD.notes.join(' ');
      renderLayoutState();                            // before the board, so Reset to shared exists even if rendering fails
      renderBoard();
      if(!loadSharedLayout.done){ loadSharedLayout.done = 1; if(/[?&]wall=1\b/.test(location.search)) setWall(true); }
    });
  }
  window.addEventListener('resize', function(){ if(BOARD.shared) renderBoard(); });
  /* ---------- edit mode ---------- */
  var editing = false;
  function savePersonal(){
    try { localStorage.setItem('obsPersonalLayout', JSON.stringify(BOARD.personal)); } catch(e){}
    if(typeof renderLayoutState === 'function') renderLayoutState();   // header indicator arrives in Task 6
  }
  function ensurePersonal(){
    if(!BOARD.personal) BOARD.personal = {baseVersion: BOARD.shared.version, layout: JSON.parse(JSON.stringify(BOARD.shared))};
    return BOARD.personal.layout;
  }
  function commitLayout(lay){ BOARD.personal = {baseVersion: (BOARD.personal||{}).baseVersion != null ? BOARD.personal.baseVersion : BOARD.shared.version, layout: lay}; savePersonal(); renderBoard(); }
  function commitScreenWidgets(widgets){
    var lay = ensurePersonal(), id = currentScreen().id;
    lay.screens.forEach(function(s){ if(s.id === id) s.widgets = widgets; });
    commitLayout(lay);
  }
  function setEdit(on){
    if(on && window.innerWidth < 1100) return;
    editing = on; document.body.classList.toggle('editing', on);
    $('#editBtn').setAttribute('aria-pressed', String(on)); $('#editBtn').textContent = on ? 'Done' : 'Edit';
    if(on) ensurePersonal();
    renderBoard();
  }
  $('#editBtn').addEventListener('click', function(){ setEdit(!editing); });

  // per-widget tools: drag handle, remove, resize corner (added once to every panel)
  $$('#board > [data-widget]').forEach(function(el){
    var tools = document.createElement('div'); tools.className = 'w-tools';
    tools.innerHTML = '<button class="w-drag" title="Drag to move (or focus and use arrow keys; Shift+arrows resize)" aria-label="Move '+esc(L.WIDGETS[el.dataset.widget].title)+'">⠿ Move</button>'+
                      '<button class="w-remove" aria-label="Remove '+esc(L.WIDGETS[el.dataset.widget].title)+'">✕</button>';
    var corner = document.createElement('div'); corner.className = 'w-resize'; corner.setAttribute('aria-hidden','true');
    el.appendChild(tools); el.appendChild(corner);
    tools.querySelector('.w-remove').addEventListener('click', function(){
      var ws = currentScreen().widgets, i = ws.map(function(w){ return w.type; }).indexOf(el.dataset.widget);
      if(i >= 0) commitScreenWidgets(L.removeWidget(ws, i));
    });
    tools.querySelector('.w-drag').addEventListener('pointerdown', function(e){ startPointer(e, el, 'move'); });
    corner.addEventListener('pointerdown', function(e){ startPointer(e, el, 'resize'); });
    tools.querySelector('.w-drag').addEventListener('keydown', function(e){
      var d = {ArrowLeft:[-1,0], ArrowRight:[1,0], ArrowUp:[0,-1], ArrowDown:[0,1]}[e.key]; if(!d) return;
      e.preventDefault();
      var ws = currentScreen().widgets, i = ws.map(function(w){ return w.type; }).indexOf(el.dataset.widget), w = ws[i];
      commitScreenWidgets(e.shiftKey ? L.resize(ws, i, w.w + d[0], w.h + d[1]) : L.move(ws, i, w.x + d[0], w.y + d[1]));
      setTimeout(function(){ widgetEl(w.type).querySelector('.w-drag').focus(); }, 40);
    });
  });

  function cellSize(){
    var r = boardEl.getBoundingClientRect(), gap = 12;
    return {left: r.left, top: r.top, colW: (r.width + gap) / 12, rowH: 40 + gap};
  }
  function startPointer(e, el, mode){
    if(!editing) return;
    e.preventDefault();
    var ws = currentScreen().widgets, i = ws.map(function(w){ return w.type; }).indexOf(el.dataset.widget);
    if(i < 0) return;
    var start = {x: e.clientX, y: e.clientY, w: ws[i]}, c = cellSize(), preview = ws;
    el.classList.add('ghost');
    function onMove(ev){
      var dx = Math.round((ev.clientX - start.x) / c.colW), dy = Math.round((ev.clientY - start.y) / c.rowH);
      preview = mode === 'move' ? L.move(ws, i, start.w.x + dx, start.w.y + dy) : L.resize(ws, i, start.w.w + dx, start.w.h + dy);
      preview.forEach(function(w){ var p = widgetEl(w.type); p.style.gridColumn = (w.x+1)+' / span '+w.w; p.style.gridRow = (w.y+1)+' / span '+w.h; });
    }
    function onUp(){
      window.removeEventListener('pointermove', onMove); window.removeEventListener('pointerup', onUp);
      el.classList.remove('ghost'); commitScreenWidgets(preview);
    }
    window.addEventListener('pointermove', onMove); window.addEventListener('pointerup', onUp);
  }

  // add-widget menu
  $('#addWidgetBtn').addEventListener('click', function(ev){
    var have = {}; currentScreen().widgets.forEach(function(w){ have[w.type] = 1; });
    var free = Object.keys(L.WIDGETS).filter(function(t){ return !have[t]; });
    var m = document.createElement('div'); m.className = 'add-menu'; m.setAttribute('role','menu');
    m.innerHTML = free.length ? free.map(function(t){ return '<button role="menuitem" data-t="'+t+'">'+esc(L.WIDGETS[t].title)+'<small>'+esc(L.WIDGETS[t].desc)+'</small></button>'; }).join('')
                              : '<div class="map-note" style="padding:8px">Every widget is already on this screen.</div>';
    var r = ev.currentTarget.getBoundingClientRect(); m.style.left = r.left+'px'; m.style.top = (r.bottom+window.scrollY+4)+'px';
    document.body.appendChild(m);
    function close(){ if(m.parentNode) m.parentNode.removeChild(m); document.removeEventListener('click', outside, true); }
    function outside(e){ if(!m.contains(e.target) && e.target !== ev.currentTarget) close(); }
    setTimeout(function(){ document.addEventListener('click', outside, true); }, 0);
    $$('button[data-t]', m).forEach(function(b){ b.addEventListener('click', function(){ commitScreenWidgets(L.addWidget(currentScreen().widgets, b.dataset.t)); close(); }); });
    var first = m.querySelector('button'); if(first) first.focus();
  });

  // screen management
  $('#addScreenBtn').addEventListener('click', function(){
    var name = prompt('Name for the new screen:', 'New screen'); if(name === null) return;
    try { var lay = L.addScreen(ensurePersonal(), name); commitLayout(lay); showScreen(lay.screens[lay.screens.length-1].id); } catch(e){ alert(e.message); }
  });
  $('#renameScreenBtn').addEventListener('click', function(){
    var s = currentScreen(), name = prompt('Rename screen:', s.name); if(name) commitLayout(L.renameScreen(ensurePersonal(), s.id, name));
  });
  $('#wallScreenBtn').addEventListener('click', function(){
    var lay = ensurePersonal(), id = currentScreen().id;
    lay.screens.forEach(function(s){ if(s.id === id) s.wall = !s.wall; }); commitLayout(lay);
  });
  $('#screenLeftBtn').addEventListener('click', function(){ commitLayout(L.moveScreen(ensurePersonal(), currentScreen().id, -1)); });
  $('#screenRightBtn').addEventListener('click', function(){ commitLayout(L.moveScreen(ensurePersonal(), currentScreen().id, 1)); });
  $('#deleteScreenBtn').addEventListener('click', function(){
    var s = currentScreen(); if(!confirm('Delete the screen "'+s.name+'"?')) return;
    try { commitLayout(L.removeScreen(ensurePersonal(), s.id)); showScreen(activeLayout().screens[0].id); } catch(e){ alert(e.message); }
  });
  window.addEventListener('resize', function(){ if(editing && window.innerWidth < 1100) setEdit(false); });

  /* ---------- personal vs shared layout ---------- */
  // savePersonal() is defined in the edit-mode block (Task 5) and calls renderLayoutState() below once it exists.
  function resetToShared(){
    BOARD.personal = null; try { localStorage.removeItem('obsPersonalLayout'); } catch(e){}
    renderLayoutState(); renderBoard();
  }
  function saveAsShared(){
    var lay = activeLayout();
    return fetch('/api/layout', {method: 'PUT', cache: 'no-store',
      headers: {'Content-Type': 'application/json', 'X-Observatory': '1'},
      body: JSON.stringify({layout: lay, base_version: BOARD.shared.version})})
    .then(function(r){ return r.json().then(function(j){ return {status: r.status, j: j}; }); })
    .then(function(res){
      if(res.status === 409){
        if(confirm('Someone saved a different shared layout since you started. Replace it with yours?')){
          BOARD.shared = L.sanitizeLayout(res.j.layout).layout;
          return saveAsShared();
        }
        return;
      }
      if(res.status !== 200) throw new Error(res.j.error || ('HTTP '+res.status));
      BOARD.shared = L.sanitizeLayout(res.j.layout).layout;
      resetToShared();
      toastLayout('Saved as the shared layout (version '+BOARD.shared.version+').');
    }).catch(function(e){ toastLayout('Could not save: '+e.message); });
  }
  function toastLayout(msg){ var n = $('#boardNotes'); n.hidden = false; n.textContent = msg; clearTimeout(toastLayout.t); toastLayout.t = setTimeout(function(){ n.hidden = !BOARD.notes.length; n.textContent = BOARD.notes.join(' '); }, 6000); }
  function renderLayoutState(){
    var el = $('#layoutState');
    if(!BOARD.personal){ el.innerHTML = 'Shared layout'; return; }
    var stale = BOARD.shared && L.isPersonalStale(BOARD.personal, BOARD.shared);
    el.innerHTML = 'Personal layout'+(stale ? ' · <span class="warn">shared layout changed since</span>' : '')+
      ' · <button class="txt-btn" id="resetShared">Reset to shared</button>'+
      ' <button class="txt-btn" id="saveShared">Save as shared default</button>';
    $('#resetShared').addEventListener('click', function(){ if(confirm('Discard your personal layout and use the shared one?')) resetToShared(); });
    $('#saveShared').addEventListener('click', function(){
      var q = stale ? 'The shared layout was changed after you started your personal one. Saving replaces that newer version for everyone, including the wall screen. Continue?'
                    : 'Make your layout the shared default for everyone, including the wall screen?';
      if(confirm(q)) saveAsShared();
    });
  }
  setInterval(function(){ if(!editing && liveOn) loadSharedLayout().catch(function(){}); }, 60000);

  loadSharedLayout().catch(function(e){ $('#boardNotes').hidden = false; $('#boardNotes').textContent = 'Layout could not be loaded ('+e.message+'); showing every widget.'; });

  /* ---------- tooltip ---------- */
  function pointFromEvent(ev){
    var r = trendCanvas.getBoundingClientRect(), x = (ev.touches ? ev.touches[0].clientX : ev.clientX) - r.left;
    var data = visible(), pw = r.width-52-44, i = Math.round(((x-52)/pw)*(data.length-1));
    return {i:clamp(i,0,data.length-1), data:data};
  }
  function tipHTML(d){
    return '<div class="tt-t">Time '+hhmm(d.t)+'</div>'+
      '<div class="row"><span>Events</span><span style="color:#35E7FF">'+nf0.format(d.total)+'</span></div>'+
      '<div class="row"><span>Events/s</span><span style="color:#EAF7FF">'+(d.total/60).toFixed(1)+'</span></div>'+
      '<div class="row"><span>Alerts</span><span style="color:#FF4D5E">'+d.fail+'</span></div>';
  }
  function showTip(ev){
    if(points.length<2) return;
    var res = pointFromEvent(ev); hoverIdx = res.i; tooltip.innerHTML = tipHTML(res.data[res.i]);
    var wrap = $('#chartWrap').getBoundingClientRect();
    var px = (ev.touches ? ev.touches[0].clientX : ev.clientX) - wrap.left, py = (ev.touches ? ev.touches[0].clientY : ev.clientY) - wrap.top;
    var tw = tooltip.offsetWidth || 160, th = tooltip.offsetHeight || 90;
    tooltip.style.left = clamp(px+16,8,wrap.width-tw-8)+'px'; tooltip.style.top = clamp(py-th-12,8,wrap.height-th-8)+'px';
    tooltip.classList.add('on'); renderTrend();
  }
  function hideTip(){ hoverIdx = null; tooltip.classList.remove('on'); renderTrend(); }
  trendCanvas.addEventListener('mousemove', showTip);
  trendCanvas.addEventListener('mouseleave', hideTip);
  trendCanvas.addEventListener('touchstart', function(e){ showTip(e); }, {passive:true});
  trendCanvas.addEventListener('touchmove', function(e){ showTip(e); e.preventDefault(); }, {passive:false});
  trendCanvas.addEventListener('touchend', function(){ setTimeout(hideTip, 2200); });
  trendCanvas.addEventListener('click', function(){ openDrawer(); });
  trendCanvas.addEventListener('keydown', function(e){
    if(e.key==='Enter'||e.key===' '){ e.preventDefault(); openDrawer(); }
    if(e.key==='ArrowLeft'||e.key==='ArrowRight'){
      e.preventDefault(); var data = visible();
      hoverIdx = clamp((hoverIdx==null ? data.length-1 : hoverIdx)+(e.key==='ArrowRight'?1:-1),0,data.length-1);
      tooltip.innerHTML = tipHTML(data[hoverIdx]);
      var wrap = $('#chartWrap').getBoundingClientRect();
      tooltip.style.left = clamp((hoverIdx/(data.length-1))*wrap.width,8,wrap.width-190)+'px'; tooltip.style.top = '10px';
      tooltip.classList.add('on'); renderTrend();
    }
    if(e.key==='Escape') hideTip();
  });

  /* ---------- legend toggles ---------- */
  $$('.lg').forEach(function(btn){
    btn.addEventListener('click', function(){
      var k = btn.dataset.series, on = btn.getAttribute('aria-pressed')==='true';
      var other = k==='total' ? 'fail' : 'total';
      if(on && !showSeries[other]) return;           // keep at least one series
      showSeries[k] = !on; btn.setAttribute('aria-pressed', String(!on)); renderTrend();
      if(drawer.classList.contains('on')) renderDetail();
    });
  });

  /* ---------- drawer ---------- */
  function resample(interval){
    var src = points.slice(-60), out = [];
    if(interval===1) return src;
    for(var i=0;i<src.length;i+=interval){
      var chunk = src.slice(i,i+interval); if(!chunk.length) break;
      var total=0, fail=0; chunk.forEach(function(d){ total+=d.total; fail+=d.fail; });
      out.push({t:chunk[0].t, total:total, fail:fail});
    }
    return out;
  }
  function renderDetail(){
    if(points.length<2) return;
    var data = resample(drawerInterval), m = maxima(data);
    drawChart(detailCanvas, data, {padL:58,padR:50,padT:14,padB:24,maxTotal:m.total,maxFail:m.fail,vStep:Math.max(2,Math.round(data.length/6)),show:showSeries,hover:null});
    var total=0, fail=0, peak=0; data.forEach(function(d){ total+=d.total; fail+=d.fail; if(d.total>peak) peak=d.total; });
    var mins = Math.min(60, points.length);
    $('#detailStats').innerHTML =
      '<div class="stat"><div class="k">TOTAL EVENTS</div><div class="v">'+nf0.format(total)+'</div></div>'+
      '<div class="stat"><div class="k">ALERTS</div><div class="v" style="color:#FF4D5E">'+fail+'</div></div>'+
      '<div class="stat"><div class="k">AVG EVENTS/S</div><div class="v">'+(total/(mins*60)).toFixed(1)+'</div></div>'+
      '<div class="stat"><div class="k">PEAK / '+drawerInterval+' MIN</div><div class="v">'+nf0.format(peak)+'</div></div>';
    $('#drawerMeta').textContent = hhmm(data[0].t)+' — '+hhmm(data[data.length-1].t)+' · Granularity '+drawerInterval+' min';
    $('#detailSummary').textContent = 'Chart summary: '+nf0.format(total)+' events and '+fail+' alerts in the period.';
  }
  function openDrawer(alertIdx){
    if(alertIdx!=null){ activeAlert = alertIdx; renderAlerts(); }
    renderDetail(); overlay.classList.add('on'); drawer.classList.add('on'); drawer.setAttribute('aria-hidden','false');
    if(alertIdx!=null){ var el = $('.tl-item.hl'); if(el && el.scrollIntoView) el.scrollIntoView({block:'nearest'}); }
    setTimeout(function(){ $('#closeDrawer').focus(); }, 60);
  }
  function closeDrawer(){ overlay.classList.remove('on'); drawer.classList.remove('on'); drawer.setAttribute('aria-hidden','true'); if(D) apply(D); }
  $('#expandBtn').addEventListener('click', function(){ openDrawer(); });
  $('#closeDrawer').addEventListener('click', closeDrawer);
  overlay.addEventListener('click', closeDrawer);
  $('#resetLive').addEventListener('click', function(){
    drawerInterval = 1; $$('#drawer .seg button[data-int]').forEach(function(b){ b.setAttribute('aria-pressed', String(b.dataset.int==='1')); }); closeDrawer();
  });
  $$('#drawer .seg button[data-int]').forEach(function(b){
    b.addEventListener('click', function(){
      drawerInterval = parseInt(b.dataset.int,10);
      $$('#drawer .seg button[data-int]').forEach(function(x){ x.setAttribute('aria-pressed', String(x===b)); }); renderDetail();
    });
  });
  document.addEventListener('keydown', function(e){ if(e.key==='Escape' && drawer.classList.contains('on')) closeDrawer(); });

  /* ---------- history / comparisons ---------- */
  var histDrawer = $('#histDrawer'), H = null, histMetric = 'events', histHover = -1, histTimer = null;
  var MLABEL = {events:'Events', alerts:'Alerts', sev_high:'High alerts', ai_in:'AI servers received', ai_out:'AI servers sent'};
  var BAD_UP = {alerts:true, sev_high:true};                // metrics where an increase is "bad"
  function fmtMetric(m, v){
    if(v==null) return '–';
    if(m==='ai_in' || m==='ai_out') return fmtBytes(v);
    return v>=1e5 ? compact(v) : nf0.format(v);
  }
  function deltaCell(m, cur, prev, win){
    var need = Math.ceil(win*0.9);
    if(cur.sum==null || prev.sum==null) return '<td class="dc na" title="No data collected for this window yet">n/a</td>';
    if(cur.hours<need || prev.hours<need) return '<td class="dc na" title="Both windows need at least '+need+' of '+win+' hours of data">partial '+cur.hours+'/'+prev.hours+' h</td>';
    if(prev.sum===0) return '<td class="dc na">'+(cur.sum===0?'0%':'new')+'</td>';
    var pct = (cur.sum-prev.sum)/prev.sum*100, up = pct>=0;
    var cls = Math.abs(pct)<0.05 ? 'na' : (BAD_UP[m] ? (up?'badc':'goodc') : (up?'up':'down'));
    return '<td class="dc '+cls+'">'+(up?'▲ ':'▼ ')+Math.abs(pct).toFixed(1)+'%</td>';
  }
  function valCell(m, w, win){
    var t = w.hours<win ? '<small>'+w.hours+'/'+win+' h</small>' : '';
    return '<td>'+fmtMetric(m, w.sum)+t+'</td>';
  }
  function cmpTable(c, labels, withWeek){
    var win = c.hours, order = (H && H.ai_configured===false) ? ['events','alerts','sev_high'] : ['events','alerts','sev_high','ai_in','ai_out'];
    var head = '<tr><th>METRIC</th><th>'+labels[0]+'</th><th>'+labels[1]+'</th><th>CHANGE</th>'+(withWeek?'<th>'+labels[2]+'</th><th>CHANGE</th>':'')+'</tr>';
    var body = order.map(function(m){
      var x = c.metrics[m];
      return '<tr><td>'+MLABEL[m]+'</td>'+valCell(m,x.cur,win)+valCell(m,x.prev,win)+deltaCell(m,x.cur,x.prev,win)+
        (withWeek ? valCell(m,x.wk,win)+deltaCell(m,x.cur,x.wk,win) : '')+'</tr>';
    }).join('');
    return '<div class="cmp-wrap"><table class="cmp"><thead>'+head+'</thead><tbody>'+body+'</tbody></table></div>';
  }
  function renderHistory(){
    if(!H) return;
    if(H.error){ $('#histMeta').textContent = 'History unavailable: '+H.error; return; }
    var noAi = H.ai_configured===false;
    $$('#histMetric button').forEach(function(b){ b.hidden = noAi && /^ai_/.test(b.dataset.m); });
    if(noAi && /^ai_/.test(histMetric)){ histMetric = 'events'; $$('#histMetric button').forEach(function(x){ x.setAttribute('aria-pressed', String(x.dataset.m==='events')); }); }
    $('#histMeta').textContent = 'Hourly aggregates, kept '+H.retain_days+' days · compared through '+H.last_complete_hour;
    $('#dailyCmp').innerHTML = cmpTable(H.daily, ['LAST 24 H','PREVIOUS 24 H','SAME 24 H LAST WEEK'], true);
    $('#weeklyCmp').innerHTML = cmpTable(H.weekly, ['LAST 7 D','PREVIOUS 7 D'], false);
    $('#dailyMeta').textContent = '· rolling 24 complete hours';
    $('#weeklyMeta').textContent = '· rolling 7 × 24 complete hours';
    var s = H.since, notes = [];
    notes.push('Events history starts '+(s.events||'–')+(s.live && s.events!==s.live ? ' (days before '+s.live+' come from UTMStack ingest statistics)' : '')+'.');
    notes.push((noAi ? 'Alerts are' : 'Alerts and AI traffic are')+' recorded from '+(s.alerts||'–')+' onward; OpenSearch keeps no older copy.');
    notes.push('Comparisons show a change only when both windows have at least 90% of their hours; gaps are never filled in. Alerts rising is shown red; traffic rising is shown yellow.');
    $('#histNotes').innerHTML = notes.map(esc).join('<br>');
    drawHist();
  }
  function drawHist(){
    var cv = $('#histCanvas'); if(!H || !H.days) return;
    var f = fit(cv), ctx = f.ctx, w = f.w, h = f.h; ctx.clearRect(0,0,w,h);
    var days = H.days, padL = 58, padR = 12, padT = 14, padB = 24, pw = w-padL-padR, ph = h-padT-padB;
    var max = 0; days.forEach(function(d){ if(d[histMetric]!=null && d[histMetric]>max) max = d[histMetric]; });
    if(max<=0) max = 1;
    var nice = Math.pow(10, Math.floor(Math.log10(max))), top = Math.ceil(max*1.08/nice)*nice;
    ctx.font = '600 11.5px ui-monospace, monospace'; ctx.lineWidth = 1;
    for(var k=0;k<=4;k++){
      var yy = Math.round(padT+ph*k/4)+.5;
      ctx.strokeStyle = k===4 ? '#284056' : '#1B2A3A'; ctx.beginPath(); ctx.moveTo(padL,yy); ctx.lineTo(padL+pw,yy); ctx.stroke();
      ctx.fillStyle = '#8299AB'; ctx.textAlign = 'right'; ctx.textBaseline = 'middle';
      var v = top*(1-k/4); ctx.fillText(histMetric==='ai_in'||histMetric==='ai_out' ? fmtBytes(v) : compact(v), padL-8, yy);
    }
    var slot = pw/days.length, bw = Math.max(3, slot*.7);
    days.forEach(function(d,i){
      var x = padL+i*slot+(slot-bw)/2, v = d[histMetric], base = padT+ph;
      if(v==null){                                                    // no data collected that day
        ctx.strokeStyle = '#284056'; ctx.setLineDash([2,3]); ctx.beginPath(); ctx.moveTo(x,base-2); ctx.lineTo(x+bw,base-2); ctx.stroke(); ctx.setLineDash([]);
      } else {
        var bh = Math.max(1, v/top*ph), partial = d.today || d.hours<24;
        ctx.fillStyle = i===histHover ? '#9CF3FF' : (d.today ? '#68F5B1' : (partial ? '#2C7A9E' : '#35E7FF'));
        ctx.fillRect(x, base-bh, bw, bh);
      }
      if(i%7===0 || i===days.length-1){
        ctx.fillStyle = '#8299AB'; ctx.textAlign = 'center'; ctx.textBaseline = 'top'; ctx.fillText(d.day.slice(5), x+bw/2, base+7);
      }
    });
    var have = days.filter(function(d){return d[histMetric]!=null}).length;
    $('#histSummary').textContent = MLABEL[histMetric]+': '+have+' of '+days.length+' days have data.';
  }
  function loadHistory(){
    fetch('/api/history', {cache:'no-store'}).then(function(r){ return r.json(); }).then(function(d){ H = d; renderHistory(); })
      .catch(function(e){ H = {error:'server unreachable ('+e.message+')'}; renderHistory(); });
  }
  function openHist(){
    overlay.classList.add('on'); histDrawer.classList.add('on'); histDrawer.setAttribute('aria-hidden','false');
    loadHistory(); clearInterval(histTimer); histTimer = setInterval(loadHistory, 60000);
    setTimeout(function(){ $('#closeHist').focus(); drawHist(); }, 450);
  }
  function closeHist(){
    clearInterval(histTimer); histTimer = null;
    if(!drawer.classList.contains('on')) overlay.classList.remove('on');
    histDrawer.classList.remove('on'); histDrawer.setAttribute('aria-hidden','true');
  }
  $('#trendsBtn').addEventListener('click', openHist);
  $('#closeHist').addEventListener('click', closeHist);
  overlay.addEventListener('click', closeHist);
  document.addEventListener('keydown', function(e){ if(e.key==='Escape' && histDrawer.classList.contains('on')) closeHist(); });
  $$('#histMetric button').forEach(function(b){
    b.addEventListener('click', function(){
      histMetric = b.dataset.m; $$('#histMetric button').forEach(function(x){ x.setAttribute('aria-pressed', String(x===b)); }); drawHist();
    });
  });
  var histCv = $('#histCanvas'), histTip = $('#histTip');
  function histPick(ev){
    if(!H || !H.days) return -1;
    var r = histCv.getBoundingClientRect(), x = ev.clientX-r.left, pw = r.width-58-12;
    var i = Math.floor((x-58)/(pw/H.days.length));
    return (i>=0 && i<H.days.length) ? i : -1;
  }
  histCv.addEventListener('mousemove', function(ev){
    var i = histPick(ev); if(i===histHover) return; histHover = i; drawHist();
    if(i<0){ histTip.classList.remove('on'); return; }
    var d = H.days[i], r = histCv.getBoundingClientRect(), pr = histCv.parentNode.getBoundingClientRect();
    histTip.innerHTML = '<div class="tt-t">'+esc(d.day)+(d.today?' (today)':'')+'</div>'+
      '<div class="row"><span>'+MLABEL[histMetric]+'</span><span style="color:#35E7FF">'+fmtMetric(histMetric,d[histMetric])+'</span></div>'+
      '<div class="row"><span>Hours of data</span><span>'+d.hours+'/24</span></div>';
    var x = ev.clientX-pr.left+14, tw = histTip.offsetWidth||170;
    histTip.style.left = clamp(x,8,pr.width-tw-8)+'px'; histTip.style.top = '10px'; histTip.classList.add('on');
  });
  histCv.addEventListener('mouseleave', function(){ histHover = -1; histTip.classList.remove('on'); drawHist(); });

  /* ======================= drill-down drawer ======================= */
  var dig = $('#dig'), digBody = $('#digBody'), digStack = [], digTok = 0, S = null;
  function fmtDT(d){ d = new Date(d); return pad(d.getMonth()+1)+'-'+pad(d.getDate())+' '+hhmmss(d); }
  function ago(s){ s = Math.max(0,s); if(s<90) return Math.round(s)+' s'; if(s<5400) return (s/60).toFixed(1)+' min'; return (s/3600).toFixed(1)+' h'; }
  function signedAgo(s){ return (s<0?'−':'+')+ago(Math.abs(s)); }
  function pillSev(s){ return '<span class="lvl '+lvlClass(s)+'"><i class="d '+lvlDot(s)+'"></i>'+esc(s)+'</span>'; }
  function api(path, params){
    var q = '';
    if(params){
      q = '?'+Object.keys(params).filter(function(k){ return params[k]!=='' && params[k]!=null; })
        .map(function(k){ return encodeURIComponent(k)+'='+encodeURIComponent(params[k]); }).join('&');
    }
    return fetch(path+q, {cache:'no-store'}).then(signedIn).then(function(r){ return r.json(); })
      .then(function(d){ if(d && d.error) throw new Error(d.error); return d; });
  }
  function setHead(title, meta){ $('#digTitle').textContent = title; $('#digMeta').textContent = meta||''; }
  function loading(){ digBody.innerHTML = '<div class="empty">Loading…</div>'; }
  function failed(e){ digBody.innerHTML = '<div class="empty">Could not load: '+esc(e.message||e)+'</div>'; }
  function spark(vals){
    var w = 84, h = 18, max = 1; vals.forEach(function(v){ if(v>max) max = v; });
    var pts = vals.map(function(v,i){ return (i/(Math.max(1,vals.length-1))*w).toFixed(1)+','+(h-1-(v/max)*(h-3)).toFixed(1); }).join(' ');
    return '<svg class="spk" width="'+w+'" height="'+h+'" viewBox="0 0 '+w+' '+h+'" aria-hidden="true"><polyline fill="none" stroke="#35E7FF" stroke-width="1.3" points="'+pts+'"/></svg>';
  }
  function bar(pct, color){ return '<span class="mini"><i style="width:'+clamp(pct,0.5,100)+'%;background:'+(color||'#35E7FF')+'"></i></span>'; }
  function kv(o, prefix, out, depth){
    out = out || []; depth = depth||0;
    Object.keys(o||{}).forEach(function(k){
      var v = o[k], key = prefix ? prefix+'.'+k : k;
      if(v==null || v==='' || (Array.isArray(v) && !v.length)) return;
      if(typeof v==='object' && !Array.isArray(v) && depth<2) kv(v, key, out, depth+1);
      else out.push([key, Array.isArray(v) ? v.map(function(x){ return typeof x==='object' ? JSON.stringify(x) : x; }).join(', ') : String(v)]);
    });
    return out;
  }
  function kvTable(o, skip){
    var rows = kv(o).filter(function(r){ return !skip || skip.indexOf(r[0].split('.')[0])<0; }).slice(0,70);
    if(!rows.length) return '<div class="ai-note">No fields.</div>';
    return '<table class="cmp kvt"><tbody>'+rows.map(function(r){ return '<tr><td>'+esc(r[0])+'</td><td class="wrap">'+esc(r[1])+'</td></tr>'; }).join('')+'</tbody></table>';
  }
  function statCards(items){
    return '<div class="stat-grid">'+items.map(function(i){
      return '<div class="stat"><div class="k">'+i[0]+'</div><div class="v"'+(i[2]?' style="color:'+i[2]+'"':'')+'>'+i[1]+'</div></div>';
    }).join('')+'</div>';
  }
  function barChart(cv, vals, labels){
    if(!cv) return;
    var f = fit(cv), ctx = f.ctx, w = f.w, h = f.h; ctx.clearRect(0,0,w,h);
    var padL = 46, padB = 18, padT = 8, pw = w-padL-8, ph = h-padT-padB, max = 1;
    vals.forEach(function(v){ if(v>max) max = v; });
    ctx.font = '600 11.5px ui-monospace, monospace'; ctx.fillStyle = '#8299AB'; ctx.textAlign = 'right'; ctx.textBaseline = 'middle';
    ctx.fillText(compact(max), padL-6, padT+4); ctx.fillText('0', padL-6, padT+ph);
    ctx.strokeStyle = '#284056'; ctx.beginPath(); ctx.moveTo(padL,padT+ph+.5); ctx.lineTo(w-8,padT+ph+.5); ctx.stroke();
    var slot = pw/vals.length, bw = Math.max(2, slot*.72);
    vals.forEach(function(v,i){
      var bh = v/max*ph; ctx.fillStyle = i===vals.length-1 ? '#68F5B1' : '#35E7FF'; ctx.fillRect(padL+i*slot+(slot-bw)/2, padT+ph-bh, bw, bh);
    });
    ctx.fillStyle = '#8299AB'; ctx.textBaseline = 'top';
    [0, Math.floor(vals.length/2), vals.length-1].forEach(function(i,k){
      ctx.textAlign = k===0 ? 'left' : (k===2 ? 'right' : 'center');
      ctx.fillText(labels[i], k===0 ? padL : (k===2 ? w-8 : padL+pw/2), padT+ph+5);
    });
  }

  function openDig(v, reset){
    if(reset) digStack = [];
    digStack.push(v);
    if(histDrawer.classList.contains('on')) closeHist();
    if(drawer.classList.contains('on')) closeDrawer();
    overlay.classList.add('on'); dig.classList.add('on'); dig.setAttribute('aria-hidden','false');
    renderDig();
  }
  function closeDig(){
    digStack = []; digTok++;
    dig.classList.remove('on'); dig.setAttribute('aria-hidden','true');
    if(!drawer.classList.contains('on') && !histDrawer.classList.contains('on')) overlay.classList.remove('on');
  }
  function digBack(){ digStack.pop(); if(digStack.length) renderDig(); else closeDig(); }
  function renderDig(){
    var v = digStack[digStack.length-1], tok = ++digTok;
    $('#digBack').hidden = digStack.length<2;
    loading();
    VIEWS[v.name](v, function(){ return tok===digTok; });
    digBody.scrollTop = 0;
  }

  var VIEWS = {};

  /* ---- sources / event types ---- */
  VIEWS.sources = function(v, live){
    setHead(v.tab==='type' ? 'Events · Breakdown by Type' : 'Data Sources', 'Last 24 hours');
    var go = function(){ if(live()) drawSources(v); };
    if(v.data){ go(); return; }
    api('/api/sources').then(function(d){ v.data = d; go(); }).catch(function(e){ if(live()) failed(e); });
  };
  function drawSources(v){
    var d = v.data, now = d.now, srcs = d.sources.slice().sort(function(a,b){ return b.events-a.events; });
    var online = srcs.filter(function(s){ return now-(s.last||0) < 600000; }).length;
    var top3 = srcs.slice(0,3).reduce(function(s,x){ return s+x.share; },0);
    var html = statCards([['EVENTS (24 H)', nf0.format(d.total)], ['DATA SOURCES', srcs.length+' <span class="unit">'+online+' online</span>'],
      ['TOP 3 PRODUCE', top3.toFixed(0)+'%'], ['EVENT TYPES', String(d.types.length)]]);
    html += '<div class="seg" role="group" aria-label="Breakdown"><button data-act="srctab" data-v="source" aria-pressed="'+(v.tab==='source')+'">By source</button>'+
            '<button data-act="srctab" data-v="type" aria-pressed="'+(v.tab==='type')+'">By type</button></div>';
    if(v.tab==='type'){
      html += '<table class="cmp"><thead><tr><th>EVENT TYPE</th><th>EVENTS</th><th>SHARE</th><th>SOURCES</th><th>TOP SOURCE</th></tr></thead><tbody>'+
        d.types.map(function(t){
          return '<tr class="clk" tabindex="0" data-act="type" data-v="'+esc(t.name)+'"><td>'+esc(TYPE_LABEL[t.name]||t.name)+'</td><td>'+nf0.format(t.events)+'</td>'+
            '<td>'+bar(t.share)+' '+t.share.toFixed(1)+'%</td><td>'+t.sources+'</td><td>'+esc(t.top)+'</td></tr>';
        }).join('')+'</tbody></table><div class="ai-note">Click a type to list its sources.</div>';
    } else {
      var list = v.type ? srcs.filter(function(s){ return s.types.indexOf(v.type)>=0; }) : srcs;
      if(v.type) html += '<div class="chip">Type: '+esc(TYPE_LABEL[v.type]||v.type)+' <button data-act="type" data-v="" aria-label="Clear type filter">✕</button></div>';
      html += '<table class="cmp"><thead><tr><th>SOURCE</th><th>TYPE</th><th>EVENTS</th><th>SHARE</th><th>ALERTS</th><th>24 H</th><th>LAST SEEN</th><th>STATE</th></tr></thead><tbody>'+
        list.map(function(s){
          var age = (now-(s.last||0))/1000, on = age<600;
          return '<tr class="clk" tabindex="0" data-act="source" data-v="'+esc(s.name)+'"><td>'+esc(s.name)+'</td><td>'+esc(TYPE_LABEL[s.type]||s.type)+'</td>'+
            '<td>'+nf0.format(s.events)+'</td><td>'+bar(s.share)+' '+s.share.toFixed(1)+'%</td><td'+(s.alerts?' class="badc"':'')+'>'+s.alerts+'</td>'+
            '<td>'+spark(s.hourly)+'</td><td>'+ago(age)+' ago</td><td class="'+(on?'goodc':'up')+'">'+(on?'Online':'Silent')+'</td></tr>';
        }).join('')+'</tbody></table>';
    }
    digBody.innerHTML = html;
  }

  /* ---- single source ---- */
  VIEWS.source = function(v, live){
    setHead('Source · '+v.src, 'Last 24 hours');
    api('/api/source', {name:v.src}).then(function(d){
      if(!live()) return;
      var lag = d.lag, lagTxt = lag && lag.p50!=null ? signedAgo(lag.p50)+' median' : 'n/a';
      var html = statCards([['EVENTS (24 H)', nf0.format(d.events)], ['ALERTS (24 H)', nf0.format(d.alerts), d.alerts?'#FF8A95':null],
        ['TYPE', esc((d.types[0]&&(TYPE_LABEL[d.types[0].name]||d.types[0].name))||'–')], ['DEVICE → STORED', lagTxt]]);
      html += '<canvas class="detail-chart" id="srcCanvas" role="img" aria-label="Events per hour for this source, last 24 hours."></canvas>';
      html += '<h3 class="tl-title">Alerts raised by this source</h3>';
      html += d.rules.length ? '<table class="cmp"><tbody>'+d.rules.map(function(r){
        return '<tr class="clk" tabindex="0" data-act="alerts-rule" data-src="'+esc(d.name)+'" data-v="'+esc(r.name)+'"><td>'+esc(r.name)+'</td><td>'+pillSev(r.sev)+'</td><td>'+r.n+'</td></tr>';
      }).join('')+'</tbody></table>' : '<div class="ai-note">No alerts from this source in the last 24 h.</div>';
      if(d.alerts) html += '<div><button class="ghost-btn" data-act="alerts-src" data-v="'+esc(d.name)+'">View all '+d.alerts+' alerts from this source</button></div>';
      html += '<h3 class="tl-title">Most recent events <span class="panel-meta">newest 20 · click to expand</span></h3>';
      html += d.recent.map(function(r){
        return '<details class="ev"><summary><span class="t">'+fmtDT(r.t)+'</span> <span class="svc">'+esc(r.type||'')+'</span> <span class="snip">'+esc((r.raw||'').slice(0,110))+'</span></summary><pre>'+esc(r.raw||'')+'</pre></details>';
      }).join('') || '<div class="ai-note">No events.</div>';
      digBody.innerHTML = html;
      barChart($('#srcCanvas'), d.hourly.map(function(h){ return h.n; }), d.hourly.map(function(h){ return hhmm(new Date(h.t)); }));
    }).catch(function(e){ if(live()) failed(e); });
  };

  /* ---- alerts list ---- */
  VIEWS.alerts = function(v, live){
    setHead('Alerts', 'Last 24 hours · newest first');
    api('/api/alerts', {sev:v.sev, source:v.source, rule:v.rule, q:v.q, from:v.from||0, size:25}).then(function(d){
      if(!live()) return;
      var opt = function(list, cur, any){ var l = list.slice(); if(cur && l.indexOf(cur)<0) l.unshift(cur);
        return '<option value="">'+any+'</option>'+l.map(function(x){ return '<option'+(x===cur?' selected':'')+' value="'+esc(x)+'">'+esc(x)+'</option>'; }).join(''); };
      var sevChips = ['High','Medium','Low'].map(function(s){
        return '<button class="chip btn" data-act="sevf" data-v="'+s+'" aria-pressed="'+(v.sev===s)+'">'+s+' <b>'+(d.sev[s]||0)+'</b></button>'; }).join('');
      var html = '<div class="filters">'+
        '<label>Severity<select id="fSev"><option value="">All</option>'+['High','Medium','Low'].map(function(s){ return '<option'+(v.sev===s?' selected':'')+'>'+s+'</option>'; }).join('')+'</select></label>'+
        '<label>Source<select id="fSrc">'+opt(d.sources, v.source, 'All sources')+'</select></label>'+
        '<label>Rule<select id="fRule">'+opt(d.rules, v.rule, 'All rules')+'</select></label>'+
        '<label class="grow">Search<input id="fQ" type="search" maxlength="100" placeholder="name, description, source…" value="'+esc(v.q||'')+'"></label>'+
        '<button class="ghost-btn" data-act="search">Apply</button><button class="ctl" data-act="reset">Reset</button></div>';
      html += '<div class="chips"><span class="panel-meta">'+nf0.format(d.total)+' matching</span>'+sevChips+'</div>';
      html += d.items.length ? '<table class="cmp"><thead><tr><th>TIME</th><th>SEVERITY</th><th>SOURCE</th><th>ALERT</th><th>IP</th><th>EVT</th><th>STATUS</th></tr></thead><tbody>'+
        d.items.map(function(a){
          return '<tr class="clk" tabindex="0" data-act="alert" data-v="'+esc(a.id)+'"><td>'+fmtDT(a.t)+'</td><td>'+pillSev(a.sev)+'</td><td>'+esc(a.source)+'</td><td class="wrap">'+esc(a.name)+'</td><td>'+esc(a.ip)+'</td><td>'+a.affected+'</td><td>'+esc(a.status)+'</td></tr>';
        }).join('')+'</tbody></table>' : '<div class="empty">No alerts match these filters.</div>';
      var from = d.from, to = Math.min(d.total, from+d.size);
      html += '<div class="pager"><button class="ctl" data-act="page" data-v="'+Math.max(0,from-d.size)+'"'+(from<=0?' disabled':'')+'>← Newer</button>'+
        '<span class="panel-meta">'+(d.total?(from+1):0)+'–'+to+' of '+nf0.format(d.total)+'</span>'+
        '<button class="ctl" data-act="page" data-v="'+(from+d.size)+'"'+(to>=d.total?' disabled':'')+'>Older →</button></div>';
      digBody.innerHTML = html;
    }).catch(function(e){ if(live()) failed(e); });
  };

  /* ---- single alert ---- */
  VIEWS.alert = function(v, live){
    setHead('Alert detail', '');
    api('/api/alert', {id:v.id}).then(function(a){
      if(!live()) return;
      setHead(a.name||'Alert', a.id);
      var sevL = a.severityLabel||'Low';
      var html = '<div class="badges">'+pillSev(sevL)+' <span class="tag">'+esc(a.statusLabel||'Open')+'</span>'+(a['@timestamp']?' <span class="tag">'+fmtDT(a['@timestamp'])+'</span>':'')+
        (a.category?' <span class="tag">'+esc(a.category)+'</span>':'')+(a.technique&&a.technique!=='Indeterminate'?' <span class="tag">'+esc(a.technique)+'</span>':'')+'</div>';
      html += '<p class="desc">'+esc(a.description||'')+'</p>';
      if(a.solution) html += '<div class="note-card"><b>Recommended action</b><br>'+esc(a.solution)+'</div>';
      html += '<div class="drawer-foot">'+
        (a.dataSource?'<button class="ghost-btn" data-act="source" data-v="'+esc(a.dataSource)+'">Source: '+esc(a.dataSource)+'</button><button class="ghost-btn" data-act="alerts-src" data-v="'+esc(a.dataSource)+'">More from this source</button>':'')+
        '<button class="ghost-btn" data-act="alerts-rule" data-src="" data-v="'+esc(a.name||'')+'">Same rule</button></div>';
      var facts = {dataSource:a.dataSource, dataType:a.dataType, adversary:a.adversary, target:a.target, impact:a.impact, groupedBy:a.groupedBy, deduplicatedBy:a.deduplicatedBy, reference:a.reference, notes:a.notes};
      html += '<h3 class="tl-title">Details</h3>'+kvTable(facts);
      var ips = alertIps(a);
      if(ips.length){
        html += '<h3 class="tl-title">Reputation <span class="panel-meta">AbuseIPDB &amp; VirusTotal · cached 24 h</span></h3>';
        html += ips.map(function(x,i){ return '<div class="note-card whois" id="rep'+i+'"><b>'+esc(x.ip)+'</b> <span class="tag">'+esc(x.role)+'</span><br>Looking up…</div>'; }).join('');
        html += '<h3 class="tl-title">WHOIS <span class="panel-meta">RDAP via rdap.org · public IPs only · cached 24 h</span></h3>';
        html += ips.map(function(x,i){ return '<div class="note-card whois" id="whois'+i+'"><b>'+esc(x.ip)+'</b> <span class="tag">'+esc(x.role)+'</span><br>Looking up…</div>'; }).join('');
      }
      html += '<h3 class="tl-title">Source events <span class="panel-meta">showing '+(a.events||[]).length+' of '+a.event_count+'</span></h3>';
      html += (a.events||[]).map(function(e){
        var t = e.timestamp||e['@timestamp']||(e.log&&e.log.timesTamp)||'', ip = (e.origin&&e.origin.ip)||'';
        var geo = e.origin&&e.origin.geolocation ? [e.origin.geolocation.city, e.origin.geolocation.country].filter(Boolean).join(', ') : '';
        return '<details class="ev"><summary><span class="t">'+esc(String(t).slice(0,25))+'</span> <span class="svc">'+esc(e.dataType||'')+'</span> <span class="snip">'+esc(ip+(geo?' · '+geo:''))+(e.severity?' · '+esc(e.severity):'')+'</span></summary>'+
          kvTable(e, ['raw'])+(e.raw?'<pre>'+esc(e.raw)+'</pre>':'')+'</details>';
      }).join('') || '<div class="ai-note">No event data stored on this alert.</div>';
      digBody.innerHTML = html;
      loadReputation(ips, live);
      loadWhois(ips, live);
    }).catch(function(e){ if(live()) failed(e); });
  };

  /* ---- single blocked-inbound IP (from the Live Firewall Map ticker, not tied to an alert) ---- */
  var SERVICES = {20:'FTP data',21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',80:'HTTP',110:'POP3',123:'NTP',135:'MS RPC',
    137:'NetBIOS',139:'NetBIOS',143:'IMAP',161:'SNMP',389:'LDAP',443:'HTTPS',445:'SMB',465:'SMTPS',500:'IPsec IKE',514:'Syslog',
    587:'SMTP submission',993:'IMAPS',995:'POP3S',1194:'OpenVPN',1433:'MS SQL',1723:'PPTP',1900:'SSDP',3306:'MySQL',3389:'RDP',
    4500:'IPsec NAT-T',5060:'SIP',5061:'SIP TLS',5432:'PostgreSQL',5900:'VNC',6881:'BitTorrent',7680:'Windows Delivery Optimization',
    8000:'HTTP alt',8080:'HTTP proxy',8443:'HTTPS alt',9200:'OpenSearch',11211:'Memcached',27017:'MongoDB'};
  function when(t){ return t ? String(t).replace('T',' ').slice(0,16)+' UTC' : '–'; }
  function attackerHtml(d){
    if(d.error) return '<div class="note-card">'+esc(d.error)+'</div>';
    if(d.private) return '<div class="note-card">'+esc(d.note)+'</div>';
    if(!d.total) return '<div class="note-card">No logged traffic from this address in the last '+esc(d.hours||24)+' hours.</div>';
    var NET = {vpn:'VPN', tor:'Tor', hosting:'Hosting'};
    var h = '<table class="cmp kvt"><tbody>'+
      '<tr><td>Connections</td><td>'+nf0.format(d.total)+' · <span style="color:#FF8A95">'+nf0.format(d.denied||0)+' denied</span> · '+
        '<span style="color:#68F5B1">'+nf0.format(d.allowed||0)+' allowed</span></td></tr>'+
      '<tr><td>First / last seen</td><td>'+esc(when(d.first))+' → '+esc(when(d.last))+'</td></tr>'+
      (d.net?'<tr><td>Network</td><td><span class="netb netb-'+esc(d.net)+'">'+esc(NET[d.net]||d.net)+'</span></td></tr>':'')+
      ((d.types||[]).length?'<tr><td>Seen in</td><td>'+d.types.map(function(t){ return esc(t.type)+' ('+nf0.format(t.count)+')'; }).join(', ')+'</td></tr>':'')+
      '</tbody></table>';
    if(d.replies) h += '<div class="ai-note">'+nf0.format(d.replies)+' of these were late replies from port '+
      esc((d.reply_ports||[]).join(', ')||'?')+' to connections your own devices had already closed. The firewall drops them; they are not attacks.</div>';
    (d.reasons||[]).forEach(function(r){ h += '<div class="ai-note">Firewall: “'+esc(r.text)+'” ('+nf0.format(r.count)+')</div>'; });
    if((d.ports||[]).length){
      h += '<h3 class="tl-title">Ports tried <span class="panel-meta">'+(d.port_count>d.ports.length?'busiest '+d.ports.length+' of '+nf0.format(d.port_count)+' different ports':'on your side')+'</span></h3>'+
        '<table class="cmp"><thead><tr><th>Port</th><th>Service</th><th>Denied</th><th>Allowed</th></tr></thead><tbody>'+
        d.ports.map(function(x){ return '<tr><td>'+esc(x.port)+(x.proto?'/'+esc(String(x.proto).toLowerCase()):'')+'</td><td>'+esc(SERVICES[x.port]||'')+
          '</td><td style="color:'+(x.denied?'#FF8A95':'inherit')+'">'+nf0.format(x.denied)+'</td><td style="color:'+(x.allowed?'#FFC857':'inherit')+'">'+nf0.format(x.allowed)+'</td></tr>'; }).join('')+
        '</tbody></table>';
      if(d.ports.some(function(x){ return x.allowed; })) h += '<div class="ai-note" style="color:#FFC857">Some connections on these ports were allowed: check that the service behind them is meant to be reachable from the internet.</div>';
    } else if(!d.replies) h += '<div class="ai-note">No port information in these logs (e.g. sign-in or VPN-portal events).</div>';
    if((d.sites||[]).length) h += '<h3 class="tl-title">Sites it reached</h3><table class="cmp"><thead><tr><th>Site</th><th>Denied</th><th>Allowed</th></tr></thead><tbody>'+
      d.sites.map(function(x){ return '<tr><td>'+esc(x.name||x.site)+'</td><td>'+nf0.format(x.denied)+'</td><td>'+nf0.format(x.allowed)+'</td></tr>'; }).join('')+'</tbody></table>';
    if((d.targets||[]).length) h += '<h3 class="tl-title">Addresses it targeted</h3><table class="cmp"><thead><tr><th>Address</th><th>Ports</th><th>Denied</th><th>Allowed</th></tr></thead><tbody>'+
      d.targets.map(function(x){ return '<tr><td>'+esc(x.ip)+'</td><td>'+(x.ports||[]).map(esc).join(', ')+'</td><td>'+nf0.format(x.denied)+'</td><td>'+nf0.format(x.allowed)+'</td></tr>'; }).join('')+'</tbody></table>';
    return h;
  }
  VIEWS.ip = function(v, live){
    var ip = (v.ip||'').trim();
    setHead('Attacker', ip);
    if(!IP_RE.test(ip)){ failed({message: 'not a valid IP address'}); return; }
    var ips = [{ip: ip, role: 'blocked inbound'}];
    var html = '<div class="badges"><span class="tag">Blocked inbound</span>'+(v.sub?' <span class="tag">'+esc(v.sub)+'</span>':'')+'</div>';
    html += '<h3 class="tl-title">Activity from this address <span class="panel-meta">last 24 h · all sites</span></h3>'+
      '<div id="atk0"><div class="note-card">Looking up…</div></div>';
    html += '<h3 class="tl-title">Reputation <span class="panel-meta">AbuseIPDB &amp; VirusTotal · cached 24 h</span></h3>'+
      '<div class="note-card whois" id="rep0"><b>'+esc(ip)+'</b> <span class="tag">blocked inbound</span><br>Looking up…</div>'+
      '<h3 class="tl-title">WHOIS <span class="panel-meta">RDAP via rdap.org · public IPs only · cached 24 h</span></h3>'+
      '<div class="note-card whois" id="whois0"><b>'+esc(ip)+'</b> <span class="tag">blocked inbound</span><br>Looking up…</div>';
    digBody.innerHTML = html;
    api('/api/attacker', wallOn ? {ip: ip, anon: 1} : {ip: ip})
      .then(function(d){ if(live() && $('#atk0')) $('#atk0').innerHTML = attackerHtml(d); })
      .catch(function(e){ if(live() && $('#atk0')) $('#atk0').innerHTML = attackerHtml({error: e.message}); })
      .then(function(){ loadReputation(ips, live); loadWhois(ips, live); });
  };

  /* ---- live reputation (AbuseIPDB / VirusTotal) for a list of {ip, role} ---- */
  function repCard(x, d){
    var head = '<b>'+esc(x.ip)+'</b> <span class="tag">'+esc(x.role)+'</span>';
    if(d.error) return head+'<br>'+esc(d.error);
    if(d.private) return head+'<br>'+esc(d.note);
    var ab = d.abuseipdb || {}, vt = d.virustotal || {}, parts = [];
    if(ab.configured === false) parts.push('<div class="ai-note">AbuseIPDB not configured (set ABUSEIPDB_KEY).</div>');
    else if(ab.error) parts.push('<div class="ai-note">AbuseIPDB: '+esc(ab.error)+'</div>');
    else {
      var scoreCol = ab.score>=50 ? '#FF4D5E' : (ab.score>=10 ? '#FFC857' : '#68F5B1');
      parts.push('<table class="cmp kvt"><tbody>'+
        '<tr><td>AbuseIPDB score</td><td><span style="color:'+scoreCol+'">'+(ab.score!=null?esc(ab.score)+'/100':'–')+'</span></td></tr>'+
        (ab.reports?'<tr><td>Reports</td><td>'+nf0.format(ab.reports)+' from '+nf0.format(ab.distinct_reporters||0)+' reporters</td></tr>':'')+
        (ab.usage_type?'<tr><td>Usage type</td><td>'+esc(ab.usage_type)+'</td></tr>':'')+
        (ab.isp?'<tr><td>ISP</td><td>'+esc(ab.isp)+'</td></tr>':'')+'</tbody></table>');
    }
    if(vt.configured === false) parts.push('<div class="ai-note">VirusTotal not configured (set VIRUSTOTAL_KEY).</div>');
    else if(vt.error) parts.push('<div class="ai-note">VirusTotal: '+esc(vt.error)+'</div>');
    else {
      parts.push('<table class="cmp kvt"><tbody>'+
        '<tr><td>VirusTotal</td><td><span style="color:'+((vt.malicious||0)>0?'#FF4D5E':'#68F5B1')+'">'+esc(vt.malicious||0)+' malicious</span> / '+esc(vt.suspicious||0)+' suspicious / '+esc(vt.harmless||0)+' harmless</td></tr>'+
        ((vt.flagged_by||[]).length?'<tr><td>Flagged as</td><td>'+vt.flagged_by.map(esc).join(', ')+'</td></tr>':'')+
        (vt.as_owner?'<tr><td>Network</td><td>'+esc(vt.as_owner)+(vt.country?' · '+esc(vt.country):'')+'</td></tr>':'')+'</tbody></table>');
    }
    return head+parts.join('');
  }
  function loadReputation(ips, live){
    ips.reduce(function(chain, x, i){
      return chain.then(function(){
        var box = $('#rep'+i); if(!box || !live()) return;
        return api('/api/reputation', {ip:x.ip}).then(function(d){ if(live() && $('#rep'+i)) $('#rep'+i).innerHTML = repCard(x, d); })
          .catch(function(e){ if(live() && $('#rep'+i)) $('#rep'+i).innerHTML = repCard(x, {error:e.message}); });
      });
    }, Promise.resolve());
  }

  /* ---- WHOIS (RDAP) for the IPs on an alert ---- */
  var IP_RE = /^(\d{1,3}(\.\d{1,3}){3}|[0-9a-fA-F]*:[0-9a-fA-F:]+)$/;
  function alertIps(a){
    var out = [];
    function add(ip, role){ if(typeof ip==='string' && IP_RE.test(ip) && !out.some(function(x){ return x.ip===ip; })) out.push({ip:ip, role:role}); }
    add(a.adversary && a.adversary.ip, 'adversary'); add(a.target && a.target.ip, 'target');
    (a.events||[]).forEach(function(e){ add(e.origin && e.origin.ip, 'event origin'); add(e.target && e.target.ip, 'event target'); });
    return out.slice(0,5);
  }
  function whoisCard(x, d){
    var head = '<b>'+esc(x.ip)+'</b> <span class="tag">'+esc(x.role)+'</span>';
    if(d.error) return head+'<br>'+esc(d.error);
    if(d.private) return head+'<br>'+esc(d.note);
    var day = function(t){ return t ? String(t).slice(0,10) : ''; };
    var rows = [
      ['Network', (d.name||'')+(d.handle?'  ('+d.handle+')':'')], ['Country', d.country||''],
      ['Range', d.start ? d.start+' – '+d.end+((d.cidrs||[]).length?'   ['+d.cidrs.join(', ')+']':'') : ''],
      ['Type', d.type||''], ['Registered', day(d.registered)], ['Last changed', day(d.changed)],
      ['Abuse contact', d.abuse||''],
      ['Contacts', (d.contacts||[]).map(function(c){ return (c.roles.length?c.roles.join('/')+': ':'')+c.name+(c.email?' <'+c.email+'>':''); }).join('\n')],
      ['Remarks', (d.remarks||[]).join(' ')], ['Registry', d.source||'']
    ].filter(function(r){ return r[1]; });
    return head+'<table class="cmp kvt"><tbody>'+rows.map(function(r){
      return '<tr><td>'+esc(r[0])+'</td><td class="wrap" style="white-space:pre-line">'+esc(r[1])+'</td></tr>'; }).join('')+'</tbody></table>';
  }
  function loadWhois(ips, live){
    ips.reduce(function(chain, x, i){
      return chain.then(function(){
        var box = $('#whois'+i); if(!box || !live()) return;
        return api('/api/whois', {ip:x.ip}).then(function(d){ if(live() && $('#whois'+i)) $('#whois'+i).innerHTML = whoisCard(x, d); })
          .catch(function(e){ if(live() && $('#whois'+i)) $('#whois'+i).innerHTML = whoisCard(x, {error:e.message}); });
      });
    }, Promise.resolve());
  }

  /* ---- ingest lag ---- */
  VIEWS.lag = function(v, live){
    setHead('Ingest Lag · What is causing it', 'Last 15 minutes, per source');
    api('/api/lag').then(function(d){
      if(!live()) return;
      var html = statCards([['NEWEST EVENT AGE', d.newest_age_s==null?'–':ago(d.newest_age_s)], ['SOURCES CHECKED', String(d.sources.length)],
        ['LATE (≥1 MIN)', String(d.sources.filter(function(s){ return s.p50!=null && s.p50>=60 && s.docs>=20; }).length), '#FFC857'],
        ['SILENT (>10 MIN)', String(d.silent.length)]]);
      html += '<div class="ai-note">Two different things get called "lag". <b>Newest event age</b> is the headline number: how old the most recent stored event is. '+
        '<b>Device → stored delay</b> is the gap between the timestamp the device put on an event and when UTMStack stored it; it is the part that can hide behind a healthy headline.</div>';
      html += d.notes.map(function(n){ return '<div class="note-card '+esc(n.level)+'"><b>'+esc(n.title)+'</b><br>'+esc(n.text)+'</div>'; }).join('');
      html += '<h3 class="tl-title">Per-source delay <span class="panel-meta">device timestamp → stored · + late, − clock ahead</span></h3>';
      var rows = d.sources.map(function(s){
        var st = s.p50==null ? ['No device time','na'] : (s.p50>=60 ? ['Delayed','up'] : (s.p50<=-60 ? ['Clock ahead','up'] : ['On time','goodc']));
        return '<tr class="clk" tabindex="0" data-act="source" data-v="'+esc(s.name)+'"><td>'+esc(s.name)+'</td><td>'+esc(TYPE_LABEL[s.type]||s.type)+'</td><td>'+(s.eps*60).toFixed(0)+'</td>'+
          '<td>'+ago(s.age_s)+'</td><td>'+(s.p50==null?'–':signedAgo(s.p50))+'</td><td>'+(s.p95==null?'–':signedAgo(s.p95))+'</td><td class="'+st[1]+'">'+st[0]+'</td></tr>';
      });
      d.silent.forEach(function(s){
        rows.push('<tr class="clk" tabindex="0" data-act="source" data-v="'+esc(s.name)+'"><td>'+esc(s.name)+'</td><td>'+esc(TYPE_LABEL[s.type]||s.type)+'</td><td>0</td><td>'+ago(s.age_s)+'</td><td>–</td><td>–</td><td class="up">Silent</td></tr>');
      });
      html += '<table class="cmp"><thead><tr><th>SOURCE</th><th>TYPE</th><th>EVENTS/MIN</th><th>LAST EVENT</th><th>MEDIAN DELAY</th><th>P95 DELAY</th><th>STATE</th></tr></thead><tbody>'+rows.join('')+'</tbody></table>';
      digBody.innerHTML = html;
    }).catch(function(e){ if(live()) failed(e); });
  };

  /* ---- storage ---- */
  VIEWS.storage = function(v, live){
    setHead('Storage · Daily usage', 'OpenSearch primary shards · UTC days');
    api('/api/storage').then(function(d){
      if(!live()) return; S = d; renderStoreFoot();
      var html = statCards([['AVG PER DAY', fmtBytes(d.avg_daily_total||0)], ['ALERTS PER DAY', fmtBytes(d.avg_daily_alerts||0)],
        ['DISK FREE', fmtBytes(d.disk_free)], ['≈ DAYS LEFT', d.days_left!=null?Math.round(d.days_left)+' d':'–']]);
      html += '<div class="ai-note">Average basis: '+esc(d.avg_basis)+'. '+esc(d.note)+'</div>';
      html += '<table class="cmp"><thead><tr><th>DAY (UTC)</th><th>ALERTS</th><th>ALERT COUNT</th><th>PER ALERT</th><th>LOGS</th><th>LOG COUNT</th><th>TOTAL</th></tr></thead><tbody>'+
        d.days.slice().reverse().map(function(e){
          return '<tr><td>'+esc(e.day)+(e.day===d.today_utc?' <small>today, still growing</small>':'')+'</td><td>'+fmtBytes(e.alerts)+'</td><td>'+nf0.format(e.alert_docs)+'</td><td>'+(e.per_alert?fmtBytes(e.per_alert):'–')+'</td>'+
            '<td>'+fmtBytes(e.logs)+'</td><td>'+nf0.format(e.log_docs)+'</td><td>'+fmtBytes(e.total)+'</td></tr>';
        }).join('')+'</tbody></table>';
      digBody.innerHTML = html;
    }).catch(function(e){ if(live()) failed(e); });
  };

  /* ---- OpenSearch cluster status ---- */
  VIEWS.cluster = function(v, live){
    setHead('OpenSearch status', 'What is behind the cluster health');
    api('/api/cluster').then(function(d){
      if(!live()) return;
      var col = d.status==='green' ? '#68F5B1' : (d.status==='yellow' ? '#FFC857' : '#FF4D5E');
      setHead('OpenSearch is '+d.status, 'What is behind the cluster health');
      var html = statCards([['STATUS', d.status.toUpperCase(), col], ['DATA NODES', String(d.nodes)],
        ['ACTIVE SHARDS', d.active+' <span class="unit">'+(d.active_pct||0).toFixed(1)+'%</span>'],
        ['UNASSIGNED', String(d.unassigned), d.unassigned?'#FFC857':null], ['PRIMARIES MISSING', String(d.unassigned_primaries), d.unassigned_primaries?'#FF4D5E':null]]);
      html += d.notes.map(function(n){ return '<div class="note-card '+esc(n.level)+'"><b>'+esc(n.title)+'</b><br>'+esc(n.text)+'</div>'; }).join('');
      if(d.families.length){
        html += '<h3 class="tl-title">Where the unassigned shards are</h3><table class="cmp"><thead><tr><th>INDEX FAMILY</th><th>INDICES</th><th>UNASSIGNED</th><th>REPLICAS SET</th><th>SIZE</th></tr></thead><tbody>'+
          d.families.map(function(f){ return '<tr><td>'+esc(f.family)+'</td><td>'+f.indices+'</td><td class="up">'+f.unassigned+'</td><td>'+f.replicas+'</td><td>'+fmtBytes(f.bytes)+'</td></tr>'; }).join('')+'</tbody></table>';
        var rs = Object.keys(d.reasons);
        if(rs.length) html += '<div class="ai-note">Recorded reasons: '+rs.map(function(k){ return esc(k)+' ×'+d.reasons[k]; }).join(' · ')+'</div>';
      }
      if(d.explained){
        html += '<h3 class="tl-title">Why OpenSearch cannot place them <span class="panel-meta">allocation explain, e.g. '+esc(d.explained.index)+' shard '+esc(d.explained.shard)+'</span></h3>';
        html += '<div class="note-card"><b>'+esc(d.explained.text||'')+'</b>'+d.decider.map(function(x){ return '<br><span class="svc">'+esc(x.decider)+'</span> — '+esc(x.text); }).join('')+'</div>';
      }
      if(d.fix && d.can_fix && d.fix.steps.some(function(st){ return st.op; })){
        html += '<h3 class="tl-title">Apply the fix</h3><div class="note-card warn"><b>The dashboard can apply this fix for you.</b><br>'+
          'The dashboard runs the steps below for you: it removes the replica copies a one-node cluster can never place and stops new '+
          'indices from asking for one. No data is deleted. It re-checks the cluster first and only runs these exact changes.</div>'+
          '<div class="fix-apply">'+(d.needs_password?'<input id="fixPw" type="password" maxlength="200" autocomplete="current-password" placeholder="Your dashboard password" aria-label="Dashboard password">':'')+
          '<button class="ctl" id="fixApply" aria-pressed="true">Apply fix</button><span class="hint" id="fixNote"></span></div><div id="fixResults"></div>';
      }
      if(d.fix){
        html += '<h3 class="tl-title">'+(d.can_fix?'Or fix it by hand':'How to fix it')+'</h3><div class="note-card warn">'+
          (d.can_fix?'':d.viewer?'<b>Only an admin can apply the fix from the dashboard.</b> Ask one, or:<br>':
            '<b>This installation\'s OpenSearch account is read-only, so the dashboard cannot change your cluster.</b> Re-run the installer to add the fix account, or:<br>')+
          'Paste these commands one at a time into a terminal on the UTMStack server, as a user that can use sudo. '+
          'Each one reads the OpenSearch password from UTMStack\'s backend service by itself (you never type it) and prints OpenSearch\'s answer: '+
          '<code>{"acknowledged":true}</code> means it worked. They remove the replica copies a one-node cluster can never place and stop new daily '+
          'indices from asking for one. No data is deleted.</div>'+
          d.fix.steps.map(function(st, i){ return '<div class="ai-sec">'+(i+1)+' · '+esc(st.title.toUpperCase())+'</div><pre class="cmd">'+esc(st.cmd)+'</pre>'; }).join('');
        if(d.fix.protected_note) html += '<div class="note-card">'+esc(d.fix.protected_note)+'</div>';
        if(d.fix.manual && d.fix.manual.length)
          html += '<div class="note-card warn">Left out of the commands for safety, because their names contain unusual characters: '+
            d.fix.manual.map(esc).join(', ')+'. Check these indices by hand before changing them.</div>';
      }
      digBody.innerHTML = html;
      var btn = $('#fixApply');
      if(btn) btn.addEventListener('click', function(){
        var note = $('#fixNote'), pw = $('#fixPw');
        if(pw && !pw.value){ note.textContent = 'Enter your dashboard password first.'; note.style.color = '#FFC857'; pw.focus(); return; }
        btn.disabled = true; note.textContent = 'Applying…'; note.style.color = '';
        fetch('/api/cluster/fix', {method: 'POST', cache: 'no-store', headers: {'Content-Type': 'application/json', 'X-Observatory': '1'},
                                   body: JSON.stringify({current_password: pw ? pw.value : ''})})
          .then(function(r){ return r.json().then(function(j){ return {status: r.status, j: j}; }); })
          .then(function(res){
            if(!live()) return;
            btn.disabled = false;
            if(res.status !== 200){ note.textContent = res.j.error || ('Failed (HTTP '+res.status+')'); note.style.color = '#FF8A95'; return; }
            var c = res.j.cluster || {}, rs = res.j.results || [];
            note.textContent = 'OpenSearch is now '+String(c.status||'?').toUpperCase()+(c.unassigned?' · '+c.unassigned+' still unassigned':'');
            note.style.color = c.status==='green' ? '#68F5B1' : '#FFC857';
            $('#fixResults').innerHTML = rs.length ? '<table class="cmp"><tbody>'+rs.map(function(r){
              return '<tr><td>'+esc(r.title)+'</td><td style="color:'+(r.ok?'#68F5B1':'#FF8A95')+'">'+(r.ok?'✓ done':'✗ '+esc(r.text))+'</td></tr>'; }).join('')+'</tbody></table>'
              : '<div class="ai-note">Nothing left to fix.</div>';
            if(c.status==='green') setTimeout(function(){ if(live()) renderDig(); }, 2500);   // redraw: the panel turns green
            if(typeof refresh === 'function') refresh();
          })
          .catch(function(e){ if(live()){ btn.disabled = false; note.textContent = 'Failed: '+e.message; note.style.color = '#FF8A95'; } });
      });
    }).catch(function(e){ if(live()) failed(e); });
  };

  /* ---- delegated interaction ---- */
  function curView(){ return digStack[digStack.length-1]; }
  function readFilters(v){ v.sev = $('#fSev').value; v.source = $('#fSrc').value; v.rule = $('#fRule').value; v.q = $('#fQ').value.trim(); v.from = 0; }
  digBody.addEventListener('click', function(e){
    var t = e.target.closest('[data-act]'); if(!t || t.disabled) return;
    var a = t.dataset.act, v = curView(), val = t.dataset.v;
    if(a==='source') openDig({name:'source', src:val});
    else if(a==='alert') openDig({name:'alert', id:val});
    else if(a==='alerts-src') openDig({name:'alerts', source:val});
    else if(a==='alerts-rule') openDig({name:'alerts', rule:val, source:t.dataset.src||''});
    else if(a==='srctab'){ v.tab = val; v.type = ''; drawSources(v); }
    else if(a==='type'){ v.tab = 'source'; v.type = val; drawSources(v); }
    else if(a==='sevf'){ readFilters(v); v.sev = (v.sev===val ? '' : val); renderDig(); }
    else if(a==='search'){ readFilters(v); renderDig(); }
    else if(a==='reset'){ v.sev = v.source = v.rule = v.q = ''; v.from = 0; renderDig(); }
    else if(a==='page'){ v.from = +val; renderDig(); }
  });
  digBody.addEventListener('keydown', function(e){
    if(e.key==='Enter' && e.target.id==='fQ'){ var v = curView(); readFilters(v); renderDig(); return; }
    if((e.key==='Enter'||e.key===' ') && e.target.matches('tr[data-act]')){ e.preventDefault(); e.target.click(); }
  });
  $('#digBack').addEventListener('click', digBack);
  $('#closeDig').addEventListener('click', closeDig);
  overlay.addEventListener('click', closeDig);
  document.addEventListener('keydown', function(e){ if(e.key==='Escape' && dig.classList.contains('on')) closeDig(); });

  /* ---------- support panel (logo click) ---------- */
  var supDrawer = $('#supDrawer'), supInfo = null;
  function copyText(text){
    // navigator.clipboard needs HTTPS and may be refused by policy; the dashboard is often plain HTTP on the LAN,
    // so fall back to the older execCommand copy whenever the modern API is missing or rejects.
    if(navigator.clipboard && window.isSecureContext)
      return navigator.clipboard.writeText(text).catch(function(){ return legacyCopy(text); });
    return legacyCopy(text);
  }
  function legacyCopy(text){
    var ta = document.createElement('textarea'); ta.value = text; ta.setAttribute('readonly','');
    ta.style.position = 'fixed'; ta.style.opacity = '0'; document.body.appendChild(ta); ta.select();
    var ok = false; try { ok = document.execCommand('copy'); } catch(e){}
    document.body.removeChild(ta);
    return ok ? Promise.resolve() : Promise.reject(new Error('copy blocked'));
  }
  function diagText(i){
    return ['UTMStack Observatory '+i.version, 'Host: '+(i.host||'-'), 'Installed: '+(i.installed||'-'), 'Running since: '+(i.started||'-'),
      'OpenSearch: '+(i.opensearch||'-')+' via '+(i.transport||'-'), 'Newest data age: '+(i.data_age_s==null?'-':i.data_age_s.toFixed(1)+' s'),
      'Data sources online: '+(i.sources_online==null?'-':i.sources_online+' / '+i.sources_total), 'HTTPS: '+(i.tls?'yes':'no'),
      'Last error: '+(i.error||'none'), 'Range: '+RANGE+' h · wall mode: '+(wallOn?'on':'off'),
      'Browser: '+navigator.userAgent, 'Time: '+new Date().toISOString()].join('\n');
  }
  function renderSup(){
    var i = supInfo, c = i.contact || {};
    var card = '<div class="sup-card"><div class="org">'+esc(c.name||'Support')+'</div>'+
      (c.email ? '<a href="mailto:'+esc(c.email)+'">'+esc(c.email)+'</a>' : '')+
      (c.phone ? '<a href="tel:'+esc(c.phone.replace(/[^0-9+]/g,''))+'">'+esc(c.phone)+'</a>' : '')+
      (c.url ? '<a href="'+esc(c.url)+'" target="_blank" rel="noopener noreferrer">'+esc(c.url.replace(/^https?:\/\//,''))+'</a>' : '')+'</div>';
    var rows = [['VERSION', i.version], ['INSTALLED', i.installed ? fmtDT(i.installed) : '–']];
    if(i.host){
      rows = rows.concat([['HOST', i.host], ['RUNNING SINCE', fmtDT(i.started)],
        ['OPENSEARCH', String(i.opensearch||'?').toUpperCase()+' · '+i.transport],
        ['NEWEST DATA', i.data_age_s==null ? '–' : ago(i.data_age_s)+' old'],
        ['DATA SOURCES', i.sources_online==null ? '–' : i.sources_online+' / '+i.sources_total+' online'],
        ['CONNECTION', i.tls ? 'HTTPS' : 'Plain HTTP (use on a trusted network or VPN)'],
        ['LAST ERROR', i.error || 'None']]);
    }
    $('#supBody').innerHTML = card +
      '<div><h3 class="tl-title">System</h3><div class="sup-grid">'+rows.map(function(r){ return '<span class="k">'+r[0]+'</span><span class="v">'+esc(r[1])+'</span>'; }).join('')+'</div></div>'+
      (i.host ? '<div class="drawer-foot"><button class="ghost-btn" id="copyDiag">Copy diagnostics</button><span class="hint" id="copyNote">Plain-text summary for a support request · no passwords, no client names</span></div>' : '')+
      '<div class="hint" style="margin-top:18px">UTMStack Observatory '+esc(i.version||'')+(i.copyright?' · '+esc(i.copyright):'')+'</div>';
    var b = $('#copyDiag');
    if(b) b.addEventListener('click', function(){
      copyText(diagText(i)).then(function(){ $('#copyNote').textContent = 'Copied — paste it into your email to support.'; },
                                 function(){ $('#copyNote').textContent = 'Copy was blocked by the browser; select the System details above instead.'; });
    });
  }
  function openSup(){
    overlay.classList.add('on'); supDrawer.classList.add('on'); supDrawer.setAttribute('aria-hidden','false');
    $('#supBody').innerHTML = '<div class="empty">Loading…</div>';
    fetch('/api/support'+(wallOn?'?anon=1':''), {cache:'no-store'}).then(function(r){ return r.json(); })
      .then(function(i){ supInfo = i; renderSup(); $('#closeSup').focus(); })
      .catch(function(e){ $('#supBody').innerHTML = '<div class="empty">Could not load: '+esc(e.message)+'</div>'; });
  }
  function closeSup(){
    supDrawer.classList.remove('on'); supDrawer.setAttribute('aria-hidden','true');
    if(!document.querySelector('.drawer.on')) overlay.classList.remove('on');
    $('#logoBtn').focus();
  }
  $('#logoBtn').addEventListener('click', openSup);
  $('#closeSup').addEventListener('click', closeSup);
  overlay.addEventListener('click', function(){ if(supDrawer.classList.contains('on')) closeSup(); });
  document.addEventListener('keydown', function(e){ if(e.key==='Escape' && supDrawer.classList.contains('on')) closeSup(); });

  /* ---- source filter: header button, "Showing only" strip, picker drawer ---- */
  var srcDrawer = $('#srcDrawer'), srcAvail = null;
  function srcLabel(x){ return x.name + (x.name !== x.id ? ' ('+x.id+')' : ''); }
  function renderSrcState(){
    var n = SRC.length, names = SRC.map(function(x){ return x.name; });
    $('#srcBtn').setAttribute('aria-pressed', String(n > 0));
    // the wall screen hides client names: counts only
    $('#srcBtnText').textContent = !n ? 'All sources' : wallOn ? n+' source'+(n===1?'':'s') : n === 1 ? names[0] : names[0]+' +'+(n-1);
    $('#srcBtn').title = n ? 'Showing only: '+(wallOn ? n+' sources' : names.join(', '))+'. Click to change.' : 'Show only some data sources (firewalls, servers, tenants)';
    $('#srcStrip').hidden = !n;
    $('#srcChips').innerHTML = wallOn ? '<span class="src-chip"><span>'+n+' selected source'+(n===1?'':'s')+'</span></span>' :
      SRC.map(function(x, i){
        return '<span class="src-chip" title="'+esc(srcLabel(x)+(x.type ? ' · '+(MAP_TYPE_LABEL[x.type]||x.type) : ''))+'"><span>'+esc(x.name)+'</span>'+
          '<button type="button" data-i="'+i+'" aria-label="Stop showing only '+esc(x.name)+'">×</button></span>';
      }).join(' ');
  }
  function setSources(list){
    SRC = list.slice(0, 25);
    try { if(SRC.length) localStorage.setItem('obsSources', JSON.stringify(SRC)); else localStorage.removeItem('obsSources'); } catch(e){}
    renderSrcState();
    if(srcDrawer.classList.contains('on')) renderSrcList();
    $('#statusText').textContent = 'Loading '+(SRC.length ? SRC.length+' selected source'+(SRC.length===1?'':'s') : 'all sources')+'…';
    G = null; seenTicks = {}; drawMap(frameT());          // drop the previous selection's arcs right away
    poll(); pollGeo(); pollPorts();
  }
  function renderSrcList(){
    if(!srcAvail){ return; }
    var q = $('#srcSearch').value.trim().toLowerCase(), picked = {};
    SRC.forEach(function(x){ picked[x.id] = true; });
    // selected sources that sent nothing in 24 h still get a row, so they can be unticked
    var rows = srcAvail.concat(SRC.filter(function(x){ return !srcAvail.some(function(a){ return a.id === x.id; }); })
      .map(function(x){ return {id: x.id, name: x.name, type: x.type, events: null}; }));
    rows = rows.filter(function(x){
      return !q || (x.name+' '+x.id+' '+x.type+' '+(MAP_TYPE_LABEL[x.type]||'')).toLowerCase().indexOf(q) >= 0;
    });
    var groups = {};
    rows.forEach(function(x){ (groups[x.type || 'other'] = groups[x.type || 'other'] || []).push(x); });
    var html = Object.keys(groups).sort().map(function(t){
      return '<div class="src-group"><h3>'+esc((MAP_TYPE_LABEL[t] || t).toUpperCase())+'</h3>'+groups[t].map(function(x){
        var on = !!picked[x.id];
        return '<label class="src-row'+(on?' on':'')+'"><input type="checkbox" data-id="'+esc(x.id)+'"'+(on?' checked':'')+'>'+
          '<span class="n" title="'+esc(srcLabel(x))+'">'+esc(srcLabel(x))+'</span>'+
          '<span class="c">'+(x.events == null ? 'no events in 24 h' : compact(x.events)+' · 24 h')+'</span></label>';
      }).join('')+'</div>';
    }).join('');
    $('#srcList').innerHTML = html || '<div class="empty">'+(q ? 'No source matches “'+esc(q)+'”.' : 'No data sources sent logs in the last 24 hours.')+'</div>';
    $('#srcMeta').textContent = SRC.length ? SRC.length+' of '+srcAvail.length+' selected' : 'None ticked: every source is shown';
  }
  function openSrc(){
    overlay.classList.add('on'); srcDrawer.classList.add('on'); srcDrawer.setAttribute('aria-hidden','false');
    $('#srcList').innerHTML = '<div class="empty">Loading…</div>';
    fetch('/api/source-list', {cache:'no-store'}).then(signedIn).then(function(r){ return r.json(); })
      .then(function(d){
        if(d.error) throw new Error(d.error);
        srcAvail = d.sources || [];
        // refresh stored names/types (a firewall renamed since it was picked)
        var byId = {}; srcAvail.forEach(function(x){ byId[x.id] = x; });
        if(SRC.some(function(x){ return byId[x.id] && (byId[x.id].name !== x.name || byId[x.id].type !== x.type); })){
          SRC = SRC.map(function(x){ return byId[x.id] ? {id: x.id, name: byId[x.id].name, type: byId[x.id].type} : x; });
          try { localStorage.setItem('obsSources', JSON.stringify(SRC)); } catch(e){}
          renderSrcState();
        }
        renderSrcList();
      })
      .catch(function(e){ $('#srcList').innerHTML = '<div class="empty">Could not load the source list: '+esc(e.message)+'</div>'; });
    $('#srcSearch').focus();
  }
  function closeSrc(){
    srcDrawer.classList.remove('on'); srcDrawer.setAttribute('aria-hidden','true');
    if(!document.querySelector('.drawer.on')) overlay.classList.remove('on');
    $('#srcBtn').focus();
  }
  $('#srcBtn').addEventListener('click', openSrc);
  $('#closeSrc').addEventListener('click', closeSrc);
  overlay.addEventListener('click', function(){ if(srcDrawer.classList.contains('on')) closeSrc(); });
  document.addEventListener('keydown', function(e){ if(e.key==='Escape' && srcDrawer.classList.contains('on')) closeSrc(); });
  $('#srcSearch').addEventListener('input', renderSrcList);
  $('#srcList').addEventListener('change', function(e){
    var id = e.target && e.target.getAttribute('data-id'); if(id == null) return;
    var x = srcAvail.filter(function(a){ return a.id === id; })[0] || SRC.filter(function(a){ return a.id === id; })[0];
    if(e.target.checked){ if(SRC.length >= 25){ e.target.checked = false; $('#srcMeta').textContent = 'At most 25 sources at once'; return; }
                          setSources(SRC.concat([{id: x.id, name: x.name, type: x.type}])); }
    else setSources(SRC.filter(function(a){ return a.id !== id; }));
  });
  $('#srcAll').addEventListener('click', function(){ setSources([]); });
  $('#srcClear').addEventListener('click', function(){ setSources([]); });
  $('#srcChips').addEventListener('click', function(e){
    var b = e.target.closest && e.target.closest('button[data-i]'); if(!b) return;
    var i = +b.getAttribute('data-i'); setSources(SRC.filter(function(_, k){ return k !== i; }));
  });
  renderSrcState();

  /* ---- settings drawer: dashboard login, API keys, support contact, map home/sites, AI hosts ---- */
  var setDrawer = $('#setDrawer');
  function field(id, label, value, hint, opts){
    opts = opts || {};
    return '<div class="set-field"><label for="'+id+'">'+esc(label)+'</label>'+
      '<input id="'+id+'" type="'+(opts.password?'password':'text')+'" maxlength="'+(opts.maxlength||300)+'"'+
      (opts.placeholder?' placeholder="'+esc(opts.placeholder)+'"':'')+
      (value!=null?' value="'+esc(value)+'"':'')+'>'+
      (hint?'<div class="hint">'+esc(hint)+'</div>':'')+'</div>';
  }
  function sel(id, label, value, options, hint){
    return '<div class="set-field"><label for="'+id+'">'+esc(label)+'</label><select id="'+id+'">'+
      options.map(function(o){ return '<option value="'+esc(o[0])+'"'+(o[0]===(value||'')?' selected':'')+'>'+esc(o[1])+'</option>'; }).join('')+
      '</select>'+(hint?'<div class="hint">'+esc(hint)+'</div>':'')+'</div>';
  }
  function secretPh(on){ return on ? 'Configured — leave blank to keep' : 'Not set'; }
  function noteOn(el, text, kind){ el.textContent = text; el.style.color = kind==='bad' ? '#FF8A95' : kind==='good' ? '#68F5B1' : kind==='warn' ? '#FFC857' : ''; }
  function postJSON(path, body){
    return fetch(path, {method: 'POST', cache: 'no-store', headers: {'Content-Type': 'application/json', 'X-Observatory': '1'},
      body: JSON.stringify(body || {})}).then(signedIn)
      .then(function(r){ return r.json().catch(function(){ return {}; }).then(function(j){ return {status: r.status, j: j}; }); });
  }
  function accountSection(){
    var how = ME.method==='link' ? 'email link' : ME.method==='password' ? 'administrator password' : 'no login (localhost)';
    return '<h3 class="tl-title">Signed in</h3><div class="drawer-foot"><span>'+esc(ME.name)+
      ' <span class="panel-meta">'+esc(ME.role)+' · '+how+'</span></span>'+
      (ME.method!=='none'?'<button class="ghost-btn" id="signOut">Sign out</button>':'')+'</div>';
  }
  function bindAccount(){
    var b = $('#signOut');
    if(b) b.addEventListener('click', function(){
      b.disabled = true;
      postJSON('/auth/logout').then(function(){ location.href = '/login'; }, function(){ location.href = '/login'; });
    });
  }
  function usersSection(u){
    var when = function(t){ return t ? fmtDT(t*1000) : 'never'; };
    return '<h3 class="tl-title">Users <span class="panel-meta">invited people sign in with a one-time link sent by email</span></h3>'+
      (u.link_status ? '<div class="note-card warn"><b>Email sign-in is not working yet:</b> '+esc(u.link_status)+
        '. Set it up under <i>Email for sign-in links</i> below; until then only the administrator password works.</div>' : '')+
      (u.users.length ? '<table class="cmp users"><thead><tr><th>EMAIL</th><th>ROLE</th><th>LAST SIGN-IN</th><th></th></tr></thead><tbody>'+
        u.users.map(function(x){
          var me = x.email === u.me;
          return '<tr><td>'+esc(x.email)+(me?' <small>you</small>':'')+'</td><td><select data-role="'+esc(x.email)+'"'+(me?' disabled':'')+
            ' aria-label="Role of '+esc(x.email)+'">'+['admin','viewer'].map(function(r){ return '<option'+(r===x.role?' selected':'')+'>'+r+'</option>'; }).join('')+
            '</select></td><td>'+when(x.last_login)+'</td><td>'+(me?'':'<button class="ghost-btn" data-rm="'+esc(x.email)+'">Remove</button>')+'</td></tr>';
        }).join('')+'</tbody></table>' : '<div class="hint">No users yet: add the first one below.</div>')+
      '<div class="user-add"><input id="uEmail" type="email" maxlength="254" placeholder="name@example.com" aria-label="Email address to add">'+
      '<select id="uRole" aria-label="Role"><option value="viewer">viewer</option><option value="admin">admin</option></select>'+
      '<label class="hint"><input type="checkbox" id="uInvite" checked> email an invitation</label>'+
      '<button class="ghost-btn" id="uAdd">Add user</button></div><span class="hint" id="uNote"></span>'+
      '<div class="hint">Viewers see every panel, change the layout and create reports. Admins also manage users, settings and <i>Apply fix</i>.</div>';
  }
  function bindUsers(){
    var note = $('#uNote');
    function act(body, done){
      if($('#setCurPass')) body.current_password = $('#setCurPass').value;
      noteOn(note, 'Saving…');
      postJSON('/api/users', body).then(function(res){
        if(res.status !== 200){ noteOn(note, res.j.error || ('Failed (HTTP '+res.status+')'), 'bad'); return; }
        $('#usersBox').innerHTML = usersSection(res.j); bindUsers(); noteOn($('#uNote'), done, 'good');
      }).catch(function(e){ noteOn(note, 'Failed: '+e.message, 'bad'); });
    }
    $('#uAdd').addEventListener('click', function(){
      var email = $('#uEmail').value.trim();
      if(!email){ noteOn(note, 'Enter an email address.', 'warn'); $('#uEmail').focus(); return; }
      act({action: 'add', email: email, role: $('#uRole').value, invite: $('#uInvite').checked}, 'Added '+email+'.');
    });
    $$('#usersBox [data-rm]').forEach(function(b){ b.addEventListener('click', function(){
      if(confirm('Remove '+b.dataset.rm+'? They are signed out at once.')) act({action: 'remove', email: b.dataset.rm}, 'Removed '+b.dataset.rm+'.');
    }); });
    $$('#usersBox [data-role]').forEach(function(x){ x.addEventListener('change', function(){
      act({action: 'add', email: x.dataset.role, role: x.value}, x.dataset.role+' is now '+x.value+'.');
    }); });
  }
  function mailSection(s){
    return '<h3 class="tl-title">Email for sign-in links</h3>'+
      (s.mail_status ? '<div class="hint" style="color:#FFC857">Not ready: '+esc(s.mail_status)+'.</div>' : '<div class="hint" style="color:#68F5B1">Ready to send sign-in links.</div>')+
      field('setPublicUrl', 'Dashboard public address', s.public_url, 'The address people open; sign-in links point here. Example: '+location.origin,
            {maxlength: 300, placeholder: location.origin}) +
      sel('setMailMethod', 'Send email with', s.mail_method, [['', 'Off'], ['smtp', 'SMTP server'], ['graph', 'Microsoft 365 (Graph API)']]) +
      field('setMailFrom', 'Sender address', s.mail_from, 'For Microsoft 365, the mailbox the app sends as (a shared mailbox works).', {maxlength: 254}) +
      '<div id="smtpBox">'+
        field('setSmtpHost', 'SMTP server', s.smtp_host, 'e.g. smtp.office365.com, smtp.gmail.com, email-smtp.us-east-1.amazonaws.com', {maxlength: 253}) +
        field('setSmtpPort', 'Port', s.smtp_port, 'Blank: 587 for STARTTLS, 465 for TLS, 25 for none.', {maxlength: 5}) +
        sel('setSmtpSec', 'Encryption', s.smtp_security, [['starttls', 'STARTTLS (port 587)'], ['tls', 'TLS (port 465)'], ['none', 'None (internal relay only)']]) +
        field('setSmtpUser', 'SMTP username', s.smtp_user, 'Blank for a relay that needs no login.', {maxlength: 254}) +
        field('setSmtpPass', 'SMTP password', null, null, {password: true, maxlength: 500, placeholder: secretPh(s.smtp_pass_configured)}) +
      '</div><div id="graphBox">'+
        field('setGraphTenant', 'Tenant ID', s.graph_tenant, 'Entra ID → App registrations → your app. Needs the Mail.Send application permission, admin-consented.', {maxlength: 100}) +
        field('setGraphClient', 'Client (application) ID', s.graph_client_id, null, {maxlength: 100}) +
        field('setGraphSecret', 'Client secret', null, null, {password: true, maxlength: 500, placeholder: secretPh(s.graph_secret_configured)}) +
      '</div>'+
      '<div class="drawer-foot"><input id="mailTestTo" type="email" maxlength="254" placeholder="'+esc(ME.email||'you@example.com')+'" aria-label="Send the test email to">'+
      '<button class="ghost-btn" id="mailTest">Send test email</button><span class="hint" id="mailNote">Save first; the test uses the saved settings.</span></div>';
  }
  function bindMail(){
    function method(){ var m = $('#setMailMethod').value; $('#smtpBox').hidden = m !== 'smtp'; $('#graphBox').hidden = m !== 'graph'; }
    $('#setMailMethod').addEventListener('change', method); method();
    $('#mailTest').addEventListener('click', function(){
      var note = $('#mailNote'); noteOn(note, 'Sending…');
      postJSON('/api/mail/test', {to: $('#mailTestTo').value.trim()}).then(function(res){
        if(res.status === 200 && res.j.ok) noteOn(note, 'Sent to '+res.j.to+'. Check that inbox (and its junk folder).', 'good');
        else noteOn(note, res.j.error || ('Failed (HTTP '+res.status+')'), 'bad');
      }).catch(function(e){ noteOn(note, 'Failed: '+e.message, 'bad'); });
    });
  }
  var MAIL_FIELDS = [['setPublicUrl', 'public_url'], ['setMailMethod', 'mail_method'], ['setMailFrom', 'mail_from'], ['setSmtpHost', 'smtp_host'],
                     ['setSmtpPort', 'smtp_port'], ['setSmtpSec', 'smtp_security'], ['setSmtpUser', 'smtp_user'],
                     ['setGraphTenant', 'graph_tenant'], ['setGraphClient', 'graph_client_id']];
  function renderSettings(s, users){
    var pwConfirm = ME.method === 'password';
    var html = accountSection() + '<div id="usersBox">'+usersSection(users)+'</div>' + mailSection(s) +
      '<h3 class="tl-title">Administrator password <span class="panel-meta">the break-glass login, always an admin</span></h3>'+
      field('setUser', 'Username', s.dash_user, null, {maxlength:64}) +
      field('setPass', 'New password', null, 'At least 12 characters. Leave blank to keep the current one.',
            {password:true, maxlength:200, placeholder:'Leave blank to keep current'}) +
      '<h3 class="tl-title">API keys <span class="panel-meta">for live reputation lookups on alert IPs</span></h3>'+
      field('setAbuse', 'AbuseIPDB key', null, null, {password:true, maxlength:200, placeholder: secretPh(s.abuseipdb_key_configured)}) +
      field('setVt', 'VirusTotal key', null, null, {password:true, maxlength:200, placeholder: secretPh(s.virustotal_key_configured)}) +
      '<h3 class="tl-title">Support contact</h3>'+
      field('setSupport', 'Shown when the logo is clicked', s.support, 'Format: Name|email|phone|url', {maxlength:2000}) +
      '<h3 class="tl-title">Live map</h3>'+
      field('setHome', 'Home location', s.home, "Format: lat,lon[,City] — used when a firewall's own location isn't known", {maxlength:200}) +
      field('setSites', 'Site pins', s.sites, 'Format: Name=lat,lon,City;1.2.3.4=lat,lon;...', {maxlength:2000}) +
      '<h3 class="tl-title">AI traffic</h3>'+
      field('setAi', 'AI hosts', s.ai_hosts, 'Format: name=ip,name=ip — needs Sophos XG firewall logs in UTMStack', {maxlength:2000}) +
      '<h3 class="tl-title">Reports</h3>'+
      field('setReportHour', 'Daily report hour (UTC)', s.report_hour, 'A number 0–23. Leave blank for on-demand only (Reports button, top right).', {maxlength:2}) +
      '<h3 class="tl-title">Dashboard layout</h3>'+
      '<div class="drawer-foot"><button class="ghost-btn" id="setOpenLayout">Open layout editor</button>'+
      '<span class="hint">Widgets, screens and the wall rotation have their own editor (Edit, top right of the tab bar).</span></div>'+
      '<h3 class="tl-title">Confirm</h3>'+
      (pwConfirm ? field('setCurPass', 'Current password', null, 'Needed only when you change users, the login, email, an API key or the support contact.',
            {password:true, maxlength:200, placeholder:'Your current dashboard password'}) :
        ME.method === 'link' ? '<div class="hint">Changes to users, the login, email, API keys or the support contact need a sign-in from the last '+
            (ME.reauth_minutes||15)+' minutes. If a save is refused, sign out and sign in with a new link.</div>' : '') +
      '<div class="drawer-foot"><button class="ctl" id="setSave" aria-pressed="true">Save</button><span class="hint" id="setNote"></span></div>';
    $('#setBody').innerHTML = html;
    bindAccount(); bindUsers(); bindMail();
    $('#setOpenLayout').addEventListener('click', function(){ closeSettings(); setEdit(true); });
    $('#setSave').addEventListener('click', function(){
      var patch = {home: $('#setHome').value.trim(), sites: $('#setSites').value.trim(), ai_hosts: $('#setAi').value.trim(),
                   report_hour: $('#setReportHour').value.trim()};
      if($('#setUser').value.trim() !== (s.dash_user||'')) patch.dash_user = $('#setUser').value.trim();
      if($('#setSupport').value.trim() !== (s.support||'')) patch.support = $('#setSupport').value.trim();
      MAIL_FIELDS.forEach(function(f){ var v = $('#'+f[0]).value.trim(); if(v !== (s[f[1]]||'')) patch[f[1]] = v; });
      if($('#setCurPass') && $('#setCurPass').value) patch.current_password = $('#setCurPass').value;
      if($('#setPass').value) patch.dash_pass = $('#setPass').value;
      if($('#setAbuse').value) patch.abuseipdb_key = $('#setAbuse').value;
      if($('#setVt').value) patch.virustotal_key = $('#setVt').value;
      if($('#setSmtpPass').value) patch.smtp_pass = $('#setSmtpPass').value;
      if($('#setGraphSecret').value) patch.graph_secret = $('#setGraphSecret').value;
      var credsChanged = ME.method === 'password' && (patch.dash_pass || patch.dash_user !== undefined);
      var note = $('#setNote'); noteOn(note, 'Saving…');
      saveSettings(patch).then(function(res){
        if(res.status !== 200){ noteOn(note, res.j.error || ('Save failed (HTTP '+res.status+')'), 'bad'); return; }
        if(credsChanged){
          noteOn(note, 'Saved. Reloading to sign in with the new login…', 'good');
          setTimeout(function(){ location.reload(); }, 1200);
          return;
        }
        openSettings('Saved.');                   // re-read: the email status and users depend on what was saved
      }).catch(function(e){ noteOn(note, 'Save failed: '+e.message, 'bad'); });
    });
  }
  function saveSettings(patch){
    return fetch('/api/settings', {method: 'PUT', cache: 'no-store',
      headers: {'Content-Type': 'application/json', 'X-Observatory': '1'}, body: JSON.stringify(patch)}).then(signedIn)
      .then(function(r){ return r.json().then(function(j){ return {status: r.status, j: j}; }); });
  }
  function openSettings(saved){
    overlay.classList.add('on'); setDrawer.classList.add('on'); setDrawer.setAttribute('aria-hidden','false');
    if(!saved) $('#setBody').innerHTML = '<div class="empty">Loading…</div>';
    fetch('/api/me', {cache:'no-store'}).then(signedIn).then(function(r){ return r.json(); }).then(function(m){
      ME = m;
      if(ME.role !== 'admin'){
        $('#setBody').innerHTML = accountSection() +
          '<div class="hint">You are a viewer: an admin manages users and settings. You can still change the layout (Edit, top right of the tab bar) and create reports.</div>';
        bindAccount(); $('#closeSet').focus(); return;
      }
      var get = function(p){ return fetch(p, {cache:'no-store'}).then(signedIn).then(function(r){ return r.json(); }); };
      return Promise.all([get('/api/settings'), get('/api/users')]).then(function(r){
        renderSettings(r[0], r[1]);
        if(typeof saved === 'string') noteOn($('#setNote'), saved, 'good');
        else $('#closeSet').focus();
      });
    }).catch(function(e){ $('#setBody').innerHTML = '<div class="empty">Could not load: '+esc(e.message)+'</div>'; });
  }
  function closeSettings(){
    setDrawer.classList.remove('on'); setDrawer.setAttribute('aria-hidden','true');
    if(!document.querySelector('.drawer.on')) overlay.classList.remove('on');
    $('#settingsBtn').focus();
  }
  $('#settingsBtn').addEventListener('click', function(){ openSettings(); });
  $('#closeSet').addEventListener('click', closeSettings);
  overlay.addEventListener('click', function(){ if(setDrawer.classList.contains('on')) closeSettings(); });
  document.addEventListener('keydown', function(e){ if(e.key==='Escape' && setDrawer.classList.contains('on')) closeSettings(); });

  /* ---- reports drawer: PDF/HTML downloads, generate on demand ---- */
  var repDrawer = $('#repDrawer');
  function fmtBytes(n){
    if(n>=1e9) return (n/1e9).toFixed(1)+' GB'; if(n>=1e6) return (n/1e6).toFixed(1)+' MB';
    if(n>=1e3) return (n/1e3).toFixed(0)+' KB'; return n+' B';
  }
  function renderReports(d){
    var hourNote = d.report_hour!=null ? ('Scheduled daily at '+String(d.report_hour).padStart(2,'0')+':00 UTC.') : 'No daily schedule set.';
    var html = '<div class="drawer-foot"><button class="ctl" id="repGenerate">Generate now</button>'+
      '<span class="hint">'+esc(hourNote)+' Set it in Settings.</span></div>';
    html += d.reports.length ? '<table class="cmp"><thead><tr><th>Generated</th><th>PDF</th><th>HTML</th></tr></thead><tbody>'+
      d.reports.map(function(r){
        return '<tr><td>'+fmtDT(r.generated_at)+'</td>'+
          '<td>'+(r.pdf?'<a href="/api/reports/'+encodeURIComponent(r.pdf.name)+'">Download ('+fmtBytes(r.pdf.bytes)+')</a>':'–')+'</td>'+
          '<td>'+(r.html?'<a href="/api/reports/'+encodeURIComponent(r.html.name)+'">Download ('+fmtBytes(r.html.bytes)+')</a>':'–')+'</td></tr>';
      }).join('')+'</tbody></table>' : '<div class="empty">No reports yet.</div>';
    $('#repBody').innerHTML = html;
    $('#repGenerate').addEventListener('click', function(){
      var btn = $('#repGenerate'); btn.disabled = true; btn.textContent = 'Generating…';
      fetch('/api/reports/generate', {method: 'POST', cache: 'no-store',
        headers: {'Content-Type': 'application/json', 'X-Observatory': '1'}})
        .then(function(r){ return r.json().then(function(j){ return {status: r.status, j: j}; }); })
        .then(function(res){
          if(res.status !== 200){ btn.disabled = false; btn.textContent = 'Generate now'; alert('Generate failed: '+(res.j.error||res.status)); return; }
          loadReports();
        }).catch(function(e){ btn.disabled = false; btn.textContent = 'Generate now'; alert('Generate failed: '+e.message); });
    });
  }
  function loadReports(){
    $('#repBody').innerHTML = '<div class="empty">Loading…</div>';
    fetch('/api/reports', {cache: 'no-store'}).then(function(r){ return r.json(); })
      .then(renderReports)
      .catch(function(e){ $('#repBody').innerHTML = '<div class="empty">Could not load: '+esc(e.message)+'</div>'; });
  }
  function openReports(){
    overlay.classList.add('on'); repDrawer.classList.add('on'); repDrawer.setAttribute('aria-hidden','false');
    loadReports();
    setTimeout(function(){ $('#closeRep').focus(); }, 60);
  }
  function closeReports(){
    repDrawer.classList.remove('on'); repDrawer.setAttribute('aria-hidden','true');
    if(!document.querySelector('.drawer.on')) overlay.classList.remove('on');
    $('#reportsBtn').focus();
  }
  $('#reportsBtn').addEventListener('click', openReports);
  $('#closeRep').addEventListener('click', closeReports);
  overlay.addEventListener('click', function(){ if(repDrawer.classList.contains('on')) closeReports(); });
  document.addEventListener('keydown', function(e){ if(e.key==='Escape' && repDrawer.classList.contains('on')) closeReports(); });

  /* ---- entry points: KPI cards, alert table, storage footer ---- */
  $('#kpiBand').addEventListener('click', function(e){
    var k = e.target.closest('[data-open]'); if(!k) return;
    var o = k.dataset.open;
    if(o==='sources') openDig({name:'sources', tab:'source'}, true);
    else if(o==='types') openDig({name:'sources', tab:'type'}, true);
    else if(o==='alerts') openDig({name:'alerts'}, true);
    else if(o==='lag') openDig({name:'lag'}, true);
  });
  $('#kpiBand').addEventListener('keydown', function(e){
    if((e.key==='Enter'||e.key===' ') && e.target.matches('[data-open]')){ e.preventDefault(); e.target.click(); }
  });
  $('#alertBody').addEventListener('click', function(e){
    var tr = e.target.closest('tr[data-id]'); if(tr) openDig({name:'alert', id:tr.dataset.id}, true);
  });
  $('#alertBody').addEventListener('keydown', function(e){
    if((e.key==='Enter'||e.key===' ') && e.target.matches('tr[data-id]')){ e.preventDefault(); e.target.click(); }
  });
  $('#top5Body').addEventListener('click', function(e){
    var row = e.target.closest('[data-rule]'); if(row) openDig({name:'alerts', rule:row.dataset.rule, source:''}, true);
  });
  $('#top5Body').addEventListener('keydown', function(e){
    if((e.key==='Enter'||e.key===' ') && e.target.matches('[data-rule]')){ e.preventDefault(); e.target.click(); }
  });
  $('#allAlertsBtn').addEventListener('click', function(){ openDig({name:'alerts'}, true); });
  $('#envBadge').addEventListener('click', function(){ openDig({name:'cluster'}, true); });
  $('#storeFoot').addEventListener('click', function(){ openDig({name:'storage'}, true); });
  $('#storeFoot').addEventListener('keydown', function(e){ if(e.key==='Enter'||e.key===' '){ e.preventDefault(); openDig({name:'storage'}, true); } });

  /* ---- storage footer under the Alert Rules / AI Traffic box ---- */
  function renderStoreFoot(){
    var el = $('#storeFoot');
    if(!S || !S.days || !S.days.length){ el.innerHTML = '<span class="panel-meta">STORAGE · collecting…</span>'; return; }
    var t = S.days[S.days.length-1];
    el.innerHTML =
      '<div class="sf-head"><span>STORAGE · '+esc(t.day)+' UTC</span><span class="hint">'+(t.day===S.today_utc?'today so far':'final')+' · click for 30-day history</span></div>'+
      '<div class="sf-grid"><div><div class="k">ALERTS</div><div class="v">'+fmtBytes(t.alerts)+'</div><div class="s">'+nf0.format(t.alert_docs)+' · '+(t.per_alert?fmtBytes(t.per_alert):'–')+' each</div></div>'+
      '<div><div class="k">LOGS</div><div class="v">'+fmtBytes(t.logs)+'</div><div class="s">'+compact(t.log_docs)+' events</div></div>'+
      '<div><div class="k">TOTAL</div><div class="v" style="color:#35E7FF">'+fmtBytes(t.total)+'</div><div class="s">'+fmtBytes(S.disk_free)+' free'+(S.days_left!=null?' · ≈'+Math.round(S.days_left)+' d':'')+'</div></div></div>';
  }
  function loadStorage(){ api('/api/storage').then(function(d){ S = d; renderStoreFoot(); }).catch(function(){}); }
  loadStorage(); setInterval(loadStorage, 60000);

  /* ---------- header controls ---------- */
  $('#liveBtn').addEventListener('click', function(){
    liveOn = !liveOn; this.setAttribute('aria-pressed', String(liveOn));
    $('#liveBtnText').textContent = liveOn ? 'Live' : 'Paused';
    document.body.classList.toggle('paused', !liveOn);
    if(liveOn){                                     // resume: show everything collected while paused, then carry on live
      var d = pendingD, g = pendingG; pendingD = pendingG = null; heldUpdates = 0;
      if(g){ G = g; renderMapSide(); }
      renderPorts();
      if(d) apply(d); else if(D) apply(D);
      poll(); pollGeo();
    } else {
      pauseT = performance.now(); $('#liveDot').className = 'live-dot paused'; pausedStatus();
    }
  });
  $('#fsBtn').addEventListener('click', function(){
    if(!document.fullscreenElement && document.documentElement.requestFullscreen) document.documentElement.requestFullscreen();
    else if(document.exitFullscreen) document.exitFullscreen();
  });

  /* ---------- resize ---------- */
  var rt;
  function redrawAll(){ renderTrend(); renderSpark(); renderDonut(); if(drawer.classList.contains('on')) renderDetail(); }
  window.addEventListener('resize', function(){ clearTimeout(rt); rt = setTimeout(redrawAll, 90); });
  if(window.ResizeObserver) new ResizeObserver(function(){ clearTimeout(rt); rt = setTimeout(redrawAll, 90); }).observe($('.shell'));
  document.addEventListener('visibilitychange', function(){ if(!document.hidden) setTimeout(redrawAll, 60); });
})();
