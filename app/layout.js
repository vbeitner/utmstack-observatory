/* UTMStack Observatory — pure layout arithmetic for the widget board (no DOM).
   Items are {type, x, y, w, h} on a 12-column grid; y/h are 40 px row units. Every function returns new
   objects and never mutates its arguments. Loaded in the browser as window.ObsLayout, in Node via require(). */
(function (root) {
  'use strict';
  var COLS = 12, MAX_SCREENS = 12;
  var WIDGETS = {   // keep minW/minH in step with WIDGET_TYPES in app/layout_store.py
    kpis:      {title: 'Key metrics',             desc: 'Data sources, events, alerts and ingest lag.',            minW: 6, minH: 4, w: 12, h: 4,  wallSafe: true},
    map:       {title: 'Live firewall map',       desc: 'Animated connections from every firewall to the world.',  minW: 5, minH: 8, w: 8,  h: 14, wallSafe: 'anon'},
    mapside:   {title: 'Map stats',               desc: 'Connection rate, top countries and latest blocked inbound.', minW: 3, minH: 8, w: 4, h: 14, wallSafe: 'anon'},
    donut:     {title: 'Event source distribution', desc: 'Share of events by data type.',                         minW: 3, minH: 5, w: 4,  h: 6,  wallSafe: true},
    rules:     {title: 'Alert rules / AI traffic', desc: 'Top alert rules, or traffic to the AI servers.',         minW: 3, minH: 6, w: 4,  h: 8,  wallSafe: true},
    trend:     {title: 'Real-time event trend',   desc: 'Events and alerts per minute, last 30 minutes.',          minW: 4, minH: 5, w: 12, h: 7,  wallSafe: true},
    rate:      {title: 'Event rate',              desc: 'Events per second with a 60-minute sparkline.',           minW: 4, minH: 2, w: 12, h: 2,  wallSafe: true},
    alerts:    {title: 'Latest alerts',           desc: 'Newest alerts with severity and source.',                 minW: 4, minH: 5, w: 7,  h: 9,  wallSafe: false},
    resources: {title: 'Resource utilisation',    desc: 'CPU, memory and disk of the UTMStack host.',              minW: 3, minH: 5, w: 5,  h: 9,  wallSafe: true}
  };

  function copy(items) { return items.map(function (i) { return {type: i.type, x: i.x, y: i.y, w: i.w, h: i.h}; }); }
  function clampItem(i) {
    var m = WIDGETS[i.type] || {minW: 1, minH: 1};
    i.w = Math.max(m.minW, Math.min(COLS, Math.round(i.w)));
    i.h = Math.max(m.minH, Math.min(40, Math.round(i.h)));
    i.x = Math.max(0, Math.min(COLS - i.w, Math.round(i.x)));
    i.y = Math.max(0, Math.round(i.y));
    return i;
  }
  function collides(a, b) { return a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h; }
  function readingOrder(items) { return copy(items).sort(function (a, b) { return a.y - b.y || a.x - b.x; }); }

  function compact(items) {
    // Float every item as high as it can go, in reading order, without overlapping the ones already placed.
    var placed = [];
    readingOrder(items).forEach(function (it) {
      it.y = 0;
      while (placed.some(function (p) { return collides(p, it); })) it.y++;
      placed.push(it);
    });
    var byType = {}; placed.forEach(function (p) { byType[p.type] = p; });
    return items.map(function (i) { return byType[i.type]; });   // keep the caller's array order
  }
  function resolve(items, moved) {
    // The moved item wins its spot; anything it overlaps is pushed down below it (cascading), then compact.
    var out = copy(items), m = out[moved], changed = true;
    var others = out.filter(function (_, k) { return k !== moved; }).sort(function (a, b) { return a.y - b.y || a.x - b.x; });
    while (changed) {
      changed = false;
      others.forEach(function (o) {
        var blockers = [m].concat(others.filter(function (p) { return p !== o && p.y < o.y; }));
        blockers.forEach(function (b) { if (collides(b, o)) { o.y = b.y + b.h; changed = true; } });
      });
    }
    // compact everything except that the moved item may not float above its target row by more than gaps allow
    return compact(out);
  }
  function move(items, i, x, y) {
    var out = copy(items), orig = out[i].y;
    out[i].x = x; out[i].y = y; clampItem(out[i]);
    if (out[i].y > orig) {
      // Moving down into a widget that sat below: jump past it, so compaction swaps them instead of floating the
      // moved widget straight back to where it started.
      var below = out.filter(function (o, k) { return k !== i && o.y > orig && collides(out[i], o); });
      if (below.length) out[i].y = Math.max.apply(null, below.map(function (o) { return o.y + o.h; }));
    }
    return resolve(out, i);
  }
  function resize(items, i, w, h) { var out = copy(items); out[i].w = w; out[i].h = h; clampItem(out[i]); return resolve(out, i); }
  function addWidget(items, type) {
    if (!WIDGETS[type]) throw new Error('unknown widget ' + type);
    if (items.some(function (i) { return i.type === type; })) throw new Error(type + ' is already on this screen');
    var bottom = items.reduce(function (m, i) { return Math.max(m, i.y + i.h); }, 0);
    return copy(items).concat([clampItem({type: type, x: 0, y: bottom, w: WIDGETS[type].w, h: WIDGETS[type].h})]);
  }
  function removeWidget(items, i) { return compact(copy(items).filter(function (_, k) { return k !== i; })); }

  function num(v, d) { v = Number(v); return Number.isFinite(v) ? v : d; }
  function sanitizeLayout(layout) {
    // Accepts anything (an old, newer or corrupt personal layout from localStorage) and returns a usable layout,
    // notes for whatever was dropped, and empty:true when no screen survived.
    var notes = [], ids = [];
    var raw = (layout && Array.isArray(layout.screens)) ? layout.screens : [];
    var screens = raw.filter(function (s) { return s && typeof s === 'object'; }).map(function (s, n) {
      var name = String(s.name || '').trim().slice(0, 40) || ('Screen ' + (n + 1));
      var id = typeof s.id === 'string' && /^[a-z0-9-]{1,24}$/.test(s.id) && ids.indexOf(s.id) < 0 ? s.id : slug(name, ids);
      ids.push(id);
      var seen = {};
      var widgets = (Array.isArray(s.widgets) ? s.widgets : []).filter(function (w) {
        if (!w || !WIDGETS[w.type]) { notes.push('Dropped unknown widget "' + (w && w.type) + '" on screen "' + name + '".'); return false; }
        if (seen[w.type]) return false;
        seen[w.type] = 1; return true;
      }).map(function (w) {
        var d = WIDGETS[w.type];
        return clampItem({type: w.type, x: num(w.x, 0), y: num(w.y, 0), w: num(w.w, d.w), h: num(w.h, d.h)});
      });
      return {id: id, name: name, wall: !!s.wall, widgets: compact(widgets)};
    });
    return {layout: {schema: 1, version: layout && layout.version || 0, saved_at: layout && layout.saved_at, screens: screens},
            notes: notes, empty: screens.length === 0};
  }
  function isPersonalStale(personal, shared) { return !!personal && personal.baseVersion !== shared.version; }

  function cloneLayout(l) { return JSON.parse(JSON.stringify(l)); }
  function slug(name, taken) {
    var base = String(name).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 20) || 'screen', id = base, n = 2;
    while (taken.indexOf(id) >= 0) id = base + '-' + (n++);
    return id;
  }
  function addScreen(layout, name) {
    var l = cloneLayout(layout);
    if (l.screens.length >= MAX_SCREENS) throw new Error('at most ' + MAX_SCREENS + ' screens');
    name = String(name || 'New screen').trim().slice(0, 40) || 'New screen';
    l.screens.push({id: slug(name, l.screens.map(function (s) { return s.id; })), name: name, wall: false, widgets: []});
    return l;
  }
  function renameScreen(layout, id, name) {
    var l = cloneLayout(layout); name = String(name || '').trim().slice(0, 40);
    l.screens.forEach(function (s) { if (s.id === id && name) s.name = name; });
    return l;
  }
  function moveScreen(layout, id, dir) {
    var l = cloneLayout(layout), i = l.screens.findIndex(function (s) { return s.id === id; }), j = i + dir;
    if (i < 0 || j < 0 || j >= l.screens.length) return l;
    var t = l.screens[i]; l.screens[i] = l.screens[j]; l.screens[j] = t;
    return l;
  }
  function removeScreen(layout, id) {
    if (layout.screens.length <= 1) throw new Error('cannot delete the last screen');
    var l = cloneLayout(layout); l.screens = l.screens.filter(function (s) { return s.id !== id; });
    return l;
  }

  var api = {COLS: COLS, WIDGETS: WIDGETS, collides: collides, compact: compact, resolve: resolve, move: move, resize: resize,
             addWidget: addWidget, removeWidget: removeWidget, readingOrder: readingOrder, sanitizeLayout: sanitizeLayout,
             isPersonalStale: isPersonalStale, addScreen: addScreen, renameScreen: renameScreen, moveScreen: moveScreen,
             removeScreen: removeScreen};
  if (typeof module === 'object' && module.exports) module.exports = api; else root.ObsLayout = api;
})(this);
