# Movable Widgets and Named Screens Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the fixed Observatory page into a board of movable and resizable widgets on named screens. The board has a shared layout saved on the server and personal per-browser overrides. It ships with the existing eight panels only; the new widgets get their own plan.

**Architecture:** Each existing panel becomes a *widget*: its DOM element gets a `data-widget` type and the board places it with CSS Grid. Every widget type occurs at most once per screen, and only one screen is visible at a time. So switching screens just shows, hides and positions the existing elements, and the current render functions, which look up fixed element ids, keep working unchanged.

Pure layout arithmetic (collisions, push-down, compaction, move, resize) lives in a small `app/layout.js`, tested with `node --test`. The server stores the shared layout in `/data/layout.json` and validates it in a new `app/layout_store.py`.

**Tech Stack:** Python 3.12 standard library (server), vanilla ES5-style JavaScript (browser, no libraries), `unittest` and `node --test` for tests.

**Spec:** `docs/specs/2026-10-17-custom-layouts-design.md`, §3.1 (widgets), §3.2 (grid, edit mode, screens), §3.3 (saving). §3.4 (new endpoints) and §3.5 (support, already shipped in 1.1.2) are not part of this plan.

## Global Constraints

- Python standard library only on the server; no JS libraries or CDNs in the browser; nothing calls a third party.
- CSP stays strict. `script-src` is widened only from `'unsafe-inline'` to `'self' 'unsafe-inline'`, so that `/layout.js` can load.
- Grid: 12 columns, 40 px row unit, 12 px gap. Below 1100 px wide the board is a single column in reading order and editing is disabled.
- Limits: at most 12 screens and 20 widgets per screen; each widget type at most once per screen; a stored layout under 64 KB.
- Layout JSON carries `schema: 1`. Unknown widget types are dropped with a visible note, never a crash.
- `PUT /api/layout` requires `Content-Type: application/json`, header `X-Observatory: 1`, and, when an `Origin` header is present, an origin whose host equals the `Host` header.
- Wall mode always uses the shared layout and never shows client names. Widgets with `wallSafe: false` render a placeholder there.
- `VERSION` and `server.py` `VERSION` must match (an existing test enforces it). Every release gets a `RELEASE-NOTES.md` entry.
- The Dockerfile copies `app/` wholesale, so new files under `app/` ship automatically.

## Review Focus

1. **A stored layout from an older or newer build**, containing an unknown widget type or a missing screen field. It must load with that widget dropped and a note shown. Covered by tests in Task 1 (server) and Task 3 (browser `sanitizeLayout`).
2. **A personal layout saved before the shared layout changed.** The user must be told their view differs, and **Reset to shared** must restore it. Covered by the Task 6 browser check plus the `isPersonalStale` unit test.
3. **Dragging a widget onto another, or past the right edge.** The other widget moves down, nothing overlaps, and width is clamped to 12 columns. Covered by `move` and `resolve` tests in Task 2.
4. **Deleting the last screen, or the screen currently in wall rotation.** At least one screen must remain, and wall rotation must skip deleted screens. Covered by Task 5 tests on `removeScreen` and the Task 4 rotation check.
5. **A narrow window (under 1100 px) while in edit mode.** Editing turns off and the widgets stack in reading order without overlap. Covered by the Task 3 responsive check and the `readingOrder` test.

---

## File Structure

| File | Responsibility |
|---|---|
| `app/layout_store.py` (new) | Widget type catalogue (server copy), `default_layout()`, `validate_layout()`, atomic load/save of `/data/layout.json`, `csrf_ok()`. No HTTP. |
| `app/server.py` (modify) | Routes: `GET /api/layout`, `PUT /api/layout` (new `do_PUT`), serve `/layout.js`; CSP `script-src 'self' 'unsafe-inline'`. |
| `app/layout.js` (new) | Pure layout functions plus `WIDGETS` catalogue (browser copy), exported as `window.ObsLayout` and as a CommonJS module for tests. |
| `app/index.html` (modify) | Board markup (tab bar plus `.board`), widget wrappers, screen switching, edit mode UI, wall rotation over screens, personal and shared persistence. |
| `tests/test_layout_store.py` (new) | Server validation, defaults, CSRF checks, persistence. |
| `tests/layout.test.js` (new) | `node --test` for `app/layout.js`. |

---

### Task 1: Server layout store and API

**Files:**
- Create: `app/layout_store.py`
- Modify: `app/server.py` (CSP header in `Handler.send`, routes in `do_GET`, new `do_PUT`)
- Test: `tests/test_layout_store.py`

**Interfaces:**
- Produces:
  - `layout_store.WIDGET_TYPES: dict[str, dict]` (keys: `kpis map donut rules trend rate alerts resources`; values `{"min_w": int, "min_h": int}`)
  - `layout_store.default_layout() -> dict`
  - `layout_store.validate_layout(obj) -> tuple[dict, list[str]]` (the cleaned layout and notes about dropped items; raises `ValueError` on structural errors)
  - `layout_store.load(data_dir) -> dict`
  - `layout_store.save(data_dir, layout) -> dict` (stores with `version` incremented and `saved_at` set, returns the stored object)
  - `layout_store.csrf_ok(headers) -> bool`
  - HTTP: `GET /api/layout` returns `{"layout": {...}, "notes": [...]}`; `PUT /api/layout` with a body `{"layout": {...}, "base_version": int}` returns `{"layout": {...}}`, or `409 {"error":"conflict","layout":{current}}` when `base_version` is not the stored version, or `400 {"error": "..."}`, or `403 {"error":"forbidden"}`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_layout_store.py
"""Shared layout storage and validation. Run: python3 -m unittest discover -s tests -v"""
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "app"))
import layout_store as ls  # noqa: E402


def one_screen(widgets, **extra):
    s = {"id": "main", "name": "Main", "wall": False, "widgets": widgets}
    s.update(extra)
    return {"schema": 1, "version": 0, "screens": [s]}


class Defaults(unittest.TestCase):
    def test_default_layout_is_valid_and_has_the_three_screens(self):
        lay, notes = ls.validate_layout(ls.default_layout())
        self.assertEqual(notes, [])
        self.assertEqual([s["name"] for s in lay["screens"]], ["Overview", "Live map", "Activity"])
        self.assertEqual([s["wall"] for s in lay["screens"]], [False, True, True])
        self.assertEqual({w["type"] for w in lay["screens"][0]["widgets"]}, set(ls.WIDGET_TYPES))


class Validation(unittest.TestCase):
    def test_unknown_widget_type_is_dropped_with_a_note(self):
        lay, notes = ls.validate_layout(one_screen([{"type": "map", "x": 0, "y": 0, "w": 6, "h": 8},
                                                    {"type": "future-widget", "x": 6, "y": 0, "w": 6, "h": 8}]))
        self.assertEqual([w["type"] for w in lay["screens"][0]["widgets"]], ["map"])
        self.assertTrue(any("future-widget" in n for n in notes))

    def test_geometry_is_clamped_to_the_grid(self):
        lay, _ = ls.validate_layout(one_screen([{"type": "map", "x": 10, "y": -3, "w": 9, "h": 999}]))
        w = lay["screens"][0]["widgets"][0]
        self.assertEqual((w["x"], w["y"], w["w"], w["h"]), (3, 0, 9, 40))   # x pulled left so x+w <= 12

    def test_minimum_sizes_are_enforced(self):
        lay, _ = ls.validate_layout(one_screen([{"type": "map", "x": 0, "y": 0, "w": 1, "h": 1}]))
        w = lay["screens"][0]["widgets"][0]
        self.assertEqual((w["w"], w["h"]), (ls.WIDGET_TYPES["map"]["min_w"], ls.WIDGET_TYPES["map"]["min_h"]))

    def test_duplicate_type_on_one_screen_keeps_the_first(self):
        lay, notes = ls.validate_layout(one_screen([{"type": "map", "x": 0, "y": 0, "w": 6, "h": 8},
                                                    {"type": "map", "x": 6, "y": 0, "w": 6, "h": 8}]))
        self.assertEqual(len(lay["screens"][0]["widgets"]), 1)
        self.assertTrue(notes)

    def test_missing_fields_get_defaults_and_bad_names_are_cleaned(self):
        lay, _ = ls.validate_layout({"schema": 1, "screens": [{"name": "  <b>Ops</b>  ", "widgets": []}]})
        s = lay["screens"][0]
        self.assertEqual(s["name"], "<b>Ops</b>")          # trimmed; escaping is the browser's job
        self.assertRegex(s["id"], r"^[a-z0-9-]{1,24}$")
        self.assertIs(s["wall"], False)
        self.assertEqual(lay["version"], 0)

    def test_structural_errors_raise(self):
        for bad in (None, [], {"schema": 2, "screens": []}, {"schema": 1, "screens": []},
                    {"schema": 1, "screens": [{"widgets": "x"}]},
                    {"schema": 1, "screens": [one_screen([])["screens"][0]] * 13}):
            with self.assertRaises(ValueError, msg=repr(bad)[:60]):
                ls.validate_layout(bad)

    def test_too_many_widgets_raise(self):
        many = [{"type": t, "x": 0, "y": i, "w": 12, "h": 4} for i, t in enumerate(list(ls.WIDGET_TYPES) * 3)]
        with self.assertRaises(ValueError):
            ls.validate_layout(one_screen(many))


class Storage(unittest.TestCase):
    def test_load_returns_default_when_nothing_stored(self):
        d = tempfile.mkdtemp()
        self.assertEqual(ls.load(d)["screens"][0]["name"], "Overview")

    def test_save_bumps_version_and_survives_reload(self):
        d = tempfile.mkdtemp()
        first = ls.save(d, ls.default_layout())
        second = ls.save(d, first)
        self.assertEqual((first["version"], second["version"]), (1, 2))
        self.assertEqual(ls.load(d)["version"], 2)
        self.assertIn("saved_at", ls.load(d))

    def test_corrupt_file_falls_back_to_default(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "layout.json"), "w") as f:
            f.write("{not json")
        self.assertEqual(ls.load(d)["screens"][0]["name"], "Overview")

    def test_oversized_layout_is_rejected(self):
        lay = ls.default_layout()
        lay["screens"][0]["name"] = "x" * 70000
        with self.assertRaises(ValueError):
            ls.save(tempfile.mkdtemp(), lay)


class Csrf(unittest.TestCase):
    def test_requires_json_custom_header_and_same_origin(self):
        ok = {"Content-Type": "application/json", "X-Observatory": "1", "Host": "utm:8765", "Origin": "http://utm:8765"}
        self.assertTrue(ls.csrf_ok(ok))
        self.assertTrue(ls.csrf_ok({k: v for k, v in ok.items() if k != "Origin"}))   # same-origin fetch may omit it
        for k, v in (("Content-Type", "text/plain"), ("X-Observatory", ""), ("Origin", "http://evil.test")):
            self.assertFalse(ls.csrf_ok(dict(ok, **{k: v})), k)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m unittest tests.test_layout_store -v`
Expected: ERROR `ModuleNotFoundError: No module named 'layout_store'`

- [ ] **Step 3: Implement `app/layout_store.py`**

```python
"""Shared dashboard layout: widget catalogue, validation and storage (no HTTP here).

Layout JSON (schema 1):
  {"schema": 1, "version": N, "saved_at": iso, "screens": [
     {"id": "overview", "name": "Overview", "wall": false,
      "widgets": [{"type": "map", "x": 0, "y": 4, "w": 8, "h": 14}, ...]}, ...]}
Grid: 12 columns; y and h are 40 px row units.
"""
import json
import os
import re
import tempfile
from datetime import datetime, timezone

COLS, MAX_ROWS, MAX_H = 12, 200, 40
MAX_SCREENS, MAX_WIDGETS, MAX_BYTES = 12, 20, 64 * 1024
FILE = "layout.json"

WIDGET_TYPES = {                      # keep in step with WIDGETS in app/layout.js
    "kpis": {"min_w": 6, "min_h": 4},
    "map": {"min_w": 5, "min_h": 8},
    "donut": {"min_w": 3, "min_h": 5},
    "rules": {"min_w": 3, "min_h": 6},
    "trend": {"min_w": 4, "min_h": 5},
    "rate": {"min_w": 4, "min_h": 2},
    "alerts": {"min_w": 4, "min_h": 5},
    "resources": {"min_w": 3, "min_h": 5},
}


def _w(t, x, y, w, h):
    return {"type": t, "x": x, "y": y, "w": w, "h": h}


def default_layout():
    return {"schema": 1, "version": 0, "screens": [
        {"id": "overview", "name": "Overview", "wall": False, "widgets": [
            _w("kpis", 0, 0, 12, 4), _w("map", 0, 4, 8, 14), _w("donut", 8, 4, 4, 6), _w("rules", 8, 10, 4, 8),
            _w("trend", 0, 18, 12, 7), _w("rate", 0, 25, 12, 2), _w("alerts", 0, 27, 7, 9), _w("resources", 7, 27, 5, 9)]},
        {"id": "live-map", "name": "Live map", "wall": True, "widgets": [_w("map", 0, 0, 12, 18)]},
        {"id": "activity", "name": "Activity", "wall": True, "widgets": [
            _w("kpis", 0, 0, 12, 4), _w("trend", 0, 4, 8, 12), _w("donut", 8, 4, 4, 6), _w("rules", 8, 10, 4, 6),
            _w("rate", 0, 16, 8, 2)]},
    ]}


def _int(v, lo, hi, default):
    try:
        v = int(v)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, v))


def _slug(text, taken):
    base = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:20] or "screen"
    sid, n = base, 2
    while sid in taken:
        sid, n = "%s-%d" % (base, n), n + 1
    return sid


def validate_layout(obj):
    """Return (clean_layout, notes). Raises ValueError for a layout that cannot be repaired."""
    if len(json.dumps(obj, separators=(",", ":"))) > MAX_BYTES:      # before trimming, so oversized input is refused
        raise ValueError("layout is larger than %d KB" % (MAX_BYTES // 1024))
    if not isinstance(obj, dict) or obj.get("schema") != 1:
        raise ValueError("layout must be an object with schema 1")
    screens = obj.get("screens")
    if not isinstance(screens, list) or not 1 <= len(screens) <= MAX_SCREENS:
        raise ValueError("a layout needs 1 to %d screens" % MAX_SCREENS)
    notes, out, ids = [], [], set()
    for i, s in enumerate(screens):
        if not isinstance(s, dict) or not isinstance(s.get("widgets", []), list):
            raise ValueError("screen %d is malformed" % (i + 1))
        name = str(s.get("name") or "Screen %d" % (i + 1)).strip()[:40] or "Screen %d" % (i + 1)
        sid = str(s.get("id") or "")
        if not re.match(r"^[a-z0-9-]{1,24}$", sid) or sid in ids:
            sid = _slug(name, ids)
        ids.add(sid)
        widgets, seen = [], set()
        raw = s.get("widgets", [])
        if len(raw) > MAX_WIDGETS:
            raise ValueError("screen '%s' has more than %d widgets" % (name, MAX_WIDGETS))
        for w in raw:
            t = w.get("type") if isinstance(w, dict) else None
            if t not in WIDGET_TYPES:
                notes.append("Dropped unknown widget '%s' on screen '%s'." % (t, name))
                continue
            if t in seen:
                notes.append("Dropped a second '%s' widget on screen '%s'." % (t, name))
                continue
            seen.add(t)
            mn = WIDGET_TYPES[t]
            ww = _int(w.get("w"), mn["min_w"], COLS, mn["min_w"])
            hh = _int(w.get("h"), mn["min_h"], MAX_H, mn["min_h"])
            xx = _int(w.get("x"), 0, COLS - ww, 0)
            yy = _int(w.get("y"), 0, MAX_ROWS, 0)
            widgets.append({"type": t, "x": xx, "y": yy, "w": ww, "h": hh})
        out.append({"id": sid, "name": name, "wall": bool(s.get("wall")), "widgets": widgets})
    clean = {"schema": 1, "version": _int(obj.get("version"), 0, 10 ** 9, 0), "screens": out}
    if obj.get("saved_at"):
        clean["saved_at"] = str(obj["saved_at"])[:40]
    return clean, notes


def load(data_dir):
    try:
        with open(os.path.join(data_dir, FILE)) as f:
            return validate_layout(json.load(f))[0]
    except (OSError, ValueError):
        return validate_layout(default_layout())[0]


def save(data_dir, layout):
    clean, _ = validate_layout(layout)
    clean["version"] = load(data_dir).get("version", 0) + 1
    clean["saved_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    body = json.dumps(clean, separators=(",", ":"))
    if len(body) > MAX_BYTES:
        raise ValueError("layout is larger than %d KB" % (MAX_BYTES // 1024))
    fd, tmp = tempfile.mkstemp(dir=data_dir, prefix=".layout-")
    with os.fdopen(fd, "w") as f:
        f.write(body)
    os.replace(tmp, os.path.join(data_dir, FILE))       # atomic: a crash never leaves half a file
    return clean


def csrf_ok(headers):
    """Basic-auth credentials ride along on cross-site requests, so writes need proof they came from our page."""
    if not str(headers.get("Content-Type", "")).lower().startswith("application/json"):
        return False
    if headers.get("X-Observatory") != "1":
        return False
    origin = headers.get("Origin")
    if origin:
        host = re.sub(r"^https?://", "", origin).split("/")[0]
        return host == headers.get("Host")
    return True
```

- [ ] **Step 4: Run the store tests**

Run: `python3 -m unittest tests.test_layout_store -v`
Expected: all tests in `Defaults`, `Validation`, `Storage`, `Csrf` PASS.

- [ ] **Step 5: Wire the HTTP routes into `app/server.py`**

At the top, after the other imports:

```python
import layout_store
```

In `Handler.send`, change the CSP so `/layout.js` may load:

```python
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; "
                         "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
```

In `do_GET`, before the `elif u.path == "/land.json":` branch:

```python
        elif u.path == "/layout.js":
            with open(os.path.join(HERE, "layout.js"), "rb") as f:
                self.send(200, "text/javascript; charset=utf-8", f.read())
        elif u.path == "/api/layout":
            lay = layout_store.load(DATA_DIR)
            self.send(200, "application/json", json.dumps({"layout": lay, "notes": []}).encode())
```

Add a `do_PUT` method to `Handler`, below `do_GET`:

```python
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
        if not layout_store.csrf_ok(self.headers):
            self.send(403, "application/json", b'{"error":"forbidden"}')
            return
        try:
            n = int(self.headers.get("Content-Length") or 0)
            if n > layout_store.MAX_BYTES + 1024:
                raise ValueError("request too large")
            req = json.loads(self.rfile.read(n) or b"{}")
            with _layout_lock:
                current = layout_store.load(DATA_DIR)
                if req.get("base_version") != current.get("version"):
                    self.send(409, "application/json", json.dumps({"error": "conflict", "layout": current}).encode())
                    return
                saved = layout_store.save(DATA_DIR, req.get("layout"))
            self.send(200, "application/json", json.dumps({"layout": saved}).encode())
        except ValueError as e:
            self.send(400, "application/json", json.dumps({"error": str(e)[:200]}).encode())
```

And next to the other module-level locks (above `class Handler`):

```python
_layout_lock = threading.Lock()                  # one writer at a time; version check + save are atomic together
```

- [ ] **Step 6: HTTP-level test for the route (append to `tests/test_layout_store.py`)**

```python
class HttpRoutes(unittest.TestCase):
    def setUp(self):
        import importlib, threading
        from http.server import ThreadingHTTPServer
        os.environ.update(OS_URL="http://127.0.0.1:9", DATA_DIR=tempfile.mkdtemp(), DASH_PASS="", BIND="127.0.0.1")
        import server
        self.server = importlib.reload(server)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), self.server.Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = "http://127.0.0.1:%d" % self.httpd.server_address[1]

    def tearDown(self):
        self.httpd.shutdown()

    def req(self, method, path, body=None, headers=None):
        import urllib.request, urllib.error
        r = urllib.request.Request(self.base + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                   headers=headers or {})
        try:
            with urllib.request.urlopen(r) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def test_get_put_and_conflict(self):
        st, got = self.req("GET", "/api/layout")
        self.assertEqual((st, got["layout"]["version"]), (200, 0))
        h = {"Content-Type": "application/json", "X-Observatory": "1"}
        st, put = self.req("PUT", "/api/layout", {"layout": got["layout"], "base_version": 0}, h)
        self.assertEqual((st, put["layout"]["version"]), (200, 1))
        st, conflict = self.req("PUT", "/api/layout", {"layout": got["layout"], "base_version": 0}, h)
        self.assertEqual((st, conflict["error"], conflict["layout"]["version"]), (409, "conflict", 1))

    def test_put_without_custom_header_is_forbidden(self):
        st, _ = self.req("PUT", "/api/layout", {"layout": {}, "base_version": 0}, {"Content-Type": "application/json"})
        self.assertEqual(st, 403)

    def test_bad_layout_is_400(self):
        h = {"Content-Type": "application/json", "X-Observatory": "1"}
        st, err = self.req("PUT", "/api/layout", {"layout": {"schema": 9}, "base_version": 0}, h)
        self.assertEqual(st, 400)
        self.assertIn("schema", err["error"])
```

- [ ] **Step 7: Run all Python tests**

Run: `python3 -m unittest discover -s tests -v`
Expected: all PASS (the existing 15 plus the new ones).

- [ ] **Step 8: Commit**

```bash
git add app/layout_store.py app/server.py tests/test_layout_store.py
git commit -m "Shared layout store: validation, atomic save, GET/PUT /api/layout with CSRF checks"
```

---

### Task 2: Pure layout arithmetic (`app/layout.js`)

**Files:**
- Create: `app/layout.js`
- Test: `tests/layout.test.js`

**Interfaces:**
- Consumes: the widget catalogue values from Task 1 (`min_w`/`min_h` per type).
- Produces (`window.ObsLayout` in the browser, `module.exports` under Node):
  - `WIDGETS: {[type]: {title, desc, minW, minH, w, h, wallSafe: true|'anon'|false}}`
  - `COLS: 12`
  - `collides(a, b) -> bool`
  - `resolve(items, movedIndex) -> items` (new array; overlaps pushed down, then compacted)
  - `compact(items) -> items`
  - `move(items, i, x, y) -> items`
  - `resize(items, i, w, h) -> items`
  - `addWidget(items, type) -> items` (placed at the bottom with default size)
  - `removeWidget(items, i) -> items`
  - `readingOrder(items) -> items` (sorted by y, then x)
  - `sanitizeLayout(layout) -> {layout, notes}` (client copy: drops unknown types)
  - `isPersonalStale(personal, shared) -> bool`
  - `removeScreen(layout, id) -> layout` (keeps at least one)
  - `addScreen(layout, name) -> layout`
  - `renameScreen(layout, id, name) -> layout`
  - `moveScreen(layout, id, dir) -> layout`

  Each item is `{type, x, y, w, h}` in grid units. Every function is pure: it returns new arrays and objects and never mutates its arguments.

- [ ] **Step 1: Write the failing tests**

```js
// tests/layout.test.js — run: node --test tests/
const test = require('node:test');
const assert = require('node:assert/strict');
const L = require('../app/layout.js');

const W = (type, x, y, w, h) => ({ type, x, y, w, h });
const overlapFree = items => items.every((a, i) => items.every((b, j) => i === j || !L.collides(a, b)));

test('catalogue matches the server copy', () => {
  assert.deepEqual(Object.keys(L.WIDGETS).sort(), ['alerts', 'donut', 'kpis', 'map', 'rate', 'resources', 'rules', 'trend']);
  assert.equal(L.WIDGETS.map.minW, 5); assert.equal(L.WIDGETS.map.minH, 8);
  assert.equal(L.WIDGETS.alerts.wallSafe, false); assert.equal(L.WIDGETS.map.wallSafe, 'anon');
});

test('collides only on real overlap', () => {
  assert.equal(L.collides(W('a', 0, 0, 6, 4), W('b', 6, 0, 6, 4)), false);   // touching edges
  assert.equal(L.collides(W('a', 0, 0, 6, 4), W('b', 5, 3, 6, 4)), true);
});

test('dropping a widget onto another pushes the other down, no overlaps, no gaps', () => {
  const items = [W('map', 0, 0, 8, 10), W('donut', 8, 0, 4, 6)];
  const out = L.move(items, 1, 4, 2);                        // drag donut onto the map
  assert.ok(overlapFree(out));
  const donut = out.find(i => i.type === 'donut'), map = out.find(i => i.type === 'map');
  assert.deepEqual([donut.x, donut.y], [4, 0]);              // compacted up to the top
  assert.equal(map.y, donut.h);                               // map pushed below it
  assert.deepEqual(items[1], W('donut', 8, 0, 4, 6));         // input untouched
});

test('move clamps to the grid and resize respects minimums', () => {
  const items = [W('map', 0, 0, 8, 10)];
  assert.equal(L.move(items, 0, 11, 0)[0].x, 4);             // 4 + 8 = 12
  const r = L.resize(items, 0, 2, 1)[0];
  assert.deepEqual([r.w, r.h], [5, 8]);
  assert.equal(L.resize(items, 0, 20, 10)[0].w, 12);
});

test('compact removes vertical gaps but keeps horizontal order', () => {
  const out = L.compact([W('kpis', 0, 5, 12, 4), W('map', 0, 20, 6, 8), W('donut', 6, 30, 6, 6)]);
  assert.deepEqual(out.map(i => [i.type, i.y]), [['kpis', 0], ['map', 4], ['donut', 4]]);
});

test('addWidget appends at the bottom with the default size; removeWidget compacts', () => {
  let items = [W('kpis', 0, 0, 12, 4)];
  items = L.addWidget(items, 'resources');
  const r = items.find(i => i.type === 'resources');
  assert.deepEqual([r.x, r.y, r.w, r.h], [0, 4, L.WIDGETS.resources.w, L.WIDGETS.resources.h]);
  assert.throws(() => L.addWidget(items, 'resources'), /already/);
  items = L.removeWidget(items, 0);
  assert.equal(items[0].y, 0);
});

test('readingOrder sorts by row then column', () => {
  assert.deepEqual(L.readingOrder([W('b', 6, 0, 6, 4), W('c', 0, 4, 12, 4), W('a', 0, 0, 6, 4)]).map(i => i.type), ['a', 'b', 'c']);
});

test('sanitizeLayout drops unknown types with a note', () => {
  const { layout, notes } = L.sanitizeLayout({ schema: 1, version: 3, screens: [{ id: 's', name: 'S', wall: true, widgets: [W('map', 0, 0, 12, 10), W('hologram', 0, 10, 4, 4)] }] });
  assert.deepEqual(layout.screens[0].widgets.map(w => w.type), ['map']);
  assert.match(notes[0], /hologram/);
});

test('isPersonalStale when the shared layout moved on', () => {
  assert.equal(L.isPersonalStale({ baseVersion: 2 }, { version: 2 }), false);
  assert.equal(L.isPersonalStale({ baseVersion: 2 }, { version: 3 }), true);
});

test('screens: add, rename, move, remove (never the last one)', () => {
  let lay = { schema: 1, version: 0, screens: [{ id: 'a', name: 'A', wall: false, widgets: [] }] };
  lay = L.addScreen(lay, 'Threats');
  assert.deepEqual(lay.screens.map(s => s.id), ['a', 'threats']);
  lay = L.renameScreen(lay, 'threats', '  Hunting  ');
  assert.equal(lay.screens[1].name, 'Hunting');
  lay = L.moveScreen(lay, 'threats', -1);
  assert.deepEqual(lay.screens.map(s => s.id), ['threats', 'a']);
  lay = L.removeScreen(lay, 'a');
  assert.deepEqual(lay.screens.map(s => s.id), ['threats']);
  assert.throws(() => L.removeScreen(lay, 'threats'), /last screen/);
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --test tests/`
Expected: FAIL with `Cannot find module '../app/layout.js'`

- [ ] **Step 3: Implement `app/layout.js`**

```js
/* UTMStack Observatory — pure layout arithmetic for the widget board (no DOM).
   Items are {type, x, y, w, h} on a 12-column grid; y/h are 40 px row units. Every function returns new
   objects and never mutates its arguments. Loaded in the browser as window.ObsLayout, in Node via require(). */
(function (root) {
  'use strict';
  var COLS = 12, MAX_SCREENS = 12;
  var WIDGETS = {   // keep minW/minH in step with WIDGET_TYPES in app/layout_store.py
    kpis:      {title: 'Key metrics',             desc: 'Data sources, events, alerts and ingest lag.',            minW: 6, minH: 4, w: 12, h: 4,  wallSafe: true},
    map:       {title: 'Live firewall map',       desc: 'Animated connections from every firewall to the world.',  minW: 5, minH: 8, w: 8,  h: 14, wallSafe: 'anon'},
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
  function move(items, i, x, y) { var out = copy(items); out[i].x = x; out[i].y = y; clampItem(out[i]); return resolve(out, i); }
  function resize(items, i, w, h) { var out = copy(items); out[i].w = w; out[i].h = h; clampItem(out[i]); return resolve(out, i); }
  function addWidget(items, type) {
    if (!WIDGETS[type]) throw new Error('unknown widget ' + type);
    if (items.some(function (i) { return i.type === type; })) throw new Error(type + ' is already on this screen');
    var bottom = items.reduce(function (m, i) { return Math.max(m, i.y + i.h); }, 0);
    return copy(items).concat([clampItem({type: type, x: 0, y: bottom, w: WIDGETS[type].w, h: WIDGETS[type].h})]);
  }
  function removeWidget(items, i) { return compact(copy(items).filter(function (_, k) { return k !== i; })); }

  function sanitizeLayout(layout) {
    var notes = [];
    var screens = (layout && layout.screens || []).map(function (s) {
      var seen = {};
      var widgets = (s.widgets || []).filter(function (w) {
        if (!WIDGETS[w.type]) { notes.push('Dropped unknown widget "' + w.type + '" on screen "' + s.name + '".'); return false; }
        if (seen[w.type]) return false;
        seen[w.type] = 1; return true;
      }).map(function (w) { return clampItem({type: w.type, x: w.x, y: w.y, w: w.w, h: w.h}); });
      return {id: s.id, name: s.name, wall: !!s.wall, widgets: widgets};
    });
    return {layout: {schema: 1, version: layout && layout.version || 0, saved_at: layout && layout.saved_at, screens: screens}, notes: notes};
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test tests/`
Expected: all 10 tests PASS. If the drag test fails on the expected `map.y`, check `resolve`: the moved item must keep its target `x`, and compaction may only lift it vertically.

- [ ] **Step 5: Commit**

```bash
git add app/layout.js tests/layout.test.js
git commit -m "Pure layout arithmetic for the widget board, with node tests"
```

---

### Task 3: Board markup and screen switching (no editing yet)

**Files:**
- Modify: `app/index.html`. Replace the fixed `.shell` rows with header + tab bar + `.board`; give each panel a `data-widget`; add board CSS; add the board controller script.

**Interfaces:**
- Consumes: `window.ObsLayout` (Task 2) and `GET /api/layout` (Task 1).
- Produces, inside the main IIFE, for later tasks:
  - `BOARD = {shared, personal, layout, screenId, notes}`
  - `renderBoard()`, which places the widgets of the active screen and re-renders the canvases
  - `showScreen(id)`
  - `activeLayout()`, which returns the personal layout if one is set, otherwise the shared one
  - `widgetEl(type)`, which returns the panel element

- [ ] **Step 1: Restructure the markup**

In `<head>`, before the main inline `<script>`, load the helper:

```html
<script src="/layout.js"></script>
```

Replace the wrappers. The panels themselves stay byte-identical inside:

- `<section class="kpi-band" id="kpiBand" …>` gets `data-widget="kpis"`.
- `#mapPanel` gets `data-widget="map"`.
- The donut `<section class="panel" aria-labelledby="donutTitle">` gets `data-widget="donut"`.
- The rules `<section … aria-labelledby="top5Title" …>` gets `data-widget="rules"`.
- The trend `<section class="panel trend-panel" …>` gets `data-widget="trend"`.
- The `<section class="panel spark-panel" …>` gets `data-widget="rate"`.
- The alerts `<section … aria-labelledby="alertTitle" …>` gets `data-widget="alerts"`.
- The resources `<section … aria-labelledby="resTitle" …>` gets `data-widget="resources"`.

Then remove the wrappers `<main class="field">`, `<div class="col col-map">`, `<aside class="col col-right">`, `<section class="trend-row" id="trendRow">` and `<section class="bottom">`. All eight panels become direct children of a new `<main class="board" id="board">`, placed right after the header, together with a tab bar:

```html
  <nav class="tabbar" id="tabbar" aria-label="Screens">
    <div class="tabs" id="screenTabs" role="tablist"></div>
    <span class="spacer"></span>
    <span class="panel-meta" id="layoutState"></span>
    <button class="ctl" id="editBtn" aria-pressed="false" title="Move, resize, add and remove widgets">Edit</button>
  </nav>
  <main class="board" id="board">
    <!-- the eight panels, in the order kpis, map, donut, rules, trend, rate, alerts, resources -->
  </main>
  <div class="board-notes" id="boardNotes" hidden></div>
```

- [ ] **Step 2: Board CSS**

Delete these rules:
- `.shell{grid-template-rows:…}` (every occurrence);
- `.field`, `.col`, `.col-left`, `.col-right`, `.col-map`, `.trend-row`, `.bottom`;
- all `body.wall[data-view=…]` rules;
- the `.shell` rows inside both `@media (max-width:1099px)` blocks.

Add:

```css
.shell{min-height:100dvh;padding:20px 24px 18px;display:flex;flex-direction:column;gap:12px}
.tabbar{display:flex;align-items:center;gap:10px;min-height:40px}
.tabs{display:flex;gap:4px;flex-wrap:wrap}
.tab{height:34px;padding:0 14px;border:1px solid var(--border);border-radius:4px;font-family:var(--mono);font-size:12.5px;font-weight:600;color:var(--muted);white-space:nowrap}
.tab[aria-selected="true"]{border-color:var(--cyan);color:var(--cyan);background:var(--cyan-soft)}
.tab .wall-dot{display:inline-block;width:6px;height:6px;border-radius:50%;background:var(--green);margin-left:8px;vertical-align:middle}
.board{display:grid;grid-template-columns:repeat(12,minmax(0,1fr));grid-auto-rows:40px;gap:12px}
.board>[data-widget]{min-width:0;min-height:0}
.board>[data-widget][hidden]{display:none!important}
.kpi-band{height:100%}
.board-notes{font-family:var(--mono);font-size:12px;color:var(--yellow)}
@media (max-width:1099px){
  .board{display:flex;flex-direction:column}
  .board>[data-widget]{grid-column:auto!important;grid-row:auto!important;min-height:var(--mobile-h,320px)}
  .board>[data-widget="kpis"]{--mobile-h:auto}
  .board>[data-widget="rate"]{--mobile-h:auto}
  #editBtn{display:none}
}
```

Note: the trend panel's inner grid previously sized from `.col-left`. Its own rule `.trend-panel{display:flex;flex-direction:column;min-height:0;overflow:hidden}` already fills its cell.

- [ ] **Step 3: Board controller (inside the main IIFE, after the wall-mode block)**

```js
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
  }
  function renderBoard(){
    var s = currentScreen(), on = {};
    s.widgets.forEach(function(w){
      var el = widgetEl(w.type); if(!el) return;
      on[w.type] = 1; el.hidden = false;
      el.style.gridColumn = (w.x+1)+' / span '+w.w; el.style.gridRow = (w.y+1)+' / span '+w.h;
      el.style.order = String(w.y*100 + w.x);          // reading order for the single-column (mobile) view
    });
    $$('#board > [data-widget]').forEach(function(el){ if(!on[el.dataset.widget]) el.hidden = true; });
    renderTabs();
    setTimeout(function(){ landCache = null; if(D) apply(D); drawMap(performance.now()); }, 30);   // canvases resize to the new cells
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
        var p = L.sanitizeLayout(BOARD.personal.layout);
        BOARD.personal.layout = p.layout; BOARD.notes = BOARD.notes.concat(p.notes);
      }
      var n = $('#boardNotes'); n.hidden = !BOARD.notes.length; n.textContent = BOARD.notes.join(' ');
      renderBoard();
    });
  }
  window.addEventListener('resize', function(){ if(BOARD.shared) renderBoard(); });
  loadSharedLayout().catch(function(e){ $('#boardNotes').hidden = false; $('#boardNotes').textContent = 'Layout could not be loaded ('+e.message+'); showing every widget.'; });
```

Until `loadSharedLayout` resolves, all eight panels are visible in DOM order (no `hidden`). The page is therefore never blank.

- [ ] **Step 4: Browser check (local fixture harness)**

Start the harness used for 1.1.x:

```bash
S=/private/tmp/claude-501/-Users-victorbeitner-firefly-iii/2b184551-c6d4-4fe7-9a57-1bcca0fd2291/scratchpad
python3 $S/obs_harness.py ~/utmstack-observatory/app $S/obsdata $S/obs-fixture.json &
```

Open `http://127.0.0.1:8766/` at 1440×900.

Expected:
- Three tabs: Overview, Live map, Activity. The last two carry a green dot.
- Overview looks like 1.1.1: KPIs, map left, donut and rules right, then trend, rate, alerts and resources.
- *Live map* shows only the map at full width.
- *Activity* shows KPIs, trend, donut, rules and rate.
- The selected tab survives a reload.
- No console errors, status `Running · LIVE`.

At 768 px wide:
- one column in reading order;
- no Edit button;
- no horizontal scroll.

- [ ] **Step 5: Commit**

```bash
git add app/index.html
git commit -m "Widget board: panels placed on a 12-column grid from the shared layout, screen tabs"
```

---

### Task 4: Wall mode over screens

**Files:**
- Modify: `app/index.html`. Replace the old `WALL_VIEWS` rotation in the wall-mode block, and add the placeholder CSS.

**Interfaces:**
- Consumes: `BOARD`, `renderBoard()`, `showScreen()`, `L.WIDGETS[type].wallSafe` (Tasks 2 and 3).
- Produces: `wallScreens()`, which returns the ids of the shared screens with `wall: true`, in order.

- [ ] **Step 1: Replace the rotation**

In the wall-mode block, replace `WALL_VIEWS`, `wallIdx` and `wallView()` with the following, and replace their uses in `setWall`:

```js
  function wallScreens(){
    var ids = (BOARD.shared ? BOARD.shared.screens : []).filter(function(s){ return s.wall; }).map(function(s){ return s.id; });
    return ids.length ? ids : (BOARD.shared ? [BOARD.shared.screens[0].id] : []);
  }
  var wallIdx = 0;
  function wallStep(){
    var ids = wallScreens(); if(!ids.length) return;
    wallIdx = wallIdx % ids.length; showScreen(ids[wallIdx]); wallIdx++;
  }
```

Move the auto-start line `if(/[?&]wall=1\b/.test(location.search)) setWall(true);` out of the wall block and into the
success handler of `loadSharedLayout`, guarded so it runs once (`if(!loadSharedLayout.done){ loadSharedLayout.done = 1; if(/[?&]wall=1\b/.test(location.search)) setWall(true); }`)
— the rotation needs `BOARD.shared`, which does not exist before the first layout load.

In `setWall(on)`:
- **on:** `wallIdx = 0; wallStep(); wallTimer = setInterval(wallStep, 30000);`
- **off:** restore the screen the user had before entering wall mode. Save it in `var preWallScreen = BOARD.screenId;` when switching on, and call `showScreen(preWallScreen)` when switching off.

Remove the CSS rules `body.wall .shell>*{display:none}` and `body.wall .shell>.hdr{display:grid}`, and add:

```css
body.wall #tabbar{display:none}
body.wall .board>[data-wall-hidden]{position:relative}
body.wall .board>[data-wall-hidden]>*{visibility:hidden}
body.wall .board>[data-wall-hidden]::after{content:"Hidden on the wall screen: contains client names";position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-family:var(--mono);font-size:13px;color:var(--muted);border:1px dashed var(--border-strong)}
```

In `renderBoard`, for each placed widget, set or clear `data-wall-hidden`:

```js
      if(wallOn && L.WIDGETS[w.type].wallSafe === false) el.setAttribute('data-wall-hidden',''); else el.removeAttribute('data-wall-hidden');
```

In wall mode the row height is derived from the viewport so an 18-row screen exactly fills a TV (header 72 px + paddings ≈ 132 px, 17 gaps):

```css
body.wall .board{grid-auto-rows:calc((100dvh - 132px - 17 * 12px) / 18)}
```

- [ ] **Step 2: Browser check**

Open `http://127.0.0.1:8766/?wall=1` at 1920×1080.

Expected:
- *Live map* first, filling the screen without scrolling.
- After 30 s, *Activity*.
- Site names show as "Site A…".
- Esc returns to the screen you were on.

Temporarily add `alerts` to the Activity screen in `/data/layout.json` of the harness (`$S/obsdata/layout.json`). It must show the dashed "Hidden on the wall screen" placeholder in wall mode and the real list outside it.

- [ ] **Step 3: Commit**

```bash
git add app/index.html
git commit -m "Wall mode rotates through the screens marked for the wall; client-name widgets show a placeholder"
```

---

### Task 5: Edit mode — move, resize, add, remove, screens

**Files:**
- Modify: `app/index.html` (edit-mode CSS + controller)
- Test: `tests/layout.test.js` (no new pure functions are needed; the `removeScreen` and `addWidget` tests from Task 2 cover the arithmetic)

**Interfaces:**
- Consumes: `L.move`, `L.resize`, `L.addWidget`, `L.removeWidget`, `L.addScreen`, `L.renameScreen`, `L.moveScreen`, `L.removeScreen`, `BOARD`, `renderBoard()`.
- Produces: `setEdit(on)`, `commitScreenWidgets(widgets)` and `savePersonal()`. Edits write to a **personal** layout (`BOARD.personal = {baseVersion, layout}`), and Task 6 persists it.

- [ ] **Step 1: Edit-mode CSS**

```css
body.editing .board{background-image:linear-gradient(to right,rgba(53,231,255,.05) 1px,transparent 1px);background-size:calc((100% + 12px)/12) 100%}
body.editing .board>[data-widget]{outline:1px dashed var(--border-strong);outline-offset:3px}
.w-tools{display:none;position:absolute;top:6px;right:8px;z-index:6;gap:6px}
body.editing .w-tools{display:flex}
.w-tools button{height:26px;min-width:26px;padding:0 8px;border:1px solid var(--border-strong);border-radius:4px;background:var(--s3);font-family:var(--mono);font-size:12px;color:var(--ink2)}
.w-drag{cursor:grab}
.w-resize{position:absolute;right:2px;bottom:2px;width:16px;height:16px;cursor:nwse-resize;z-index:6;display:none;
  background:linear-gradient(135deg,transparent 50%,var(--cyan) 50%)}
body.editing .w-resize{display:block}
.board>[data-widget]{position:relative}
.ghost{outline:2px solid var(--cyan)!important;opacity:.85}
.edit-bar{display:none;gap:8px;align-items:center;flex-wrap:wrap}
body.editing .edit-bar{display:flex}
.add-menu{position:absolute;z-index:30;background:var(--s2);border:1px solid var(--border-strong);border-radius:4px;padding:6px;min-width:300px;box-shadow:0 10px 30px rgba(0,0,0,.5)}
.add-menu button{display:block;width:100%;text-align:left;padding:8px 10px;border-radius:3px}
.add-menu button:hover,.add-menu button:focus-visible{background:var(--s3)}
.add-menu small{display:block;color:var(--muted);font-size:12px}
```

- [ ] **Step 2: Edit bar markup (inside `#tabbar`, before `#editBtn`)**

```html
    <div class="edit-bar" id="editBar">
      <button class="ctl" id="addWidgetBtn" aria-haspopup="menu">+ Widget</button>
      <button class="ctl" id="addScreenBtn">+ Screen</button>
      <button class="ctl" id="renameScreenBtn">Rename</button>
      <button class="ctl" id="wallScreenBtn" aria-pressed="false" title="Include this screen in wall mode">On wall</button>
      <button class="ctl icon" id="screenLeftBtn" aria-label="Move screen left">◀</button>
      <button class="ctl icon" id="screenRightBtn" aria-label="Move screen right">▶</button>
      <button class="ctl" id="deleteScreenBtn">Delete screen</button>
    </div>
```

- [ ] **Step 3: Edit controller (after the board controller)**

```js
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
```

In `renderTabs`, keep `#wallScreenBtn`'s `aria-pressed` in step with `currentScreen().wall`:

```js
    var wb = $('#wallScreenBtn'); if(wb) wb.setAttribute('aria-pressed', String(!!cur.wall));
```

- [ ] **Step 4: Browser check**

At 1440×900, click **Edit**.

Expected:
- Every widget shows *⠿ Move*, ✕ and a resize corner.
- Dragging the donut onto the map pushes the map down, with no overlap.
- Dragging past the right edge stops at column 12.
- Resizing the map below 5×8 stops at 5×8.
- **+ Widget** lists only types not on the screen; adding *Resource utilisation* places it at the bottom.
- ✕ removes a widget and the gap closes.
- Arrow keys on a focused *Move* button move the widget; Shift+arrow resizes it.
- **+ Screen** "Threats" adds a tab and switches to it (empty board).
- **Rename**, ◀ ▶ and **On wall** work, and the green dot follows.
- **Delete screen** on the last remaining screen shows "cannot delete the last screen".
- Narrowing the window below 1100 px leaves edit mode.

- [ ] **Step 5: Commit**

```bash
git add app/index.html
git commit -m "Edit mode: drag, resize, add and remove widgets; add, rename, reorder, delete screens"
```

---

### Task 6: Personal vs shared persistence

**Files:**
- Modify: `app/index.html` (persistence functions and layout-state UI)

**Interfaces:**
- Consumes: `BOARD`, `PUT /api/layout` (Task 1), `L.isPersonalStale` (Task 2).
- Produces:
  - `resetToShared()`
  - `saveAsShared()`, which returns a Promise

- [ ] **Step 1: Persistence functions (after the edit controller)**

```js
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
    $('#saveShared').addEventListener('click', function(){ if(confirm('Make your layout the shared default for everyone, including the wall screen?')) saveAsShared(); });
  }
```

At the end of `loadSharedLayout`'s success handler, call `renderLayoutState()`.

Re-poll the shared layout every 60 s, so a wall TV picks up a newly saved shared layout without a reload:

```js
  setInterval(function(){ if(!editing) loadSharedLayout().catch(function(){}); }, 60000);
```

- [ ] **Step 2: Unit test for staleness**

Already covered by `isPersonalStale` in `tests/layout.test.js` (Task 2). No new pure function.

- [ ] **Step 3: Browser check (two tabs)**

- **Tab A.** Edit, move a widget, Done.
  - Header shows "Personal layout · Reset to shared · Save as shared default".
  - The change survives a reload.
- **Tab B (a different profile, or after clearing local storage).** It still shows the original shared layout.
- **Tab A, Save as shared default.** The header shows "Shared layout".
- **Tab B.** Within 60 s it shows the new layout. A wall-mode tab picks it up too.
- **Conflict path.** In Tab B, make a personal change and save as shared while Tab A's shared version is newer. The conflict confirm appears; choosing *Cancel* keeps Tab B's personal layout.
- **Personal behind shared.** A personal layout based on version 1 while shared is version 2 shows "shared layout changed since". **Reset to shared** restores the shared layout.

- [ ] **Step 4: Commit**

```bash
git add app/index.html
git commit -m "Personal layouts in the browser, Save as shared default with conflict handling, Reset to shared"
```

---

### Task 7: Release 1.2.0

**Files:**
- Modify: `VERSION`, `app/server.py` (`VERSION = "1.2.0"`), `RELEASE-NOTES.md`, `README.md`

- [ ] **Step 1: Bump versions and write the release note**

`VERSION` → `1.2.0`; `server.py` `VERSION = "1.2.0"`.

Prepend to `RELEASE-NOTES.md`:

```markdown
## 1.2.0 — <release date>

**For users**
- **Screens.** Tabs under the header switch between screens. It starts with *Overview*, *Live map* and *Activity*. A
  green dot marks the screens that the wall display rotates through.
- **Move, resize, add and remove widgets.** Click **Edit**: drag a widget by *Move*, resize it from its corner, remove
  it with ✕, or add one with **+ Widget**. Other widgets make room automatically. You can also add, rename, reorder and
  delete screens and choose which ones appear on the wall. Arrow keys move the focused widget, Shift+arrows resize it.
- **Your layout or everyone's.** Changes start as your personal layout in this browser. **Save as shared default**
  makes it the layout everyone (and the wall screen) sees; **Reset to shared** goes back.
- On screens narrower than 1100 pixels, widgets stack in one column and editing is switched off.

**Technical**
- New `GET/PUT /api/layout` (shared layout in `/data/layout.json` on the existing volume, versioned; writes need
  `X-Observatory: 1` + JSON + same origin; 409 on a version conflict).
- New `app/layout.js` (pure layout functions, tested with `node --test tests/`) and `app/layout_store.py`.
- CSP `script-src` now `'self' 'unsafe-inline'` to load `/layout.js`.
```

In `README.md`:
- In the feature list, add: "**Movable widgets and named screens** with a shared default layout and personal per-browser layouts (Edit button)".
- In "What is stored where", add the row: `| Shared dashboard layout | Docker volume utmstack-observatory-data (/data/layout.json) |`.
- In "Rebuild from GitHub", add the JS test command: `node --test tests/`.

- [ ] **Step 2: Full test run**

Run: `python3 -m unittest discover -s tests -v && node --test tests/`
Expected: everything PASS.

- [ ] **Step 3: Commit, push, deploy, verify**

```bash
git add -A && git commit -m "Movable widgets, named screens, shared and personal layouts (1.2.0)" && git push
```

Deploy exactly as for 1.1.2:
1. Back up into `~/observatory-backups/<timestamp>/`, including `layout.json` if present: `cp /data/layout.json /out/ 2>/dev/null || true` in the backup container.
2. `git archive HEAD` into `~/utmstack-observatory.new` on `utmstack112`, swap the directories, run `sudo ./install.sh`.
3. Wait for `/healthz` 200.

Then verify on the server:
- `GET /api/layout` returns version 0 and the three screens;
- a `PUT` without `X-Observatory` returns 403;
- the page contains `id="board"`.
