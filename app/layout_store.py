# Copyright (c) 2026 Victor Beitner. All rights reserved. See LICENSE.
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
    "mapside": {"min_w": 3, "min_h": 8},
    "donut": {"min_w": 3, "min_h": 5},
    "rules": {"min_w": 3, "min_h": 6},
    "trend": {"min_w": 4, "min_h": 5},
    "rate": {"min_w": 4, "min_h": 2},
    "alerts": {"min_w": 4, "min_h": 5},
    "resources": {"min_w": 3, "min_h": 5},
    "ports": {"min_w": 4, "min_h": 6},
}


def _w(t, x, y, w, h):
    return {"type": t, "x": x, "y": y, "w": w, "h": h}


def default_layout():
    return {"schema": 1, "version": 0, "screens": [
        {"id": "overview", "name": "Overview", "wall": False, "widgets": [
            _w("kpis", 0, 0, 12, 4), _w("map", 0, 4, 8, 14), _w("donut", 8, 4, 4, 6), _w("rules", 8, 10, 4, 8),
            _w("trend", 0, 18, 12, 7), _w("rate", 0, 25, 12, 2), _w("alerts", 0, 27, 7, 9), _w("resources", 7, 27, 5, 9),
            _w("mapside", 0, 36, 4, 9), _w("ports", 4, 36, 8, 9)]},
        {"id": "live-map", "name": "Live map", "wall": True, "widgets": [_w("map", 0, 0, 8, 18), _w("mapside", 8, 0, 4, 18)]},
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


def load_with_notes(data_dir):
    """(layout, notes). A missing file gives the default silently; a file that exists but cannot be used gives the
    default plus a note, and is left untouched until the next save moves it aside."""
    path = os.path.join(data_dir, FILE)
    try:
        with open(path) as f:
            raw = json.load(f)
    except FileNotFoundError:
        return validate_layout(default_layout())[0], []
    except (OSError, ValueError):
        raw = None
    try:
        return validate_layout(raw)
    except ValueError as e:
        return (validate_layout(default_layout())[0],
                ["The saved shared layout could not be read (%s); showing the default. Saving a layout keeps the old "
                 "file as layout.json.bad-<time> next to it." % str(e)[:120]])


def load(data_dir):
    return load_with_notes(data_dir)[0]


def _stored_is_unusable(data_dir):
    path = os.path.join(data_dir, FILE)
    if not os.path.exists(path):
        return False
    try:
        with open(path) as f:
            validate_layout(json.load(f))
        return False
    except (OSError, ValueError):
        return True


def save(data_dir, layout):
    clean, _ = validate_layout(layout)
    if _stored_is_unusable(data_dir):           # never overwrite a file we cannot read (e.g. from a newer build)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        os.replace(os.path.join(data_dir, FILE), os.path.join(data_dir, "%s.bad-%s" % (FILE, stamp)))
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
