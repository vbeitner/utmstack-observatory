#!/usr/bin/env python3
# Copyright (c) 2026 Victor Beitner. All rights reserved. See LICENSE.
"""Rebuild app/land.json (world land outline for the live map) from world-atlas TopoJSON.

Source data: Natural Earth 1:110m land (public domain), packaged as TopoJSON by world-atlas (ISC):
  curl -fsSL -o land-110m.json https://cdn.jsdelivr.net/npm/world-atlas@2.0.2/land-110m.json
  python3 tools/build_land.py land-110m.json app/land.json

Output: {"rings": [[lon, lat, lon, lat, ...], ...]} with 0.1-degree precision (small, enough for a wall map).
"""
import json
import sys


def decode(topo):
    sx, sy = topo["transform"]["scale"]
    tx, ty = topo["transform"]["translate"]
    arcs = []
    for arc in topo["arcs"]:                      # delta-encoded, quantized coordinates
        x = y = 0
        pts = []
        for dx, dy in arc:
            x += dx; y += dy
            pts.append((x * sx + tx, y * sy + ty))
        arcs.append(pts)

    def ring(idx):
        out = []
        for i in idx:
            pts = arcs[i] if i >= 0 else arcs[~i][::-1]
            out.extend(pts if not out else pts[1:])
        return out

    rings = []
    for geom in topo["objects"]["land"]["geometries"]:
        polys = geom["arcs"] if geom["type"] == "MultiPolygon" else [geom["arcs"]]
        for poly in polys:
            for r in poly:
                rings.append(ring(r))
    return rings


def main(src, dst):
    rings = []
    for r in decode(json.load(open(src))):
        flat, last = [], None
        for lon, lat in r:
            p = (round(lon, 1), round(lat, 1))
            if p != last:
                flat.extend(p); last = p
        if len(flat) >= 8:
            rings.append(flat)
    json.dump({"source": "Natural Earth 1:110m land (public domain) via world-atlas 2.0.2", "rings": rings},
              open(dst, "w"), separators=(",", ":"))
    print("%d rings -> %s" % (len(rings), dst))


if __name__ == "__main__":
    main(*sys.argv[1:3])
