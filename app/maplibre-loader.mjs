// Copyright (c) 2026 Victor Beitner. All rights reserved. See LICENSE.
// MapLibre GL JS 6 is an ES module and the dashboard script is a classic one: load it here and hand it over.
// The server stamps __VERSION__ so an upgrade never pairs a new map library with a cached old worker.
import * as maplibregl from './maplibre-gl.mjs?v=__VERSION__';
maplibregl.setWorkerUrl(new URL('./maplibre-gl-worker.mjs?v=__VERSION__', import.meta.url).href);
window.maplibregl = maplibregl;
window.dispatchEvent(new Event('maplibre-ready'));
