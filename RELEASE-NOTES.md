# Release notes

## 1.2.5 — 2026-10-17

**For users**
- Hovering a row in **Latest Alerts** or **Latest blocked inbound** now zooms and pans the live map
  to that location, with a pulsing marker and a label, so you can see where a connection or alert
  is coming from without leaving the list. Move off the row and the map eases back out; everything
  else on the map keeps animating normally while you look.
- Opening an alert's detail now shows a **Reputation** section next to WHOIS, with live abuse-score
  and vendor-detection lookups (AbuseIPDB and VirusTotal) for the IPs involved — when those are
  configured. Without an API key, that section just says so instead of showing nothing.

**Technical**
- `/api/geo` ticker entries and `/api/data` alert rows now carry `lat`/`lon` alongside their `ip`,
  sourced from the same geolocation object the IP came from (adversary, event origin, or target —
  never mixed). New shared `alert_ip_loc()` helper in `server.py`.
- New `/api/reputation?ip=` endpoint: AbuseIPDB (`ABUSEIPDB_KEY`) and VirusTotal (`VIRUSTOTAL_KEY`),
  each optional and independently gated, 24 h in-memory cache matching the existing WHOIS pattern.
  A provider failing never blocks the other.
- Map: hover-triggered camera is a pure canvas transform (translate/scale/translate) around the
  existing fixed world projection — no reprojection, so the land layer and hit-testing stay simple.
  The map's own mouse-hover tooltip is suppressed while a row-hover zoom is active to avoid the two
  fighting over the same tooltip element. Tests: 61 Python + 13 JS.

## 1.2.4 — 2026-10-17

**For users**
- No visible change to the dashboard. This release hardens the server against abuse: repeated wrong-password
  attempts from one address now get locked out for 15 minutes, a flood of connections is refused cleanly instead of
  piling up, and an HTTPS connection no longer lets one slow or idle client stall everyone else's page load.

**Technical**
- Login: per-IP failure tracking with a 5-attempt/15-minute lockout (`LOGIN_MAX_FAILURES`, `LOGIN_LOCK_S`), serialized
  so parallel guesses can't race past the limit; a success resets the counter; `/healthz` is never gated.
- Connections: new `MAX_CONNECTIONS` caps concurrent connections via a semaphore in `process_request`/
  `shutdown_request`; over the cap, new connections are closed immediately rather than queued as unbounded threads.
- TLS: the handshake now happens per-connection in `Handler.setup()` instead of on the listening socket, so one
  client's handshake (or an idle non-TLS connection) can no longer block every other client's accept. Responses over
  TLS now send `Strict-Transport-Security`.
- `Server` header no longer reveals the Python/BaseHTTP version; `REQUEST_TIMEOUT_S` (default 15s) drops idle/slow
  clients instead of holding a thread open indefinitely. Tests: 54 Python + 13 JS.

## 1.2.3 — 2026-10-17

**For users**
- The "make OpenSearch green" advice now gives **one command per system index family** instead of one for all of
  them. OpenSearch refuses the whole request if even one of those indices is protected, which is what happened when
  the advice was run on 2026-10-17; with separate commands, the allowed ones go through.
- A short note explains that a "403 no permissions" answer on a system index means it is protected and needs the
  OpenSearch super-admin certificate; the other steps are unaffected.

**Technical**
- `api_cluster().fix` gains `protected_note`; system families are emitted as separate steps. Tests: 44 Python + 13 JS.

## 1.2.2 — 2026-10-17

**For users**
- **Pause now freezes the screen but keeps collecting.** Clicking **Live** to pause stops every animation (the map's
  moving dots and pulses, the logo and the live dot) and holds all numbers and charts as they were. In the background
  the dashboard keeps fetching new data; the status shows how many updates have been collected. Clicking again shows
  the newest data at once and carries on live. Wall-mode rotation also pauses.
- Previously, pausing stopped fetching altogether, so nothing was collected while paused.

**Technical**
- `poll()` / `pollGeo()` keep running while paused and hold the newest answers; the map's animation loop stops on the
  paused frame (`frameT()`); the 60 s shared-layout refresh and wall rotation skip while paused. No server changes.

## 1.2.1 — 2026-10-17

**For users**
- 1.2.0 did not start on the server (it stopped with "No module named 'layout_store'") and was rolled back to 1.1.2
  within minutes. 1.2.1 is 1.2.0 with that fixed: everything listed under 1.2.0 below is now live.

**Technical**
- The container starts the dashboard with `python3 -I` (isolated mode), which leaves the app folder off `sys.path`, so
  the new `layout_store` module could not be imported. `server.py` now adds its own folder explicitly.
- New test `tests/test_container_start.py` starts `server.py` exactly like the container does, so this cannot slip
  through again. Tests: 43 Python + 13 JavaScript.

## 1.2.0 — 2026-10-17

**For users**
- **Screens.** Tabs under the header switch between screens. It starts with *Overview*, *Live map* and *Activity*. A
  green dot marks the screens that the wall display rotates through.
- **Move, resize, add and remove widgets.** Click **Edit** (right of the screen tabs): drag a widget by its *Move*
  handle, resize it from its bottom-right corner, remove it with ✕, or add one with **+ Widget**. Other widgets make
  room automatically. You can also add, rename, reorder and delete screens and choose which ones appear on the wall
  (**On wall**). Keyboard: focus a widget's *Move* handle, then arrow keys move it and Shift+arrows resize it. Click
  **Done** when finished.
- **Your layout or everyone's.** Changes start as your personal layout in this browser. **Save as shared default**
  makes it the layout everyone (and the wall screen) sees; **Reset to shared** goes back. If someone else changed the
  shared layout in the meantime, you are told before anything is overwritten.
- On screens narrower than 1100 pixels, widgets stack in one column and editing is switched off.
- **Fixed: the "make OpenSearch green" commands now work as printed.** They were missing `sudo`, so Docker refused
  them and nothing changed. They now read the OpenSearch password by themselves, run the data indices and OpenSearch's
  own system indices as separate steps, and print OpenSearch's answer.

**Technical**
- New `GET/PUT /api/layout` (shared layout in `/data/layout.json` on the existing volume, versioned; writes need
  `X-Observatory: 1` + JSON + same origin; 409 on a version conflict; the request body is always read before replying).
- New `app/layout.js` (pure layout functions, `node --test tests/`) and `app/layout_store.py`.
- CSP `script-src` now `'self' 'unsafe-inline'` to load `/layout.js`.
- Cluster advice: `api_cluster().fix` is now `{patterns, steps:[{title, cmd}]}`; optional `STACK_NAME` env (default
  `utmstack`).
- Tests: 42 Python + 13 JavaScript. The copy-paste OpenSearch commands only ever include index names matching `[a-z0-9._-]+`; anything else is listed for manual handling.

## 1.1.2 — 2026-10-17

**For users**
- **Support info.** Click the animated logo at the top left to open a Support panel: Cyber Security Canada's contact
  details (email and website), the dashboard version and install date, and a quick health summary (OpenSearch status,
  how fresh the data is, data sources online, whether the connection is encrypted).
- **Copy diagnostics** puts that summary on your clipboard to paste into a support email. It contains no passwords and
  no client names. On the wall screen the panel shows only the contact details and version.

**Technical**
- New endpoint `GET /api/support[?anon=1]`.
- New install option `--support "Name|email|phone|url"` (saved in `config.env`, passed as `SUPPORT_CONTACT`); default is
  Cyber Security Canada, info@cybersecuritycanada.com, https://cybersecuritycanada.com. The installer now also records
  `INSTALLED_AT`.
- 4 new tests (15 total).

## 1.1.1 — 2026-10-17

**For users**
- **The live map and the trend chart swapped places.** The Live Firewall Map now sits in the main row next to the
  event-source donut and alert rules; the real-time event trend and event rate run full width underneath it.
- The map zooms to fill its panel instead of leaving empty bands above and below the world: North America, Europe,
  Africa and the Middle East stay in view, and the far Pacific is cropped at the edges in narrower panels.

**Technical**
- Layout change only (`app/index.html`); no API or configuration changes.

## 1.1.0 — 2026-10-17

**For users**
- **Live Firewall Map.** A new panel shows every Sophos firewall on a world map, with animated lines to the cities it
  is talking to: blue for outbound, green for inbound that was allowed, red for denied. Next to it: connections per
  minute, the share denied, firewalls reporting, the most active countries, and a running list of the latest blocked
  inbound connections. Choose a 1, 5 or 15 minute window. Hover a dot for details.
- **Wall mode.** The new *Wall* button (or opening the dashboard with `?wall=1`) turns it into a full-screen display
  for a TV: client firewall names are replaced by "Site A, Site B…", and the screen alternates between the map and the
  counters every 30 seconds. Press Esc to leave.
- **The "Last 24 h" button now works.** It was a label that did nothing; it is now a 1 h / 6 h / 24 h picker for the
  event and alert counters, the event-source donut, the top alert rules and the latest-alerts list. Your choice is
  remembered in the browser. The AI Traffic panel and the drill-down views stay at 24 hours.
- **Easier to read.** Text throughout is larger and bolder with brighter grey labels, and panels were given more room so
  nothing is squeezed or cut off at common screen sizes (checked at 1280, 1440 and 1920 pixels wide, and on tablets).
- **Fixed:** clicking *Alert Rules / AI Traffic* or the Trends metric buttons no longer resets the 60-minute detail
  interval or un-highlights the other button groups.

**Technical**
- New endpoint `GET /api/geo?window=60|300|900[&anon=1]`, cached 10 s per window; anonymisation happens server-side.
- `GET /api/data?range=1|6|24`; 1 h and 6 h are built on request and cached for the refresh interval.
- New install options `--sites` and `--home` (saved in `config.env`, passed as `SITE_LOCATIONS` / `HOME_LOCATION`).
- New static asset `app/land.json` (Natural Earth, public domain) with generator `tools/build_land.py`.
- First automated tests: `tests/test_geo_and_range.py` (11 tests, OpenSearch stubbed).
- Project now lives in GitHub (`vbeitner/utmstack-observatory`); 1.0.0 was imported unchanged as the first commit.
