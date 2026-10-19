# Release notes

## 1.20.0 — 2026-10-19

**For users**
- **Apply fix button** in the SIEM-health panel (click the OpenSearch status badge). When OpenSearch is yellow because
  of replica copies a one-server cluster can never place, enter your dashboard password and press **Apply fix**: the
  dashboard makes the change, shows each step with ✓ or ✗, and the badge turns green. No data is deleted. The
  copy-paste commands are still there under *Or fix it by hand*.
- The fix also covers OpenSearch's own index-management history (the cause of today's yellow status), which kept
  creating a new daily index with a replica.

**Technical**
- `POST /api/cluster/fix` (CSRF header + dashboard password, login lockout, `audit:` log line). The fix is re-derived
  server-side from `api_cluster()`; `_fix_op_allowed()` admits only replica-0 index settings, the two plugin cluster
  settings (`plugins.index_state_management.history.number_of_replicas`, `search.insights.top_queries.exporter.type`)
  and the `single-node-no-replicas` legacy template.
- `install.sh` creates OpenSearch user `observatory_fixer` with role `observatory_health_fix` (settings/template
  updates only), password in `/etc/utmstack-observatory/os_fixer.pass`, secret `os_fix_pass`; `--no-health-fix` skips
  it. `OS_FIX_USER` / `OS_FIX_PASS(_FILE)`; without them the button only appears when the main account can write.
- Tests: `tests/test_health_fix.py`, fixer role and installer cases in `tests/test_os_reader.py`.

## 1.19.0 — 2026-10-19

**For users**
- **Security update.** The dashboard now reads UTMStack's database with its own **read-only** account instead of
  UTMStack's administrator account. Even if a flaw were ever found in the dashboard, it could not delete or change your
  SIEM data. Nothing to do: re-running the installer sets this up and keeps the same account on later upgrades.
- The last lines of the install output now show which database account the dashboard uses. If it says the
  administrator account was kept, the warning above it explains why (for example, OpenSearch without its security
  plugin); the dashboard still works as before.
- New installer option `--os-account backend` to go back to the administrator account on purpose.

**Technical**
- Closes OBS-08. `install.sh` uses the backend's `ELASTICSEARCH_USER`/`ELASTICSEARCH_PASSWORD` once, through the
  OpenSearch security REST API (`_plugins/_security`, falling back to `_opendistro/_security`), to create or update
  role `observatory_read` (`cluster:monitor/*`; `read` + `view_index_metadata` on `v11-*`; `indices:monitor/*` on all
  indices for `_cat/indices` and `_cat/shards`) and user `observatory_reader` (role assigned directly, no role-mapping
  changes). Random password kept in `/etc/utmstack-observatory/os_reader.pass` (0600) so re-runs keep the user; passed
  as the `os_pass` Docker secret (`uid=10001,mode=0400`). The new user is tested (cluster health, `v11-*` count, full
  index list) before it is used; on any failure, or with the security plugin off, the installer warns and falls back
  to the backend credentials. Credentials go to curl inside node1 as a config file on stdin, never on a command line.
- `OS_ACCOUNT` saved in `config.env`. `install.sh` can now be sourced for tests.
- New `tests/test_os_reader.py`: 14 tests against a stubbed security API (fresh install, idempotent re-run, Open
  Distro path, plugin off, denied calls, unusable user, opt-out) plus a check that the role covers every OpenSearch
  path `app/server.py` queries.
- Not yet verified on a live UTMStack host.

## 1.18.0 — 2026-10-19

**For users**
- **One person's wrong passwords no longer lock everyone out.** Until now the dashboard saw every user as the same
  address, so five wrong passwords from anyone locked out all users for 15 minutes. It now sees each user's real
  address. **Re-run `sudo ./install.sh` on the server** to get this; nothing else changes for users.
- When a password was set in the Settings panel, the installer no longer warns "login check returned HTTP 401" at the
  end. It says the Settings-panel login is in use instead.

**Technical**
- `install.sh` publishes the port with `mode=host` instead of through Swarm's ingress routing mesh, and pins the
  service to the installing manager node (`node.id`, was `node.role==manager`). After removing the old service it
  waits for the old container to exit, so the host port is free before the new task starts. Health checks are
  unchanged; local `curl 127.0.0.1:$PORT` checks now arrive from the Docker bridge gateway.
- OBS-11: per-address lockout and `MAX_CONNECTIONS_PER_IP` now apply per real client on Swarm deployments.
- New `SHARED_ADDRESS_HINT_AFTER` (default 100): the server logs one `hint:` line when its first connections all come
  from one address on the container's own network, the sign of a deployment still behind the ingress mesh.
- `settings_store.py --configured KEY…` prints which Settings-panel overrides exist (names only); the installer uses
  it to skip its login check, which would otherwise count as a failed login.
- New tests: `tests/test_shared_address.py`.

## 1.16.2 — 2026-10-19

**For users**
- **Click an attacker** in the live map's blocked list to see what that address did in the last 24 hours: the ports it
  tried with their service names (SSH, RDP, SMB…), how many were denied and how many allowed, which sites and
  addresses it reached, and when it was first and last seen. Late replies to your own connections (for example from
  port 443) are counted separately, since they are not attacks.
- **Reports** have two new sections for the last 24 hours: **Denied connections** (ports attackers tried and the top
  attackers with the ports they used) and **Successful connections** (ports in use, connections allowed in from the
  internet, and the busiest connections showing who connected to whom).
- After an upgrade the browser always loads the new version of the page's scripts, so a refresh is no longer needed.

**Technical**
- New `/api/attacker?ip=` (60 s cache; `anon=1` hides site names and internal addresses for wall screens):
  one 24 h aggregation over `v11-log-*` by `origin.ip`, plus sshd lines in syslog matched on the exact address
  (counted as port 22). "Reply traffic" = remote port 1–1023 to local port ≥ 1024, shown apart.
- `report_connections()` adds two firewall aggregations to each report (≈0.5 s on 1.7 M connections a day); a
  failure there leaves the rest of the report intact.
- Script and stylesheet URLs carry `?v=<version>`. Demo mode answers both new data sources.

## 1.16.1 — 2026-10-19

**For users**
- Fixed the live map sometimes drawing only in a small box in its top-left corner, with the arcs squeezed into it.
  The street map now re-measures itself whenever its panel size and its own size disagree.
- The map credit line moved to the top-right corner, so it no longer covers the zoom-reset button on phones.

**Technical**
- 1.16.0 creates the street map after fetching its style (to strip attribution HTML), so it can be built before the
  layout has settled in some browsers. Resize the pending map from the ResizeObserver too, call `resize()` on load,
  and check canvas vs. container size once a second (`syncBaseSize`).

## 1.16.0 — 2026-10-19

**For users**
- **Security update.** A full security assessment was done; the report is in `docs/security/SECURITY-ASSESSMENT.md`.
  No critical or high issue was found, and the medium ones are fixed in this release.
- **Settings panel:** changing the login, an API key or the support contact now asks for your **current password**
  (new *Confirm* field at the bottom). New passwords need at least 12 characters.
- **New installs use HTTPS** with a self-signed certificate (the browser warns once). Existing installs keep their
  current setting; re-run the installer with `--tls` to switch.
- `sudo ./install.sh password` now really sets a new password, even one changed in the Settings panel, so it can be
  used to lock someone out. With no argument it generates a fresh one.
- New **user manual** with screenshots and short clips (`docs/manual/USER-MANUAL.md`), a click-through **feature tour**
  (`docs/tour/index.html`) and MP4 feature videos (`docs/media/video/`).
- The map credit line is now a small fixed text in the corner of the street map, and the browser tab has an icon.

**Technical**
- Fixes OBS-02…OBS-07, OBS-10, OBS-12…OBS-14, OBS-17 and parts of OBS-01, OBS-09, OBS-11, OBS-15, OBS-16, OBS-18:
  request-header deadline (`HEADER_DEADLINE_S`, 10 s) plus default connection caps (`MAX_CONNECTIONS=64`,
  `MAX_CONNECTIONS_PER_IP=32`) and a 128 listen backlog; the page script moved to `/app.js` and the CSP dropped
  `script-src 'unsafe-inline'` (added `object-src 'none'`, Permissions-Policy, COOP, CORP); MapLibre's attribution
  control replaced by fixed text (GHSA-jrc7-96c5-q579); re-authentication and `audit:` log lines for settings changes;
  PBKDF2-SHA256 (600k) for passwords saved in Settings, clear-text ones migrated at start-up; localhost-only `Host`
  check without a login (DNS rebinding); IPv6 zone ids refused and lookup URLs encoded; third-party numbers coerced;
  every error page and HEAD/OPTIONS/DELETE answer carries the security headers; generic error messages with a
  reference id; `OS_CA_FILE` to verify OpenSearch; installer: TLS default for new installs, `--no-tls`,
  `--password-file`, secrets mounted `uid=10001,mode=0400`, credentials to curl on stdin, Settings overrides cleared
  when the installer sets the same value.
- Image: Debian security updates applied at build, pip removed, `pillow>=12.3` pinned. Trivy: 0 fixable
  vulnerabilities; pip-audit: none. Requirements now need Python 3.10+ outside the container.
- Fixed the long-standing flaky `test_parallel_guessing_is_capped` (cause: socketserver's listen backlog of 5);
  11 new tests in `tests/test_security_fixes.py`.

## 1.15.0 — 2026-10-18

**For users**
- New **demo mode** for sales demos, screenshots and the manual: start the dashboard with `DEMO=1` and it shows a
  fictional organisation (eight Canadian sites, a few servers and an M365 tenant) with realistic, moving sample data
  on every panel — no SIEM connection needed. A yellow **DEMO DATA** tag next to the title makes it obvious.
  All public addresses come from the reserved documentation ranges, so no screenshot can show a real address.
- No change for normal installs: demo mode is off unless `DEMO=1` is set.

**Technical**
- New `app/demo.py`; `server.py` swaps its data functions for the demo ones when `DEMO=1` and skips the
  OpenSearch password lookup and GeoIP downloads. The map exposes its MapLibre handle on `#mapBase.__map` for
  scripted captures.

## 1.14.2 — 2026-10-18

**For users**
- An SSH attack logged as several lines within the same second now shows once in the blocked list, even when the
  lines differ by milliseconds.

## 1.14.1 — 2026-10-18

**For users**
- SSH attacks reported by Syslog now show port 22 in the blocked list, instead of the attacker's random source
  port.

## 1.14.0 — 2026-10-18

**For users**
- New **Any network / VPN / Tor / Hosting** switch on the Live map: show only traffic from known VPN ranges, Tor
  exit nodes or hosting/datacenter ranges. Works together with the source, direction and allowed/denied switches;
  the blocked list and top countries follow it too.
- New **Port** box: type a port (for example 22, 3389 or 443) and press Enter or Show to see only traffic to that
  port — where it comes from and where it goes. ✕ clears it. Windows and M365 events carry no port, so they drop
  out while a port is set; Syslog counts its SSH lines as port 22.

**Technical**
- `/api/geo` takes `port=1..65535` (a `target.port` filter on every query; cache keyed by window, type, port and
  cleared past 200 entries). VPN/Tor/hosting filtering is client-side over the per-arc counts (a floor for firewall
  arcs, from each city's 10 busiest addresses).

## 1.13.0 — 2026-10-18

**For users**
- **Tor and VPN are now told apart on the map:** traffic mostly from Tor exit nodes is **purple**, traffic mostly
  from known VPN ranges stays **yellow**. The legend, the badges in the blocked list and the city tooltips show
  them separately.

**Technical**
- `net_counts()` returns `{vpn, tor, hosting}`; arcs carry all three. An arc/dot takes the Tor or VPN color when
  the two together are at least half its connections, choosing whichever of the two is larger.

## 1.12.0 — 2026-10-18

**For users**
- The **Live map** (and **Activity**) screens now fill the whole window height instead of stopping at a fixed height,
  so on a large or tall monitor the map is a big, squarer view rather than a wide strip.
- The street map always covers its whole panel — no empty bands above and below the world when the panel is tall
  or square. The ⟲ button returns to that full view, centred on the Atlantic.

**Technical**
- `fitRows()` sizes `grid-auto-rows` for screens flagged `wall` to the space below the board top (not in edit mode,
  wall mode — which has its own CSS — or the single-column phone layout). `coverView()` sets the MapLibre start
  zoom and `minZoom` to `log2(max(w, h) / 512)`, updated on panel resize.

## 1.11.0 — 2026-10-18

**For users**
- Traffic that comes mostly from **known VPN ranges or Tor exit nodes** is now drawn in **yellow** on the map (arcs
  and city dots), with a "VPN / Tor" entry in the legend. This now covers firewall traffic too, not only Syslog,
  Linux and Windows attackers.
- City tooltips list VPN/Tor and hosting/datacenter connections separately. "Hosting" (datacenter ranges, where
  VPS servers and many VPNs live) keeps its normal color, because most internet attack traffic comes from such
  ranges; it's shown as a badge and in the tooltip.
- The marker that appears when you hover a blocked row is now white, so it can't be mistaken for VPN traffic.

**Technical**
- Inbound city buckets add a top-10 `origin.ip` terms agg; `net_counts()` classifies those IPs locally into `vpn`
  (VPN + Tor) and `hosting` per arc. An arc/dot is yellow when VPN/Tor make up at least half its connections.
  Counts come from each city's 10 busiest addresses, so they are a floor, not exact.

## 1.10.2 — 2026-10-18

**For users**
- One SSH attack no longer shows up two or three times in "Latest blocked / failed inbound" (sshd logs each attempt
  as several lines in the same second).

## 1.10.1 — 2026-10-18

**For users**
- The map credit (OpenFreeMap / OpenStreetMap) now starts folded into the (i) button instead of covering the top of
  the map. Source names on blocked rows are capitalized.

## 1.10.0 — 2026-10-18

**For users**
- Attackers seen by **Syslog** (e.g. "Invalid user … from 2.57.122.238"), **Linux** and **Windows** now appear on the
  map, located from the attacker's IP address. **M365** now includes every user's sign-in, including the ones
  UTMStack itself didn't place. Denied, dropped and failed events count as blocked attacks.
- Every attacker IP in "Latest blocked / failed inbound" gets a **VPN**, **Tor** or **Hosting** badge when it comes
  from a known VPN range, a Tor exit node or a datacenter/hosting range (where most VPNs and attack servers live).
  City tooltips show how many connections came from such addresses.
- With **All** selected, each blocked row shows which source reported it (Firewall, Syslog, Linux, …).
- The street map and the traffic arcs now move together when you pan or zoom, and the map renders at a lighter
  resolution so the animation stays smooth.
- On first start after the update, the dashboard downloads its location database (~60 MB); Syslog/Linux/Windows
  attackers show up on the map once that finishes (a few minutes).

**Technical**
- New `app/geoip.py`: DB-IP City Lite mmdb (CC BY 4.0, monthly) + X4BNet VPN / datacenter range lists + Tor bulk exit
  list, stored in `DATA_DIR/geoip` and refreshed every 6 h when stale (lists weekly, DB monthly). IPs the local
  database can't place go to proxycheck.io in a background queue (default cap 100/day, 7-day SQLite cache); set
  `install.sh --proxycheck-key KEY` for a higher limit or `--geoip-online-daily 0` to switch it off. Private and
  CGNAT/Tailscale addresses are never looked up. New dependency: `maxminddb==2.6.2`.
- `build_geo()` split into `build_net_geo()` (types UTMStack geolocates) + `add_attackers()` per log type; one
  failing source can't blank the map. `/api/geo` reports `geoip` status (DB date, list sizes, online lookups today).
- Arc layer redraws on MapLibre's `render` event while the map moves (no one-frame lag); idle animation capped at
  ~30 fps; map and arc layer use `pixelRatio` ≤ 1.25. Map credit starts folded.

## 1.9.0 — 2026-10-18

**For users**
- The Live Firewall Map now sits on a detailed dark street map (OpenStreetMap data). Zoom in to see countries,
  cities, roads and street names under the animated traffic arcs. Zoom with the mouse wheel, a double-click, or
  the + / − / ⟲ buttons; drag to move. On phones, pinch to zoom and use two fingers to move the map — one finger
  keeps scrolling the page.
- Keep in mind that IP locations are city-level at best (often only the country), so a dot shows the area a
  connection came from, never an exact street address.
- If the street map can't load (no internet on the viewing computer, or no WebGL), the dashboard keeps the
  previous outline map with its own zoom, as before.
- Each viewer's browser now loads map tiles from tiles.openfreemap.org (free OpenStreetMap service, no account).
  That service sees the viewer's IP and which map area is open, but not the dashboard's data or address.

**Technical**
- MapLibre GL JS 4.7.1 is vendored (`app/maplibre-gl.js`/`.css`, BSD-3, `app/MAPLIBRE-LICENSE.txt`) and served
  by the dashboard; only tiles, fonts and sprites come from `TILE_HOST`. CSP adds that one host to `img-src`/
  `connect-src`, plus `worker-src blob:` (MapLibre's worker) and `style-src 'self'`.
- The animation canvas stays on top; when the basemap is up, arcs project through `map.project()` and the
  canvas passes pointer events through to MapLibre. Hover-to-zoom on ticker rows uses `easeTo` and restores the
  previous view. Falls back to the built-in outline map if the style hasn't loaded within 12 s.

## 1.8.0 — 2026-10-18

**For users**
- The Live Firewall Map zooms and pans: use the **+ / − / ⟲** buttons (bottom right), the mouse wheel or a
  double-click to zoom, and drag to move around once zoomed in. On phones and tablets, pinch to zoom and drag
  with one finger; until you zoom in, a one-finger swipe still scrolls the page.
- On touch screens, tap a city or firewall dot to see its details (desktop still shows them on hover).
- On phones the map is taller, and the filter buttons scroll sideways instead of being cut off. The animations
  run on phones too (unless the device has "Reduce motion" turned on).

**Technical**
- User zoom/pan drives the same eased camera as the existing hover-to-zoom; land is drawn as vectors when zoomed
  (stays sharp) and from the cached raster at 1×. Hit targets are now stored in screen pixels so tooltips line
  up at any zoom. Canvas `touch-action` is `pan-y` at 1× and `none` once zoomed. Zoom range 1–8×.

## 1.7.1 — 2026-10-18

**For users**
- Fixed: on narrower screens the map's filter buttons wrapped onto a second row that was hidden behind the map.

**Technical**
- `.map-filters` overrides `.panel-head`'s fixed 50 px height so wrapped rows stay visible.

## 1.7.0 — 2026-10-18

**For users**
- New **All / Allowed / Denied** switch on the Live Firewall Map. Combine it with the source and
  Inbound / Outbound switches — for example, Firewall + Inbound + Denied shows only blocked attempts coming in.
  Top countries follow the same selection.

**Technical**
- Client-side only: `dirArcs()` now applies direction and outcome to the already-fetched arcs (allowed =
  `count - denied`), no new API call. Headline stats (connections/min, denied %) stay totals.

## 1.6.2 — 2026-10-18

**For users**
- Fixed: the live map was dimmed with a "View this source's events" button in the middle even when showing real
  traffic. That note now appears only for sources without location data (Windows, Linux, Syslog), as a slim bar
  across the top of the map instead of covering it.

**Technical**
- `.map-fallback` set `display:flex`, which overrode the `hidden` attribute; added `.map-fallback[hidden]
  {display:none}` (same pattern as `.top5-body[hidden]`) and turned the overlay into a top-anchored bar.

## 1.6.1 — 2026-10-18

**For users**
- Fixed: choosing **Google** on the map showed an error. It now shows an empty map until Google logs start
  arriving in UTMStack.

**Technical**
- `build_geo()` returns an empty payload when OpenSearch answers without `aggregations` (no index exists yet
  for the type).

## 1.6.0 — 2026-10-18

**For users**
- The map's source filter now starts on **All** and adds **M365** and **Google** next to Firewall. "All" shows
  traffic from every source that carries location data, both directions; pick one source to see just that one,
  and use All / Inbound / Outbound to choose the direction. M365 shows sign-in locations (inbound), with failed
  sign-ins in the "Latest blocked / failed inbound" list.
- Fixed: switching sources sometimes needed two clicks — a slow answer for the previous choice could overwrite
  the new one. The map now clears immediately on a switch and ignores late answers.
- Google shows an empty map for now: no Google Workspace / GCP logs are reaching UTMStack yet.

**Technical**
- `/api/geo` takes `type=all|firewall-sophos-xg|o365|google` (anything else means `all`); `build_geo()` scopes
  the index pattern and a `dataType.keyword` filter per type, cache keyed by (window, type). Idle firewall pins
  only appear on the All / Firewall views. Ticker counts `failed` as blocked for non-firewall sources.
- Live coverage check (24 h): firewall has origin+target geo, o365 origin only, linux/syslog/wineventlog none.
- OpenSearch was yellow from one unplaceable replica of the internal `top_queries-*` index (single-node
  cluster). Set its replicas to 0 and added index template `observatory-single-node-top-queries` so new daily
  indices don't ask for one — cluster is green.

## 1.5.0 — 2026-10-18

**For users**
- The Live Firewall Map now has a **data source type** filter (Firewall / Windows / Linux / Syslog) and an
  **inbound/outbound** filter. Only firewall and some cloud logs actually carry origin/destination locations —
  selecting Windows, Linux, or Syslog shows a note explaining that instead of an empty map, with a button
  straight to that source's own event/rule breakdown.
- The map's stats panel (connections/min, denied %, top countries, latest blocked inbound) is now its own
  movable, resizable widget — drag it anywhere, or remove it, independently of the map itself.

**Technical**
- No backend query changes: the type filter is purely a frontend gate (`GEO_TYPES` allowlist) since
  `/api/geo` only ever covered the firewall Sophos XG index; live-checked OpenSearch confirmed `linux`/
  `syslog`/`wineventlog` have zero `origin.geolocation`-tagged docs (vs. 537k for firewall, 74k for o365).
  The fallback reuses the existing `alerts-rule`-style dig entry point (`openDig({name:'sources', tab:'source',
  type})`), not a new view.
- Inbound/outbound is a pure client-side filter over the already-fetched `arcs` array (each carries `dir`) —
  no extra API round trip. Top-countries recomputes from filtered arcs when a direction is selected; falls
  back to the server-aggregated `countries` list (more precise) when showing all traffic.
- New `mapside` widget type, registered in both `app/layout.js`'s `WIDGETS` and `app/layout_store.py`'s
  `WIDGET_TYPES` (plus the hardcoded catalogue-sync assertion in `tests/layout.test.js`) — the map panel's
  sidebar markup moved from `.map-side` nested inside `#mapPanel` to its own top-level `data-widget="mapside"`
  section, which is all the existing drag/resize/add/remove system needed to pick it up.

## 1.4.0 — 2026-10-18

**For users**
- The **Alert Rules** list on the main dashboard is now clickable: click any rule bar to see every
  alert that fired it in the last 24 hours (same filtered alert list already reachable from a
  source's own rule breakdown), then click an alert for the full detail with source events,
  WHOIS, and reputation lookups.

**Technical**
- Wired `renderRules()`'s bar rows to the existing `alerts-rule` dig view (`openDig({name:'alerts',
  rule, source:''})`) instead of adding new UI — the backend `/api/alerts?rule=` filter and the
  `VIEWS.alerts`/`VIEWS.alert` views already existed, used elsewhere (per-source rule rows, "Same
  rule" button on alert detail). Added `.bar-row.clk` hover/focus styling and a `#top5Body`
  click+keydown entry point matching the existing `#alertBody`/`#kpiBand` pattern.

## 1.3.1 — 2026-10-17

**For users**
- **Latest blocked inbound** rows (Live Firewall Map) are now clickable, not just hoverable: click one to see
  WHOIS and live reputation (AbuseIPDB/VirusTotal) for that IP, the same panel alert detail already had. Hovering
  still pans the map to the location; click for the deeper lookup.
- Reports now include three more sections: an hourly events bar chart, the event-source-type breakdown, and
  OpenSearch/host health (cluster status, CPU/memory/disk) — all from data the dashboard already computes, no
  new OpenSearch load.

**Technical**
- `loadWhois()`/`loadReputation()` generalized to take an IP list instead of an alert object, so both
  `VIEWS.alert` and the new `VIEWS.ip` (blocked-inbound rows) share one lookup path.
- New `report_trend()` in `server.py` reads the local 24h-history SQLite table for the chart (the dashboard's
  own "minutes" series only ever covers the last 60 minutes, too short for a daily report).
- `reports.py`: hand-drawn bar charts via `fpdf2`'s own rect primitives for the PDF, an inline SVG for the HTML
  — no new dependency. Fixed a state-leak bug caught in visual review: the chart's fill/draw color wasn't reset
  afterward, bleeding blue into every table drawn below it.
- Tests: 93 Python + 13 JS (updated fixtures/assertions for the new report fields).

## 1.3.0 — 2026-10-17

**For users**
- New **Reports** button (header, top right): generate a PDF or HTML security report on demand, or set a daily
  generation hour in Settings and get one automatically. Each report covers the last 24 hours — event/alert
  summary, top alert rules and recent alerts (with MITRE ATT&CK technique where the underlying rule maps to
  one), the Live Firewall Map's top blocked-inbound countries, and storage/retention health. Past reports
  (last 30) are listed with download links for both formats.
- Alert data everywhere now carries its MITRE ATT&CK technique when the rule has one, so it's available for
  both the dashboard's alert detail view and the new reports.

**Technical**
- This is the one place the project steps outside "Python standard library only": PDF rendering uses `fpdf2`
  (see `requirements.txt`), a pure-Python library with no system dependencies, so the container build and
  `--read-only`/`--cap-drop ALL` runtime posture are unaffected.
- New `app/reports.py` (pure rendering + storage, no HTTP/OpenSearch): `render_html()`, `render_pdf()`,
  `generate()`/`list_reports()`/`prune()`. Files live in `/data/reports/`, same volume as history/layout/settings.
- `server.py`: `build_report_data()` reuses the existing `data_for()`/`build_geo()`/`api_storage()` aggregations
  (no new OpenSearch query shapes); a `report_loop()` background thread (same pattern as the existing
  history/lag loops) checks once a minute whether it's the configured hour and a report hasn't run yet today.
  New `GET`/`POST /api/reports*` routes, same auth as everything else; generation requires the same CSRF header
  as the layout/settings saves. New `report_hour` (0–23) setting, validated and exposed through the existing
  Settings panel.
- `alert_row()`/`alert_summary()` and their OpenSearch `_source` lists now include `technique`, dropping the
  literal string `"Indeterminate"` (not a real MITRE classification) the same way the UI already did.
- Verified against a real `docker build` of the image (not just unit tests): confirmed `fpdf2` imports and
  `server.py` starts cleanly under the container's own `python3 -I`. Tests: 93 Python + 13 JS.

## 1.2.6 — 2026-10-17

**For users**
- New **Settings** panel (gear icon, top right of the header): change the dashboard login, the AbuseIPDB and
  VirusTotal keys, the support contact, the map's home location and site pins, and the AI-traffic hosts —
  all without SSH access to the server. Changes apply immediately; changing the password signs you out and
  reloads the page so you can log back in with the new one. A link in the panel opens the existing layout
  editor (widgets/screens/wall rotation already had their own editor — this just makes it easier to find).
- `install.sh` also gained `--abuseipdb-key` / `--virustotal-key` for setting those keys at install time, as
  an alternative to the new panel.

**Technical**
- New `app/settings_store.py`: flat JSON store at `/data/settings.json` (same volume as the layout/history),
  atomic writes, 2 s read cache (this is now on the hot path of every authenticated request). Secrets
  (`dash_pass`, the two API keys) are written but never read back to a client — only a `*_configured` boolean.
- `DASH_USER`/`DASH_PASS`/`AI_HOSTS`/`HOME_LOCATION`/`SITE_LOCATIONS`/`SUPPORT_CONTACT`/the two API keys are
  now resolved per-request via `current_*()` accessors (settings-store override, env/install-time default as
  fallback) instead of being frozen at process start. `BIND`'s auto-detect and the no-auth startup guard now
  also check the settings store, so a password set only through the panel still binds correctly after a
  redeploy.
- New `GET`/`PUT /api/settings`, same auth/CSRF handling as the existing layout save; validation reuses
  `parse_loc`/`parse_sites`/`parse_support`, and rejects clearing or shortening the dashboard password below
  8 characters. Tests: 82 Python + 13 JS, including an end-to-end live-password-change test (old password
  401s, new one 200s, no restart).

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
