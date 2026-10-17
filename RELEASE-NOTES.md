# Release notes

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
