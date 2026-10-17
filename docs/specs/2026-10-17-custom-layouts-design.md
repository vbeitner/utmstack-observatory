# Observatory 1.2 — movable widgets, named screens, widget catalogue, support info

Date: 2026-10-17 · Status: draft for review

## 1. Intent

The user asked for:

1. Widgets that can be **moved** and **resized**.
2. The ability to **add widgets** to the screens.
3. **Support info** when the live logo at the top is clicked.

Decisions taken with the user:

| Question | Answer |
|---|---|
| Where a layout is saved | **Shared default + personal.** The server holds the shared layout. Any browser may rearrange it for itself and reset back to the shared one. |
| Screens | **Several named screens** (tabs). Wall mode rotates through the screens chosen for it. |
| Editing | **Move and resize on a 12-column grid**, inside an explicit Edit mode. |
| New widgets | MITRE ATT&CK heatmap, Top attackers, Per-firewall table, What's unusual today. |

Constraints carried over from 1.0/1.1:

- Python standard library only, and no external JS libraries.
- The CSP allows inline script only, and makes no third-party calls.
- The dashboard stays read-only toward UTMStack.
- Client firewall names must never reach a wall screen.

## 2. Data facts (checked on utmstack112, 2026-10-17)

- **Alert techniques.** Alerts carry `technique` (e.g. `T1114.003 - Email Collection from Remote System`), with 621 of 727 recent alerts `Indeterminate`. They also carry `category` (UTMStack's own grouping) and `adversary.geolocation` (country, ASN, AS org).
  - There is no tactic field, so the tactic comes from a bundled technique → tactic table.
- **Denied sources are mixed.** The busiest denied sources include internal hosts (192.168.x, 10.0.2.7), so "attackers" must be restricted to public addresses (those with `origin.geolocation`).
- **AS org is often absent.** `origin.geolocation.aso` is often empty in firewall logs. WHOIS (existing `/api/whois`) fills it on click.

## 3. Design

### 3.1 Widgets

Every panel becomes a widget type. A widget type defines:

- `title`;
- default size `w×h` (grid units) and minimum size;
- `render(container, data)`;
- which data feeds it needs (`data`, `geo`, `history`, or a widget-specific endpoint);
- `wallSafe`: `true`, `anon` (renders server-anonymised data in wall mode), or `false` (shows a "hidden in wall mode — contains client names" placeholder).

| Widget | Source | Wall |
|---|---|---|
| Key metrics (4 counters) | `/api/data` | true. The silent-sources line is hidden in wall mode. |
| Event trend | `/api/data` | true |
| Event rate | `/api/data` | true |
| Event source donut | `/api/data` | true. It shows data *types*, not client names. |
| Alert rules / AI traffic | `/api/data` | true |
| Latest alerts | `/api/data` | false. The source column shows client WAN IPs. |
| Resource utilisation | `/api/data` | true |
| Live firewall map | `/api/geo` | anon |
| **ATT&CK heatmap** (new) | `/api/attack?range=` | true |
| **Top attackers** (new) | `/api/attackers?window=` | anon. The target firewall becomes "Site X". |
| **Per-firewall table** (new) | `/api/firewalls?window=` | anon |
| **What's unusual today** (new) | `/api/unusual` | anon |

Each widget type appears at most once per screen, and only the active screen is in the DOM. Element ids therefore stay unique, and the existing render functions keep working with small changes: they look up elements inside their widget container instead of the document.

### 3.2 Grid, edit mode, screens

- **Grid.** 12 columns, 40 px row unit, 12 px gap. Each widget is placed with CSS Grid (`grid-column`/`grid-row`) from `{x, y, w, h}`.
  - Below 1100 px wide the grid becomes a single column, in reading order, and editing is disabled.
- **Edit button** in the header. In edit mode:
  - Widgets show a drag bar and a resize corner, and move with pointer events.
  - A drop pushes overlapped widgets down, then the layout compacts upward (no gaps).
  - Each widget gets an ✕ to remove it.
  - An **Add widget** menu lists the types not yet on this screen, each with a one-line description.
  - Screen tabs can be added, renamed, deleted and reordered, each with an "include in wall rotation" toggle.
  - Keyboard: arrow keys move the focused widget, and Shift+arrows resize it.
- **Default screens:**
  - **Overview:** today's 1.1.1 layout.
  - **Firewalls:** map, per-firewall table, top attackers.
  - **Threats:** ATT&CK heatmap, unusual today, latest alerts, alert rules.
- **Wall mode** rotates the screens marked for it, 30 s each by default, applying the `wallSafe` rules above.

### 3.3 Saving: shared default + personal

- **Shared layout:** `GET /api/layout` and `PUT /api/layout`, stored as `/data/layout.json` on the existing volume, so it survives upgrades.
  - The server validates the schema: known widget types, integer positions in range, at most 12 screens and 20 widgets per screen, under 64 KB.
- **CSRF protection** for the write, because Basic-auth credentials are sent automatically:
  - a `Content-Type: application/json` body;
  - a custom `X-Observatory: 1` header;
  - an `Origin` that, when present, must match `Host`.
- **Personal layout:** kept in the browser's local storage. While a personal layout exists, the header shows **"Personal layout · Reset to shared"**, and edit mode offers **"Save as shared default"**.
- **The wall screen** always uses the shared layout, so a TV never depends on one browser's state.
- **Versioning:** `layout.json` carries `schema: 1`. Unknown widget types from a newer or older version are dropped with a visible note, never a crash.

### 3.4 New endpoints (read-only, cached 10–30 s, shared across viewers)

- `/api/attack?range=1|6|24`
  - Alerts are grouped by technique ID, then mapped to their ATT&CK tactic(s) using the bundled table `app/attack.json`.
  - That table is generated by `tools/build_attack.py` from MITRE's enterprise-attack STIX data.
  - Output: per-tactic and per-technique counts, the count of Indeterminate alerts, and UTMStack's categories.
- `/api/attackers?window=…`
  - Public denied inbound sources: IP, country, AS org (when present), hits, distinct firewalls hit, first and last seen.
  - Covers the firewall logs plus alert `adversary` IPs, top 15.
- `/api/firewalls?window=…`
  - Per firewall: connections, denied %, top 3 destination countries, top denied port, last event time, location source.
- `/api/unusual`
  - Compares the current hour and today with baselines:
    - the stored 30-day hourly history (events, alerts, high alerts);
    - the last 24 h in OpenSearch (firewall denies per firewall, per-source event volume).
  - It reports only deviations ≥ 3× or ≤ ⅓ with a minimum volume, each with a plain-English sentence ("Firewall denies at Site C are 4.2× their usual level since 09:00").

### 3.5 Support info (logo click)

- **Logo becomes a button.** The animated logo becomes a button that opens a **Support** panel.
- **Panel contents:**
  - the support contact (name, email, phone, URL);
  - the Observatory version and build date;
  - the host;
  - OpenSearch status;
  - newest-data age;
  - the number of data sources;
  - the time of the last layout change;
  - a **Copy diagnostics** button. It puts a plain-text summary on the clipboard with no secrets and no client names.
- **Configuration:** the contact is set with a new install option `--support "Name|email|phone|url"`, saved in `config.env` and passed as `SUPPORT_CONTACT`.
- **Wall mode:** the panel is available, and shows only the contact and version.

### 3.6 Testing

- **Unit tests (OpenSearch stubbed):** layout validation, accept/reject cases; the CSRF checks; each new endpoint's aggregation; technique → tactic mapping; anonymisation of attackers, firewalls and unusual items; unusual-detection thresholds.
- **Browser checks:** drag, resize, add, remove, screens, persistence (shared vs personal), wall rotation of chosen screens, and the support panel, at 1280, 1440 and 1920 px and on a tablet.

## 4. Build order

Each step is shipped and verified before the next:

1. Support info on the logo click. Small and independent.
2. Widget refactor plus grid, edit mode and screens, with the existing widgets only. Shared and personal saving.
3. The new widgets, in this order: per-firewall table, top attackers, ATT&CK heatmap, unusual today.

## 5. Out of scope

- Widget-specific settings beyond time range or window.
- Multiple user accounts or per-user server layouts. The dashboard has one login.
- Dragging widgets between screens. Remove the widget, then add it on the other screen.
