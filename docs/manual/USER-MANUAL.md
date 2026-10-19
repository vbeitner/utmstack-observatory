# UTMStack Observatory — User Manual

Version 1.21.0 · October 2026 · © 2026 Victor Beitner. All rights reserved.

UTMStack Observatory is a read-only operations dashboard for a UTMStack v11 SIEM. It sits next to UTMStack, reads
its OpenSearch data, and turns it into one screen a security team, an IT manager or a NOC wall can understand at a
glance: which data sources are reporting, how many events and alerts are coming in, where firewall traffic and
attacks come from on a live world map, and whether the SIEM itself is healthy.

It only reads UTMStack's data. The one exception is the optional **Apply fix** button in the SIEM-health panel,
which you press yourself to repair a yellow OpenSearch status (see [SIEM health](#8-siem-health)).

> Every screenshot and clip in this manual was taken in **demo mode**, which uses a fictional organisation and
> addresses from the reserved documentation ranges. No real customer data is shown. See
> [Demo mode](#13-demo-mode).

---

## Contents

1. [At a glance](#1-at-a-glance)
2. [Signing in](#2-signing-in)
3. [The header](#3-the-header)
4. [Overview screen](#4-overview-screen)
5. [Live map](#5-live-map)
6. [Alerts](#6-alerts)
7. [Data sources and ingest lag](#7-data-sources-and-ingest-lag)
8. [SIEM health](#8-siem-health)
9. [Trends and history](#9-trends-and-history)
10. [Reports](#10-reports)
11. [Screens, widgets and Wall mode](#11-screens-widgets-and-wall-mode)
12. [Settings panel](#12-settings-panel)
13. [Demo mode](#13-demo-mode)
14. [Installation and upgrades](#14-installation-and-upgrades)
15. [Configuration reference](#15-configuration-reference)
16. [Security and privacy](#16-security-and-privacy)
17. [Troubleshooting](#17-troubleshooting)
18. [Third-party data and licences](#18-third-party-data-and-licences)
19. [Copyright](#19-copyright)

---

## 1. At a glance

![Overview screen](../media/screens/01-overview.jpg)

| You want to know… | Look at |
|---|---|
| Is every log source still sending? | **Online data sources** card |
| How busy is the SIEM, and is that normal? | **Events** card (with change against the previous period) |
| Is anything being flagged? | **Alerts** card and the **Alert Rules** panel |
| Are logs arriving late? | **Ingest lag** card |
| Where is traffic going, and who is attacking us? | **Live map** |
| Is UTMStack's database healthy? | The **OpenSearch** status badge next to the title |
| How does this week compare with last week? | **Trends** |
| Something to send to management | **Reports** (PDF or HTML) |

The dashboard refreshes itself every few seconds. **Live** in the header means you are looking at current data.

## 2. Signing in

Open the address your administrator gave you, for example `https://siem-server:8765`. The sign-in page opens.

- **With your email address** (since 1.22): enter the address your administrator added and click *Email me a
  sign-in link*. Open the email and click **Sign in**, then **Continue**. The link works once and expires after 15
  minutes; ask for a new one if it has. You stay signed in for 7 days in that browser.
- **With the administrator password**: click *Sign in with the administrator password*. The default user is `admin`;
  the installer generates the password and prints it once at the end of the install. This is the only way in until
  email sign-in is set up (see [Settings panel](#12-settings-panel)), and always signs in as an admin.

- After **5 wrong passwords** from the same address, that address is locked out for **15 minutes**, even if the next
  attempt is correct. Both numbers can be changed (see [Configuration reference](#15-configuration-reference)).
  The dashboard sees each user's real address, also over Tailscale (since 1.21), so one person's typos never lock
  anyone else out. If many wrong passwords arrive from many addresses at once, every failed attempt is slowed down
  instead, so nobody is locked out by someone else's attack.
- To change the password, use the [Settings panel](#12-settings-panel) or `sudo ./install.sh password` on the server.
- To sign out, open Settings and click **Sign out**.
- Wrong or expired sign-in links count as failed sign-ins for the lockout above. Asking for links is limited to 3 per
  address and 5 per computer in 15 minutes.

## 3. The header

| Control | What it does |
|---|---|
| **Logo** | Shows your support contact (name, email, phone, website) and the installed version. |
| **OpenSearch status badge** (green / yellow / red) | Health of UTMStack's database. Click it to see what is causing a yellow or red state and how to fix it. See [SIEM health](#8-siem-health). |
| **Feed status / Last update** | Whether the dashboard is receiving data and when it last refreshed. |
| **Live · 1 h · 6 h · 24 h** | Time range for the counters, the event-source donut, the top alert rules and the alert list. **Live** keeps the default 24-hour view moving. |
| **Wall** | Full-screen NOC mode with site names hidden. See [Wall mode](#wall-mode). |
| **Trends · 30 d** | 30 days of history with daily and weekly comparisons. |
| **Reports** | Generated PDF/HTML reports and a **Generate now** button. |
| **Gear** | Settings panel. |
| **Full screen** | Uses the whole monitor without entering Wall mode. |

Below the header are the **screen tabs** (Overview, Live map, Activity, and any screens you add) and the **Edit**
button for changing the layout.

## 4. Overview screen

![Overview, full page](../media/screens/01b-overview-full.jpg)

**KPI cards** (top row):

- **Online data sources**: sources that reported in the last 10 minutes, out of all known sources. *No silent
  sources* means everything is reporting. Click the card for the full source list.
- **Events**: events stored in the selected period, the change against the previous period, and the peak rate.
- **Alerts**: alerts raised in the period, split by severity (High / Medium / Low), and the share of events that
  raised an alert. Click it for the alert list.
- **Ingest lag**: how old the newest stored event is. A green value of a few seconds is normal. Click it for the
  per-source analysis.

**Panels** (all movable, see [Screens and widgets](#11-screens-widgets-and-wall-mode)):

- **Live firewall map**: a compact version of the [Live map](#5-live-map).
- **Event source distribution**: a donut of events by source type (firewall, Linux, Windows, syslog, Microsoft 365…).
- **Alert Rules**: the rules raising the most alerts. **Click a rule** to open its alerts.
- **AI Traffic** (optional): bytes in and out of chosen servers, for example AI or GPU hosts, measured from firewall
  logs. Turned on by listing hosts in the Settings panel.
- **Alert timeline**, **storage**, **resources** and other widgets can be added from the widget catalogue.

![AI Traffic tab](../media/screens/17-ai-traffic.jpg)

## 5. Live map

The Live map draws every connection the firewalls log as an arc between the firewall and the remote city, and plots
attackers seen in server and cloud logs.

![Live map](../media/screens/02-live-map.jpg)

### Reading the map

| Colour | Meaning |
|---|---|
| Cyan | Outbound: a local device connected out |
| Blue-green | Inbound and allowed |
| Red | Denied or failed (blocked by the firewall, or a failed login) |
| Yellow | From a known VPN range |
| Purple | From a Tor exit node |
| White dots | Your firewalls |

Arcs move in the direction of the traffic. The side panel shows connections per minute, the percentage denied, top
countries, and **Latest blocked / failed inbound**, a ticker of the newest blocked connections with their source
address, location, target and port. Badges on a row mark **VPN**, **Tor** or **Hosting** (datacenter) addresses.
Hover a ticker row to highlight that location on the map; click it for the attacker panel described below.

### Window and filters

- **1 min · 5 min · 15 min**: how much recent traffic is drawn.
- **Source**: All, Firewall, M365, Google, Windows, Linux, Syslog. Only sources that carry IP addresses can be
  placed; a short bar at the top of the map says so when the selected source has nothing to show.
- **Direction**: All, Inbound, Outbound.
- **Outcome**: All, Allowed, Denied.
- **Network**: Any network, VPN, Tor, Hosting.
- **Port**: type a port (for example `22`, `3389`, `443`) and press **Enter** or **Show** to see only traffic to that
  port. **✕** clears it. Windows and Microsoft 365 events carry no port, so they drop out while a port is set.

All filters combine. The side panel and ticker follow them.

![Map filters in action](../media/gif/map-filters.gif)

*Tor traffic only:*

![Tor only](../media/screens/03-map-tor.jpg)

*Port search: where SSH (22) and RDP (3389) attempts come from:*

![Port search](../media/gif/port-search.gif)

*Attackers found in server logs (syslog / SSH):*

![Syslog attackers](../media/screens/06-map-syslog-attackers.jpg)

### Zoom and street map

Use **+ / − / ⟲**, the mouse wheel, double-click or drag; on a phone, pinch and drag (a single tap shows a tooltip).
Zoom in far enough and a street-level map appears underneath the arcs.

![Zoom to street level](../media/gif/zoom-street-map.gif)

> IP-based location is city-level at best. The street map adds context; it does not pinpoint an attacker's building.

![Hovering blocked rows](../media/gif/blocked-row-zoom.gif)

### Looking at one attacker

**Click a row** in *Latest blocked / failed inbound* to open that address. Under **Activity from this address**
you see what it did in the last 24 hours, across every site:

- connections in total, how many were **denied** and how many were **allowed**, and when it was first and last seen;
- **Ports tried**: each port it aimed at on your side, with its service name (22 SSH, 3389 RDP, 445 SMB…) and the
  denied/allowed count. A yellow note appears if any connection on those ports was allowed, which is worth checking;
- **Sites it reached** and the **addresses it targeted** behind them;
- the firewall's own reason when it gives one (for example a failed VPN-portal login).

Denied packets that come *from* a web or DNS port (443, 80, 53) *to* a random high port are almost always late
replies to connections your own devices had already closed. They are counted separately as "late replies" and
left out of the ports list, so the list shows only what was really tried. Reputation and WHOIS for the address
follow below. On a wall screen the panel shows *Site A, Site B…* and no internal addresses.

![Attacker panel](../media/screens/22-attacker.jpg)

### Where locations come from

1. UTMStack's own GeoIP enrichment, when present in the log.
2. A local copy of the DB-IP City Lite database, plus VPN, datacenter and Tor exit lists, downloaded and refreshed
   automatically by the dashboard.
3. Optionally, an online lookup (proxycheck.io) for addresses the local data cannot place, capped at a daily
   number (default 100, `0` turns it off).

Private addresses (10.x, 192.168.x, …) are never placed on the map and never sent anywhere.

## 6. Alerts

Click a rule in **Alert Rules**, or the **Alerts** card, to open the alert list.

![Alerts for one rule](../media/screens/07-alerts-for-rule.jpg)

Filter by **Severity**, **Source**, **Rule** and free-text **Search**, then **Apply**. **Newer / Older** page
through the results.

Click an alert to open its detail:

![Alert detail](../media/screens/08-alert-detail.jpg)

- **Recommended action**: what to do about it, in plain language.
- **Source**, **More from this source**, **Same rule**: jump to related alerts.
- **Details**: every field UTMStack stored for the alert.
- **Reputation**: live AbuseIPDB score and VirusTotal detections for the alert's public addresses, when API keys are
  configured.
- **WHOIS**: who owns each public address (registry, organisation, abuse contact).

![Alert drill-down](../media/gif/alert-drilldown.gif)

## 7. Data sources and ingest lag

Click **Online data sources** for every source, its type, event count, share, a 24-hour sparkline, when it last
reported and its status. Switch between **By source** and **By type**.

![Data sources](../media/screens/09-data-sources.jpg)

Click a source for its event history, the alerts it raised and its most recent events:

![Source detail](../media/screens/10-source-detail.jpg)

Click **Ingest lag** for the delay per source: the time between when a device logged an event and when UTMStack
stored it. Firewalls often send logs in batches, and Microsoft 365 is polled, so a delay of minutes is normal for
those.

![Ingest lag](../media/screens/11-ingest-lag.jpg)

## 8. SIEM health

The badge next to the title shows the health of UTMStack's OpenSearch cluster. Click it for an explanation in plain
language: whether data is safe, which shards are unassigned and why, and the commands that fix it.
**Copy diagnostics** puts the technical details on the clipboard for your support provider.

![Cluster health](../media/screens/12-cluster-health.jpg)

| Badge | Meaning |
|---|---|
| Green | Everything is assigned and searchable. |
| Yellow | All data is available, but some replica copies are missing. Common on single-node installs; usually not urgent. |
| Red | Some data is not searchable. Act on the advice in the panel. |

**Apply fix.** When the cause is one the dashboard knows how to fix safely (replica copies a one-server cluster can
never place, and the plugins that keep asking for them), an **Apply fix** button appears under *Apply the fix*.
Enter your dashboard password and press it. The dashboard re-checks the cluster, runs only those changes (no data
is deleted) and lists each step with ✓ or ✗; the status badge turns green within a few seconds. A step on
OpenSearch's protected security audit log can answer ✗ "protected index": that one needs the super-admin
certificate, and the commands under *Or fix it by hand* still work for it. The button uses a separate, narrow
OpenSearch account (`observatory_fixer`) that may only change replica settings; installs with
`--no-health-fix` show only the commands.

![Apply fix](../media/screens/20-apply-fix.jpg)

## 9. Trends and history

**Trends · 30 d** shows hourly history for the last 30 days (events, alerts and, if enabled, AI traffic), a
**daily comparison** (last 24 h against the 24 h before) and a **weekly comparison** (last 7 days against the
7 before).

![Trends](../media/screens/13-trends.jpg)

OpenSearch on a UTMStack server usually keeps raw logs for only about a day, so the dashboard keeps its own small
history database (counts only, never raw events). History starts when the dashboard is installed. Comparisons show
*n/a* or *partial* until both periods have at least 90% of their hours: about a day for daily, two weeks for weekly.

## 10. Reports

**Reports** lists generated reports, newest first, each as **PDF** and **HTML**. **Generate now** makes one for the
last 24 hours. Every page carries the UTMStack Observatory logo, the host and date at the top, and the copyright
notice and page number at the bottom. The first page opens with four key figures (events, alerts, data sources,
blocked attempts) and **Key findings**: up to six plain-language points to read first, such as SSH or RDP allowed in
from the internet, high-severity alerts, silent data sources or an OpenSearch status that is not green. Then come
the trend, top alert rules and recent alerts (with the MITRE ATT&CK technique where the rule has one), traffic by
country, and the sections below.

![Report, first page](../media/screens/21-report.jpg)

![Reports](../media/screens/14-reports.jpg)

Two sections cover the firewall traffic of the last 24 hours:

- **Denied connections**: all denied connections, the inbound attempts from the internet (and from how many
  addresses), the late replies that were dropped, the **ports attackers tried** with their service names, and the
  **top attackers** with their country, VPN/Tor/hosting network, the ports each one used and the sites it targeted.
- **Successful connections**: the **ports in use**, connections **allowed in from the internet** (who, from where,
  to which site and address, on which ports), and the **busiest connections — who to whom** (source, destination,
  inbound/outbound/internal, ports and firewall).

To get a report every day automatically, set **Report hour** (0–23, UTC) in the Settings panel. The last 30 reports
are kept. Downloads need the dashboard login.

A sample report made from demo data is in [`../media/sample-report.pdf`](../media/sample-report.pdf).

## 11. Screens, widgets and Wall mode

### Editing the layout

Click **Edit** (right of the screen tabs).

![Edit layout](../media/screens/16-edit-layout.jpg)

- Drag a panel by its **⠿ Move** handle; resize it from the corner.
- **+ Widget** opens the widget catalogue. **+ Screen** adds a new tab; **Rename** and **Delete screen** manage it.
- **On wall** includes the screen in Wall-mode rotation.
- **Save as shared default** makes your layout the one everyone sees. **Reset to shared** drops your personal changes.
- Click **Done** to leave edit mode.

Without saving as shared, layout changes are personal to your browser.

![Moving a widget](../media/gif/edit-layout.gif)

### Wall mode

**Wall** (or open `/?wall=1`) turns the dashboard into a NOC display: full screen, rotating through the screens
marked *On wall* every 30 seconds. Firewall names and WAN addresses are replaced by **Site A, Site B…** on the server
before they are sent, so a wall screen in a lobby never shows them. Panels that list data-source names are left out.
Press **Esc** to leave.

### Phones and tablets

The dashboard works on a phone. Panels stack, and the map gets a taller view with touch zoom.

<p>
<img src="../media/screens/18-mobile-overview.jpg" alt="Phone: overview" width="260">
<img src="../media/screens/19-mobile-map.jpg" alt="Phone: map" width="260">
</p>

## 12. Settings panel

The **gear** icon opens Settings. Viewers see only who they are signed in as and *Sign out*; everything else is for
admins. Changes apply immediately, with no restart. Changing users, the login, email settings, an API key or the
support contact needs your **current password** in the *Confirm* field at the bottom if you signed in with the
password, or a sign-in from the last 15 minutes if you signed in by email link (otherwise sign out and in again).
A value saved here overrides the matching installer option; clearing a field and saving falls back to the
installer's value.

![Settings](../media/screens/15-settings.jpg)

| Section | Settings |
|---|---|
| **Signed in** | Your address, role and how you signed in; **Sign out**. |
| **Users** | Add people by email as *viewer* (every panel, layout, reports) or *admin* (also users, settings, API keys, *Apply fix*), change a role or remove someone (they are signed out at once). *Email an invitation* sends them the dashboard address. You cannot remove or demote yourself. |
| **Email for sign-in links** | The dashboard's public address (where links point), and how to send: an SMTP server (host, port, encryption, username, password) or Microsoft 365 through the Graph API (tenant ID, client ID, client secret of an app registration with the *Mail.Send* application permission). The sender address, then **Send test email**. |
| **Administrator password** | The break-glass admin login: user name and password (at least 12 characters). Changing the password signs out everyone who signed in with the old one. |
| **API keys** | AbuseIPDB and VirusTotal keys for the Reputation section of alert detail. Keys are write-only: the panel shows whether a key is set, never the key itself. |
| **Support contact** | Name, email, phone and website shown when the logo is clicked. |
| **Live map** | Home location (where firewalls without a known location are drawn) and site pins (`FirewallName=lat,lon,City;203.0.113.7=lat,lon`). |
| **AI traffic** | Hosts to measure, as `name=ip,name=ip`. Empty hides the AI Traffic tab. |
| **Reports** | Daily report hour (0–23, UTC). Empty means on demand only. |
| **Dashboard layout** | Shortcut to the layout editor. |

## 13. Demo mode

Demo mode runs the dashboard on realistic, fully synthetic data, for sales demos, training and screenshots. It needs
no UTMStack and no internet connection (the street map tiles excepted).

- A fictional organisation: eight Canadian sites, Linux, Windows and storage servers, and a Microsoft 365 tenant.
- Every panel, drill-down, report, WHOIS and reputation lookup answers with sample data that moves over time like a
  live system.
- All public addresses come from the reserved documentation ranges `192.0.2.0/24`, `198.51.100.0/24` and
  `203.0.113.0/24`, so no screenshot can show a real company's address.
- A yellow **DEMO DATA** tag appears next to the title.

Start it on any machine with Python 3.10+ and `pip install -r requirements.txt`:

```bash
cd app
DEMO=1 DASH_PASS=choose-a-password python3 server.py
```

Then open `http://<machine>:8765`. Demo mode is off unless `DEMO=1` is set; never set it on a production install.

## 14. Installation and upgrades

**Requirements:** a UTMStack v11 server (Docker Swarm), root or sudo, and internet access for the first image build.

```bash
git clone https://github.com/vbeitner/utmstack-observatory.git
cd utmstack-observatory
sudo ./install.sh
```

The installer finds the UTMStack stack, reads the OpenSearch credentials UTMStack already uses, checks they work,
uses them once to create a dedicated **read-only** OpenSearch user for the dashboard, builds the image, starts the service and prints the address and a generated password.

To **upgrade**, get the new version and run the installer again (`git pull && sudo ./install.sh`). Password,
settings and history are kept.

| Command | What it does |
|---|---|
| `sudo ./install.sh` | Install or upgrade |
| `sudo ./install.sh status` | Service state and health |
| `sudo ./install.sh logs` | Service logs |
| `sudo ./install.sh password [NEW]` | Set a password, or generate a new one. Also removes a password set in the Settings panel, so it revokes it |
| `sudo ./install.sh uninstall` | Remove the service, keep history and settings |
| `sudo ./install.sh uninstall --purge` | Remove everything, including history, settings and the image |

## 15. Configuration reference

### Installer options

Options are remembered in `/etc/utmstack-observatory/config.env`; pass one again to change it.

| Option | Default | Meaning |
|---|---|---|
| `--port N` | `8765` | Port the dashboard listens on |
| `--user NAME` | `admin` | Dashboard user name |
| `--password PW` / `--password-file F` | generated | Dashboard password (12+ characters; the file form keeps it out of the process list) |
| `--tls` / `--no-tls` | on for new installs | HTTPS with a generated self-signed certificate, or plain HTTP |
| `--tls-cert FILE --tls-key FILE` | | HTTPS with your own certificate |
| `--tz ZONE` | host's | Time zone for day boundaries, e.g. `America/Toronto` |
| `--stack NAME` | auto | UTMStack Swarm stack name |
| `--import-history FILE` | | Seed history from an earlier install |
| `--sites "Name=lat,lon,City;IP=lat,lon"` | | Pin firewalls the map cannot place |
| `--home "lat,lon,City"` | Toronto | Where unplaced firewalls are drawn |
| `--support "Name\|email\|phone\|url"` | vendor | Contact shown under the logo |
| `--ai-hosts "name=ip,name=ip"` | off | Enable AI Traffic for these hosts |
| `--abuseipdb-key KEY` | off | AbuseIPDB reputation lookups |
| `--virustotal-key KEY` | off | VirusTotal reputation lookups |
| `--proxycheck-key KEY` | none | proxycheck.io key for the online location fallback |
| `--geoip-online-daily N` | `100` | Daily cap on online lookups; `0` disables them |
| `--no-health-fix` | button on | No *Apply fix* button in the SIEM-health panel (commands only) |
| `--no-real-ip-rule` | rule on | Do not install the firewall rule that keeps Tailscale users' real addresses (only installed when Tailscale is present) |
| `--os-account reader\|backend` | `reader` | OpenSearch account for the dashboard: the read-only `observatory_reader`, or UTMStack's administrator |
| `--admin-email ADDR` | | Add this address as an admin; it signs in by email link once email is set up |
| `--public-url URL` | | The address people open, e.g. `https://observatory.example.com:8765`; sign-in links point here |

### Environment variables

Only needed when running `app/server.py` yourself; the installer sets them for you.

| Variable | Default | Meaning |
|---|---|---|
| `OS_URL` | | OpenSearch URL, e.g. `https://node1:9200`. Empty = use `docker exec` on the host |
| `OS_USER`, `OS_PASS` / `OS_PASS_FILE` | | OpenSearch credentials (the installer sets the read-only `observatory_reader`) |
| `DASH_USER`, `DASH_PASS` / `DASH_PASS_FILE` | `admin` | Dashboard login. Without a password it only listens on 127.0.0.1 |
| `ADMIN_EMAIL`, `PUBLIC_URL` | | Same as `--admin-email` and `--public-url` |
| `SESSION_DAYS`, `LINK_MINUTES`, `REAUTH_MINUTES` | `7`, `15`, `15` | How long a sign-in lasts; how long a sign-in link works; how recent an email sign-in must be for sensitive changes |
| `PORT`, `BIND` | `8765`, `0.0.0.0` | Listening port and address |
| `TLS_CERT`, `TLS_KEY` | | Certificate and key files; enables HTTPS |
| `DATA_DIR` | app folder | History database, settings, layout, reports and IP data |
| `DISK_PATH` | `/utmstack` | Filesystem whose free space is reported |
| `HOST_NAME`, `TZ` | | Host name shown in the resource panel; time zone |
| `STACK_NAME` | `utmstack` | UTMStack stack name |
| `AI_HOSTS` | | `name=ip,name=ip` |
| `SITE_LOCATIONS`, `HOME_LOCATION` | | Same as `--sites` and `--home` |
| `SUPPORT_CONTACT` | | Same as `--support` |
| `ABUSEIPDB_KEY`, `VIRUSTOTAL_KEY` (or `_FILE`) | | Reputation API keys |
| `PROXYCHECK_KEY`, `GEOIP_ONLINE_DAILY` | , `100` | Online location fallback |
| `LOGIN_MAX_FAILURES`, `LOGIN_LOCK_S` | `5`, `900` | Lockout after N failures, for S seconds |
| `LOGIN_SURGE_PER_MIN` | `30` | Above this many failed logins a minute from all addresses together, every failed attempt is answered slowly; `0` = off |
| `OS_FIX_USER`, `OS_FIX_PASS` / `OS_FIX_PASS_FILE` | | OpenSearch account for the *Apply fix* button (the installer sets `observatory_fixer`) |
| `MAX_CONNECTIONS`, `MAX_CONNECTIONS_PER_IP` | `64`, `32` | Concurrent connections in total and per address; extra ones are refused at once |
| `SHARED_ADDRESS_HINT_AFTER` | `100` | Log a one-time hint when this many first connections all came from one Swarm network address; `0` = off |
| `HEADER_DEADLINE_S` | `10` | A client must send its whole request header within this time |
| `ALLOWED_HOSTS` | | Extra host names accepted when no login is configured (otherwise only localhost) |
| `OS_CA_FILE`, `OS_CHECK_HOSTNAME` | , `1` | Verify OpenSearch's certificate against this CA |
| `REQUEST_TIMEOUT_S` | `15` | Slow or idle clients are dropped after this |
| `DEMO` | off | `1` = demo mode, see [Demo mode](#13-demo-mode) |
| `ALLOW_NO_AUTH` | off | `1` = allow listening on a network address with no password (testing only) |

### What is stored where

| What | Where |
|---|---|
| 30-day history, storage sizes | Docker volume `utmstack-observatory-data` → `/data/history.db` |
| Live settings, shared layout | `/data/settings.json`, `/data/layout.json` |
| Users and open sign-ins (digests of the tokens, never the tokens) | `/data/users.json` |
| Reports (last 30) | `/data/reports/` |
| IP location and VPN/Tor data | `/data/geoip/` |
| Installer settings | `/etc/utmstack-observatory/config.env` |
| Dashboard password | `/etc/utmstack-observatory/admin.pass` (root only); a password set in Settings is stored hashed |
| OpenSearch account passwords | `/etc/utmstack-observatory/os_reader.pass`, `os_fixer.pass` (root only) |
| Tailscale real-address rule | `/usr/local/sbin/utmstack-observatory-real-ip` and the systemd unit `utmstack-observatory-real-ip` |

## 16. Security and privacy

- **Read-only**: the dashboard only reads OpenSearch. It cannot change UTMStack. Since 1.17 it also reads with its own
  read-only OpenSearch account (`observatory_reader`), so even a fault in the dashboard could not delete or change SIEM
  data. If that account cannot be set up (for example on a UTMStack without OpenSearch security), the installer warns
  and uses UTMStack's own account instead. The install output ends with the account in use.
- **Apply fix** uses a second, narrow OpenSearch account (`observatory_fixer`) that can only change replica
  settings; it cannot read, change or delete data. The dashboard works out the fix from the cluster itself and runs
  only a fixed list of changes, and only after you enter your password. `--no-health-fix` leaves it out.
- **Login on everything** except a minimal health check and the sign-in page. Repeated wrong passwords or sign-in
  links lock out the source address, and a wave of failures from many addresses slows every failed attempt down.
  Changing users, the login, email, an API key or the support contact also asks for the current password (or a
  recent email sign-in), and every change is logged with who made it.
- **Email sign-in links** work once, expire after 15 minutes and are only used when you click *Continue*, so a mail
  filter that opens links ahead of you cannot use them. The link's secret is after the `#`, which browsers never send
  to a server or proxy. The dashboard answers the same way whether or not an address has access, so nobody can use the
  sign-in page to find out who does.
- **Container hardening**: read-only file system, all Linux capabilities dropped, unprivileged user, no Docker socket,
  password passed as a Docker secret.
- **Browser protections**: a Content Security Policy that allows only the dashboard's own scripts, protection
  against cross-site request forgery on every change, and no third-party scripts (the map library is bundled).
- **Encryption**: new installs use HTTPS with a self-signed certificate (browsers warn once; `--tls-cert`/`--tls-key`
  for your own). Installs from before 1.16 keep plain HTTP until re-run with `--tls`.
  The installer publishes the port in Swarm's host mode on the manager node, so the dashboard sees each user's real
  address (the login lockout and connection limits are per user, not shared). Where Tailscale runs on the server it
  also adds one firewall rule (and a small boot service) that exempts the dashboard's port from Tailscale's address
  rewriting, so Tailscale users are seen individually too; nothing else about Tailscale changes. The port still listens on every
  interface, so restrict it with the host firewall, for example:
  `iptables -I DOCKER-USER -p tcp --dport 8765 ! -s 100.64.0.0/10 -j DROP`.
- **What leaves the server**: public IP addresses for WHOIS (rdap.org), reputation (AbuseIPDB, VirusTotal, only if
  keys are set) and the optional location fallback (proxycheck.io); periodic downloads of IP location and VPN/Tor
  lists; map tiles fetched by the browser from OpenFreeMap. Private addresses are never sent.
- **Stored data**: counts and aggregates only, never raw log events.

The security assessment is in [`../security/SECURITY-ASSESSMENT.md`](../security/SECURITY-ASSESSMENT.md).

## 17. Troubleshooting

| Symptom | What to check |
|---|---|
| "No traffic on the map" | Usually ingestion, not the dashboard: is the firewall still sending logs to UTMStack? Check **Data sources**. |
| Installer: OpenSearch rejects the credentials (HTTP 401) | UTMStack itself is broken (its backend uses the same credentials). Fix UTMStack first, then re-run the installer. |
| Installer warns it is using "the backend's administrator account" | The read-only OpenSearch user could not be set up; the warning says why. The dashboard still works. Fix the cause and re-run the installer. |
| SIEM health panel shows an error, installer warned "cannot list all indices" | This OpenSearch does not let the read-only user list every index. Re-run with `--os-account backend`. |
| Trends shows *n/a* or *partial* | Not enough history yet: about a day for daily, two weeks for weekly comparisons. |
| Ingest lag ~1 s but feeds are late | The headline is the newest event; click the card for the per-source delay. |
| AI Traffic empty or low | It only sees traffic that crosses the firewall, not traffic inside the LAN. |
| Street map does not appear | The browser cannot reach `tiles.openfreemap.org`; the outline map is used instead. |
| Locked out | Wait 15 minutes, or restart the service (`sudo docker service update --force utmstack-observatory`), which clears the lockout. If *everyone* is locked out at once, all users share one address: re-run `sudo ./install.sh` (1.21 or later also covers Tailscale). |
| Everyone over Tailscale appears as one address (`172.18.0.1` in `login:` log lines) | The real-address rule is missing: re-run `sudo ./install.sh`, and check `systemctl status utmstack-observatory-real-ip`. |
| Log line `hint: the first 100 connections all came from 10.0.0.2 …` | The port still goes through Swarm's ingress mesh (or a proxy), so all users share one address. Re-run `sudo ./install.sh` (1.18 or later). |
| Installer: "Login check skipped: the Settings panel overrides the installer's login" | Normal. Sign in with the login set in the Settings panel, or reset it with `sudo ./install.sh password`. |
| Anything else | `sudo ./install.sh logs` and `sudo ./install.sh status`; **Copy diagnostics** in the health panel. |

## 18. Third-party data and licences

| Component | Use | Licence |
|---|---|---|
| MapLibre GL JS 6.12.0 | Street map rendering (bundled) | BSD-3-Clause |
| OpenFreeMap / OpenStreetMap | Map tiles | ODbL (© OpenStreetMap contributors) |
| DB-IP City Lite | IP location | CC BY 4.0, "IP Geolocation by DB-IP" |
| X4BNet lists_vpn | VPN and datacenter ranges | See the project's repository |
| Tor Project exit list | Tor exit nodes | Public data |
| Natural Earth (via world-atlas) | Outline map | Public domain |
| fpdf2 | PDF reports | LGPL-3.0 |

Attribution for the map is shown in the top-right corner of the street map, and for the IP data under the map.

## 19. Copyright

UTMStack Observatory and this manual are © 2026 Victor Beitner. All rights reserved. The software is proprietary;
see the `LICENSE` file. UTMStack is a separate product by its own authors; Observatory is an independent add-on.
