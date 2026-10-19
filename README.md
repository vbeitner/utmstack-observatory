# UTMStack Observatory

A read-only operations dashboard for a UTMStack v11 SIEM. It reads UTMStack's own OpenSearch and shows:

- live event and alert trends, data-source health, event mix, top alert rules
- click-through drill-downs: sources and who produces the most events, a filterable alert list, alert detail with **WHOIS** for every IP, and an **ingest-lag analysis** that tells you which feeds are late and why
- **30 days of history** with daily and weekly comparisons, kept in a small local database because OpenSearch only retains about a day of logs
- **storage tracking**: size of the alert and log indices per day, bytes per alert, and days of disk left
- optional **AI Traffic** tab: bytes in/out of chosen servers, from Sophos XG firewall logs
- **Live Firewall Map**: animated arcs from every Sophos XG firewall to the cities it is talking to (outbound, inbound
  allowed, denied), top countries, and a ticker of the latest blocked inbound connections; 1 / 5 / 15 minute windows
- **time-range picker** (1 h / 6 h / 24 h) for the counters, event-source donut, top alert rules and latest-alert list
- **Movable widgets and named screens** (Edit button right of the screen tabs) with a shared default layout and
  personal per-browser layouts
- **Wall mode** for a NOC screen: full screen, client firewall names replaced by *Site A, Site B…*, rotating every 30 s
- **Attacker panel**: click a blocked connection to see every port that address tried in the last 24 hours (denied vs
  allowed, with service names), the sites and addresses it reached, reputation and WHOIS
- **SIEM health with Apply fix**: click the OpenSearch badge for a plain-language explanation of a yellow/red status
  and, where it is safe, a one-click fix (password-protected, narrow write account)
- **Branded PDF/HTML reports** on demand or daily: logo header and copyright footer on every page, key figures, key
  findings, denied and successful connections (ports, attackers, who connected to whom)

**Documentation:** [User manual](docs/manual/USER-MANUAL.md) (with screenshots and clips) ·
[Feature tour](docs/tour/index.html) · [Security assessment](docs/security/SECURITY-ASSESSMENT.md) ·
[Release notes](RELEASE-NOTES.md). A demo with synthetic data runs with `DEMO=1` (see the manual).

Python standard library only, with two exceptions (`fpdf2` for the PDF reports, `maxminddb` for IP locations). Runs as one container (a Docker Swarm service) next to UTMStack.

## Requirements

- A UTMStack v11 server (Docker Swarm stack, normally `utmstack`). Run the installer on the Swarm manager node.
- Docker, `curl`, root (or sudo). Internet access to pull `python:3.12-slim` the first time (and for WHOIS lookups, see below).

## Install

```bash
tar xzf utmstack-observatory-1.0.0.tar.gz
cd utmstack-observatory
sudo ./install.sh
```

The installer finds the stack, reads the OpenSearch credentials UTMStack already uses, checks they work, uses them
once to create a dedicated read-only OpenSearch user for the dashboard (see Security), builds the image, starts the service, and prints the URL and a generated login. Re-running it upgrades in place and
keeps your password, settings and history.

Common options:

| Option | Meaning |
|---|---|
| `--port 8765` | port to publish (default 8765) |
| `--tls` / `--no-tls` | HTTPS with a generated self-signed certificate (default for new installs), or `--tls-cert F --tls-key F` for your own |
| `--ai-hosts "gx10=10.0.2.34,web=10.0.2.17"` | enable the AI Traffic tab for these hosts (needs Sophos XG logs) |
| `--user NAME` / `--password PW` / `--password-file F` | dashboard login (default user `admin`, random password; new passwords 12+ characters) |
| `--tz America/New_York` | time zone for day boundaries (default: the host's) |
| `--stack NAME` | UTMStack stack name if it is not auto-detected |
| `--import-history FILE` | seed `history.db` from an earlier install |
| `--sites "Name=lat,lon,City;1.2.3.4=lat,lon"` | pin firewalls the map cannot place on its own (by device name or WAN IP) |
| `--home "lat,lon,City"` | where unplaceable firewalls are drawn (default Toronto) |
| `--support "Name\|email\|phone\|url"` | contact shown when the logo is clicked (default Cyber Security Canada, info@cybersecuritycanada.com) |
| `--abuseipdb-key KEY` / `--virustotal-key KEY` | enable live IP-reputation lookups on alert detail (see Security) |
| `--os-account reader\|backend` | OpenSearch account for the dashboard: the dedicated read-only user (default) or UTMStack's administrator |
| `--no-health-fix` | no *Apply fix* button in the SIEM-health panel; it shows the commands only |
| `--no-real-ip-rule` | do not install the firewall rule that keeps Tailscale users' real addresses (see Security) |

Other commands: `sudo ./install.sh status | logs | password [NEW] | uninstall [--purge]`.
`uninstall` keeps your stored history; `--purge` deletes it, the config and the image.

## Live Firewall Map

Reads the Sophos XG logs UTMStack already stores (`v11-log-firewall-sophos-xg-*`), plus attacker addresses from
syslog, Linux, Windows and Microsoft 365 logs. Locations come from UTMStack's own GeoIP enrichment where present, then
from a local DB-IP City Lite database with VPN, datacenter and Tor exit lists (downloaded into `/data/geoip`), and
optionally from proxycheck.io for the rest (`--geoip-online-daily`, default 100 lookups a day, `0` = off).

- **Firewall locations**: each firewall is identified by its WAN address (`dataSource`) and name (`log.deviceName`).
  Its pin comes from `--sites` if you set one, otherwise from UTMStack's GeoIP record for that WAN address, otherwise
  the `--home` location. The side panel names any firewall drawn at the home pin.
- **Direction**: *inbound* = the remote address started the connection; *outbound* = a local host reached out.
  Private addresses have no coordinates and are left off the map.
- **Load**: one aggregation query per window every 10 s, shared by every open browser (`/api/geo`).
- **Freshness**: the panel shows the age of the newest firewall event, so "live" is never overstated.
- **Wall mode** (button in the header, or open `/?wall=1`): firewall names and WAN addresses are replaced by
  *Site A, Site B…* **on the server**, so the screen never receives them. Views rotate between the map and the
  counters/trend chart; panels that show data-source names (alert list, silent sources) are not shown. Press Esc to exit.

## Security

- **Login required.** HTTP Basic auth. The password is in `/etc/utmstack-observatory/admin.pass` (root only) and is passed to the
  container as a Docker secret. Change it with `sudo ./install.sh password`.
- **HTTPS by default on new installs** (self-signed). Installs from before 1.16 keep plain HTTP until re-run with `--tls`;
  on plain HTTP the login crosses the network unencrypted, so only use it over a VPN / trusted network.
- Changing the login, an API key or the support contact in the Settings panel needs the current password; every
  settings and shared-layout change is logged (`audit:` lines in `install.sh logs`). A password set there is stored as a
  PBKDF2 hash, and `install.sh password` removes it again.
- **Real client addresses (1.18+).** The installer publishes the port in Swarm's *host* mode on the manager node, not
  through the ingress routing mesh. Through the mesh every user arrives from one overlay address (e.g. `10.0.0.2`), so
  five wrong passwords from anyone locked everyone out and `MAX_CONNECTIONS_PER_IP` was shared by all. Re-run the
  installer to switch an older install. If the log shows a `hint: the first 100 connections all came from …` line,
  the port is still going through the mesh (or a proxy). Checks run on the server itself (`curl 127.0.0.1`) arrive from
  Docker's bridge gateway (e.g. `172.18.0.1`), not `127.0.0.1`.
- **Tailscale users keep their own address (1.21+).** Tailscale masquerades everything it forwards from `tailscale0`,
  including traffic to the dashboard's container, so all Tailscale users used to arrive as `172.18.0.1` and share one
  lockout. Where `tailscale0` exists, the installer installs `/usr/local/sbin/utmstack-observatory-real-ip` and the
  systemd unit `utmstack-observatory-real-ip`, which put one `nat POSTROUTING` rule first: Tailscale-marked packets
  to container port 8765 on `docker_gwbridge` are not masqueraded. The unit re-runs after `tailscaled` restarts and at
  boot; `uninstall` and `--no-real-ip-rule` remove it. Nothing else about Tailscale changes.
- **Password guessing from many addresses** (more than `LOGIN_SURGE_PER_MIN`, default 30 failures a minute in total)
  slows every failed attempt to 3 s instead of locking anyone out.
- **Swarm publishes the port on every interface.** Restrict it with your firewall. Example allowing only Tailscale and localhost:
  `iptables -I DOCKER-USER -p tcp --dport 8765 ! -s 100.64.0.0/10 -j DROP` (adapt, and persist it your usual way).
- The container is read-only, drops all capabilities, runs as an unprivileged user, and has no Docker socket. It only *reads* OpenSearch.
- **Read-only OpenSearch account.** The installer uses UTMStack's backend credentials (the OpenSearch administrator) only
  to create, through the OpenSearch security REST API, a role `observatory_read` and a user `observatory_reader`. The
  role allows `read` and `view_index_metadata` on `v11-*`, `indices:monitor/*` on all indices (index and shard lists on
  the SIEM health panel) and `cluster:monitor/*` (cluster health, allocation explain). It cannot write, delete or change
  settings. The user's password is random, kept in `/etc/utmstack-observatory/os_reader.pass` (root only) so re-runs
  keep the same user, and passed to the container as a Docker secret (`uid=10001`, mode `0400`). The installer tests
  the new account before using it. If OpenSearch runs without the security plugin, if node1 is on another host, or if
  any API call or test fails, it warns and falls back to the backend credentials. The last lines of the install
  output show which account is in use. `--os-account backend` switches back to the administrator account on purpose.
  To remove the user after uninstalling, delete `observatory_reader` and `observatory_read` in OpenSearch's security
  settings (or `DELETE _plugins/_security/api/internalusers/observatory_reader` and `.../roles/observatory_read`).
- **Apply fix account (1.20+).** For the SIEM-health *Apply fix* button the installer also creates `observatory_fixer`
  with role `observatory_health_fix`: `indices:admin/settings/update` on all indices, `cluster:admin/settings/update`,
  `indices:admin/template/put` and `cluster:monitor/health` only. It cannot read, write or delete data. The server
  re-derives the fix from the live cluster and only sends replica-0 settings, two plugin settings and one template, after
  the dashboard password; `--no-health-fix` leaves the account out.
- It connects to OpenSearch without verifying its certificate (UTMStack uses an internal self-signed one on a private network);
  set `OS_CA_FILE` to verify it.
- Full assessment, findings and fixes: [docs/security/SECURITY-ASSESSMENT.md](docs/security/SECURITY-ASSESSMENT.md).
- **WHOIS** (alert detail) sends the looked-up public IP to `rdap.org`, which forwards to the regional registry. Private addresses are never sent. Results are cached for 24 hours.
- The history database stores counts only, not raw events.

## Settings panel

The gear icon in the header (top right) opens a **Settings** drawer for things you'd otherwise only set via
`install.sh` flags: the dashboard login, the AbuseIPDB/VirusTotal keys, the support contact, the map's home
location and site pins, and the AI-traffic hosts. Changes save to `/data/settings.json` (the same persistent
volume as the history database) and take effect immediately, no restart — a password change signs you out and
reloads the page so you log back in with the new one. A setting saved here overrides the matching `install.sh`
flag/env var; leaving a field blank on save clears the override and falls back to whatever `install.sh` set.
Dashboard layout (widgets, screens, wall rotation) has its own editor — the drawer just links to it.

## Reports

The **Reports** button in the header opens a drawer listing generated reports (newest first) with PDF and HTML
download links, and a **Generate now** button for an on-demand report. Each report covers the last 24 hours and
carries the UTMStack Observatory logo at the top and "© Victor Beitner · Confidential · Page n of N" at the bottom of
every page. It opens with four key figures and **Key findings** (risky ports allowed in from the internet,
high-severity alerts, silent sources, OpenSearch status), then the trend, top alert rules and recent alerts (with
MITRE ATT&CK technique), traffic by country, **denied connections** (ports attackers tried, top attackers) and
**successful connections** (ports in use, allowed in from the internet, busiest who-to-whom flows), and host and
storage health.

Set a generation hour (0–23, UTC) in the Settings panel to also get one automatically every day; leave it
blank and reports are on-demand only. Files live in `/data/reports` (the same volume as the history database
and settings), the last 30 are kept, and download links require the dashboard login like everything else.

## Rebuild from GitHub

Everything needed is in this repository (`vbeitner/utmstack-observatory`, private). On the UTMStack Swarm manager:

```bash
git clone https://github.com/vbeitner/utmstack-observatory.git
cd utmstack-observatory
sudo ./install.sh                 # or: git pull && sudo ./install.sh   to upgrade
```

Nothing secret is in git. The installer reads the OpenSearch credentials from UTMStack's own service spec, uses them
to create the read-only OpenSearch user (password in `/etc/utmstack-observatory/os_reader.pass`), generates
the dashboard password into `/etc/utmstack-observatory/admin.pass` (root only) on first install, and keeps them, the
settings (`config.env`) and the history volume on every upgrade.

The world outline `app/land.json` is generated from Natural Earth 1:110m land (public domain) via world-atlas 2.0.2:
`python3 tools/build_land.py land-110m.json app/land.json` (download command in the script header).

Tests (OpenSearch stubbed): `pip install -r requirements.txt` once, then `python3 -m unittest discover -s tests -v` and `node --test tests/`

## What is stored where

| What | Where |
|---|---|
| 30-day hourly history + daily storage sizes | Docker volume `utmstack-observatory-data` (`/data/history.db`) |
| Install settings | `/etc/utmstack-observatory/config.env` |
| Dashboard password | `/etc/utmstack-observatory/admin.pass` |
| Shared dashboard layout | Docker volume `utmstack-observatory-data` (`/data/layout.json`) |
| Live-edited settings (login, API keys, support, map, AI hosts) | Docker volume `utmstack-observatory-data` (`/data/settings.json`) |
| Generated PDF/HTML reports (last 30 kept) | Docker volume `utmstack-observatory-data` (`/data/reports/`) |

History starts when the dashboard is first installed. On a first run it also backfills event counts from UTMStack's ingest
statistics (`v11-statistics-*`) for as far back as that index goes. Alerts and AI traffic cannot be backfilled.

## Configuration (environment variables)

The installer sets these; you only need them to run `app/server.py` by hand.

| Variable | Default | |
|---|---|---|
| `OS_URL` | *(none)* | OpenSearch URL, e.g. `https://node1:9200`. Empty = bare-metal mode using `sudo docker exec` |
| `OS_USER`, `OS_PASS` / `OS_PASS_FILE` | | OpenSearch credentials (omit if security is off); the installer sets the read-only `observatory_reader` |
| `DASH_USER`, `DASH_PASS` / `DASH_PASS_FILE` | `admin` | dashboard login. Without a password it only listens on 127.0.0.1 |
| `PORT`, `BIND` | `8765`, `0.0.0.0` | |
| `TLS_CERT`, `TLS_KEY` | | enable HTTPS |
| `AI_HOSTS` | *(off)* | `name=ip,name=ip` |
| `DATA_DIR` | app dir | where `history.db` lives |
| `DISK_PATH` | `/utmstack` | path on the filesystem to report free space for |
| `HOST_NAME`, `TZ` | | shown in the Resource panel / used for day boundaries |
| `ABUSEIPDB_KEY` / `_FILE` | *(off)* | enables live AbuseIPDB abuse-score lookups on an alert's IPs |
| `VIRUSTOTAL_KEY` / `_FILE` | *(off)* | enables live VirusTotal vendor-detection lookups on an alert's IPs |
| `REQUEST_TIMEOUT_S` | `15` | idle/slow clients are dropped after this many seconds |
| `LOGIN_MAX_FAILURES`, `LOGIN_LOCK_S` | `5`, `900` | failed logins from one address before it's locked out, and for how long |
| `LOGIN_SURGE_PER_MIN` | `30` | failed logins a minute (all addresses) above which every failed attempt is slowed down; `0` = off |
| `OS_FIX_USER`, `OS_FIX_PASS` / `_FILE` | | OpenSearch account for the *Apply fix* button (installer: `observatory_fixer`) |
| `MAX_CONNECTIONS`, `MAX_CONNECTIONS_PER_IP` | `64`, `32` | concurrent connections accepted in total / per address; over the cap, new ones are refused immediately |
| `SHARED_ADDRESS_HINT_AFTER` | `100` | log a one-time hint if this many first connections all came from one address on the container's own network (Swarm ingress); `0` = off |
| `HEADER_DEADLINE_S` | `10` | a client must send its whole request header within this time (slow-connection protection) |
| `ALLOWED_HOSTS` | | extra `Host` names accepted when no password is set (otherwise only localhost) |
| `OS_CA_FILE`, `OS_CHECK_HOSTNAME` | , `1` | verify OpenSearch's TLS certificate against this CA |
| `DEMO` | | `1` = synthetic demo data, no OpenSearch needed |

## Troubleshooting

**Installer says OpenSearch rejects the credentials (HTTP 401).** UTMStack itself is broken, not the dashboard: the backend
uses the same credentials and will be crash-looping (`docker service ls` shows `backend 0/1`, the web UI returns 502).
It happens when OpenSearch's stored `admin` password no longer matches the one in the backend's environment. Fix that first
(reset the `admin` hash in OpenSearch's security index to the backend's password with `securityadmin.sh`), then re-run the installer.

**Trends shows "n/a" or "partial".** Comparisons only appear when both time windows have at least 90% of their hours of data.
Daily comparisons fill in after about a day, weekly after about two weeks.

**Ingest lag shows ~1 s but feeds are late.** The headline is the age of the newest event. Click the card for the per-source
delay (device timestamp to stored time). Firewalls often batch logs; Microsoft 365 is polled, so minutes of delay are normal.

**AI Traffic is empty or understated.** It uses Sophos XG firewall logs, so it only sees traffic that crosses the firewall,
not traffic between machines on the same LAN.

**Logs:** `sudo ./install.sh logs`. **Health:** `sudo ./install.sh status`.

## Copyright

UTMStack Observatory is © 2026 Victor Beitner. All rights reserved. Proprietary software; see [LICENSE](LICENSE) for
the terms and the third-party components (MapLibre GL JS 6.12.0, BSD-3-Clause; fpdf2, LGPL-3.0; map and IP data
under their own licences).
