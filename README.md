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

Python standard library only. Runs as one container (a Docker Swarm service) next to UTMStack.

## Requirements

- A UTMStack v11 server (Docker Swarm stack, normally `utmstack`). Run the installer on the Swarm manager node.
- Docker, `curl`, root (or sudo). Internet access to pull `python:3.12-slim` the first time (and for WHOIS lookups, see below).

## Install

```bash
tar xzf utmstack-observatory-1.0.0.tar.gz
cd utmstack-observatory
sudo ./install.sh
```

The installer finds the stack, reads the OpenSearch credentials UTMStack already uses, checks they work,
builds the image, starts the service, and prints the URL and a generated login. Re-running it upgrades in place and
keeps your password, settings and history.

Common options:

| Option | Meaning |
|---|---|
| `--port 8765` | port to publish (default 8765) |
| `--tls` | HTTPS with a generated self-signed certificate (or `--tls-cert F --tls-key F` for your own) |
| `--ai-hosts "gx10=10.0.2.34,web=10.0.2.17"` | enable the AI Traffic tab for these hosts (needs Sophos XG logs) |
| `--user NAME` / `--password PW` | dashboard login (default user `admin`, random password) |
| `--tz America/New_York` | time zone for day boundaries (default: the host's) |
| `--stack NAME` | UTMStack stack name if it is not auto-detected |
| `--import-history FILE` | seed `history.db` from an earlier install |
| `--sites "Name=lat,lon,City;1.2.3.4=lat,lon"` | pin firewalls the map cannot place on its own (by device name or WAN IP) |
| `--home "lat,lon,City"` | where unplaceable firewalls are drawn (default Toronto) |
| `--support "Name\|email\|phone\|url"` | contact shown when the logo is clicked (default Cyber Security Canada, info@cybersecuritycanada.com) |

Other commands: `sudo ./install.sh status | logs | password [NEW] | uninstall [--purge]`.
`uninstall` keeps your stored history; `--purge` deletes it, the config and the image.

## Live Firewall Map

Reads the Sophos XG logs UTMStack already stores (`v11-log-firewall-sophos-xg-*`) and uses UTMStack's own GeoIP
enrichment (`origin.geolocation` / `target.geolocation`), so **no GeoIP database and no outside lookup** is needed.

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
- **Plain HTTP by default**, so the login crosses the network unencrypted. Use `--tls`, or only reach it over a VPN / trusted network.
- **Swarm publishes the port on every interface.** Restrict it with your firewall. Example allowing only Tailscale and localhost:
  `iptables -I DOCKER-USER -p tcp --dport 8765 ! -s 100.64.0.0/10 -j DROP` (adapt, and persist it your usual way).
- The container is read-only, drops all capabilities, runs as an unprivileged user, and has no Docker socket. It only *reads* OpenSearch.
- It connects to OpenSearch without verifying its certificate (UTMStack uses an internal self-signed one on a private network).
- **WHOIS** (alert detail) sends the looked-up public IP to `rdap.org`, which forwards to the regional registry. Private addresses are never sent. Results are cached for 24 hours.
- The history database stores counts only, not raw events.

## Rebuild from GitHub

Everything needed is in this repository (`vbeitner/utmstack-observatory`, private). On the UTMStack Swarm manager:

```bash
git clone https://github.com/vbeitner/utmstack-observatory.git
cd utmstack-observatory
sudo ./install.sh                 # or: git pull && sudo ./install.sh   to upgrade
```

Nothing secret is in git. The installer reads the OpenSearch credentials from UTMStack's own service spec, generates
the dashboard password into `/etc/utmstack-observatory/admin.pass` (root only) on first install, and keeps it, the
settings (`config.env`) and the history volume on every upgrade.

The world outline `app/land.json` is generated from Natural Earth 1:110m land (public domain) via world-atlas 2.0.2:
`python3 tools/build_land.py land-110m.json app/land.json` (download command in the script header).

Tests (standard library only, OpenSearch stubbed): `python3 -m unittest discover -s tests -v` and `node --test tests/`

## What is stored where

| What | Where |
|---|---|
| 30-day hourly history + daily storage sizes | Docker volume `utmstack-observatory-data` (`/data/history.db`) |
| Install settings | `/etc/utmstack-observatory/config.env` |
| Dashboard password | `/etc/utmstack-observatory/admin.pass` |
| Shared dashboard layout | Docker volume `utmstack-observatory-data` (`/data/layout.json`) |

History starts when the dashboard is first installed. On a first run it also backfills event counts from UTMStack's ingest
statistics (`v11-statistics-*`) for as far back as that index goes. Alerts and AI traffic cannot be backfilled.

## Configuration (environment variables)

The installer sets these; you only need them to run `app/server.py` by hand.

| Variable | Default | |
|---|---|---|
| `OS_URL` | *(none)* | OpenSearch URL, e.g. `https://node1:9200`. Empty = bare-metal mode using `sudo docker exec` |
| `OS_USER`, `OS_PASS` / `OS_PASS_FILE` | | OpenSearch credentials (omit if security is off) |
| `DASH_USER`, `DASH_PASS` / `DASH_PASS_FILE` | `admin` | dashboard login. Without a password it only listens on 127.0.0.1 |
| `PORT`, `BIND` | `8765`, `0.0.0.0` | |
| `TLS_CERT`, `TLS_KEY` | | enable HTTPS |
| `AI_HOSTS` | *(off)* | `name=ip,name=ip` |
| `DATA_DIR` | app dir | where `history.db` lives |
| `DISK_PATH` | `/utmstack` | path on the filesystem to report free space for |
| `HOST_NAME`, `TZ` | | shown in the Resource panel / used for day boundaries |
| `REQUEST_TIMEOUT_S` | `15` | idle/slow clients are dropped after this many seconds |
| `LOGIN_MAX_FAILURES`, `LOGIN_LOCK_S` | `5`, `900` | failed logins from one address before it's locked out, and for how long |
| `MAX_CONNECTIONS` | *(unlimited)* | concurrent connections accepted; over the cap, new ones are refused immediately instead of queued |

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
