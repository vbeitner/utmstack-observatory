#!/usr/bin/env bash
# UTMStack Observatory installer.
# Deploys the dashboard as a Docker Swarm service inside UTMStack's own network, so it talks to
# OpenSearch directly (no sudo/docker.sock in the container) and survives reboots.
#
#   sudo ./install.sh [install] [options]     install or upgrade (idempotent)
#   sudo ./install.sh password [NEW]          set / regenerate the dashboard login password
#   sudo ./install.sh status | logs
#   sudo ./install.sh uninstall [--purge]     --purge also deletes saved history, config and image
#
# Options: --port N (8765)  --user NAME (admin)  --password PW  --ai-hosts "name=ip,name=ip"
#          --password-file F (read the password from a file instead of the command line)
#          --tls | --tls-cert F --tls-key F | --no-tls   (new installs default to --tls)
#          --tz ZONE   --stack NAME   --import-history FILE
#          --sites "FirewallName=lat,lon,City;1.2.3.4=lat,lon"   --home "lat,lon,City"   (live map)
#          --support "Name|email|phone|url"   (shown when the logo is clicked)
#          --abuseipdb-key KEY   --virustotal-key KEY   (live IP reputation on alert detail)
#          --proxycheck-key KEY  --geoip-online-daily N   (online fallback for attacker IP location / VPN; default 100/day, 0 = off)
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="$(cat "$SRC/VERSION")"
SERVICE=utmstack-observatory; VOLUME=utmstack-observatory-data; IMAGE=utmstack-observatory
LABEL=com.utmstack-observatory
CONF_DIR=/etc/utmstack-observatory; CONF="$CONF_DIR/config.env"; PASS_FILE="$CONF_DIR/admin.pass"

info() { printf '\033[36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || exec sudo -E "$0" "$@"

CMD=install
case "${1:-}" in install|uninstall|status|logs|password) CMD="$1"; shift;; esac

# defaults, overridden by the saved config from a previous install, then by flags
PORT=8765; DASH_USER=admin; AI_HOSTS=""; TLS=0; TZ_NAME=""; STACK=""; SITES=""; HOME_LOC=""; SUPPORT=""
DASH_USER_FLAG=0; ABUSEIPDB_FLAG=0; VIRUSTOTAL_FLAG=0
TLS_CERT_SRC=""; TLS_KEY_SRC=""; NEW_PASS=""; IMPORT=""; PURGE=0; ABUSEIPDB_KEY=""; VIRUSTOTAL_KEY=""; PROXYCHECK_KEY=""; GEOIP_ONLINE_DAILY=100
[ -f "$CONF" ] || TLS=1                          # new installs: HTTPS with a self-signed certificate unless --no-tls
# shellcheck disable=SC1090
[ -f "$CONF" ] && . "$CONF"
[ "$CMD" = password ] && { NEW_PASS="${1:-}"; [ $# -gt 0 ] && shift; }
while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="$2"; shift 2;;            --user) DASH_USER="$2"; DASH_USER_FLAG=1; shift 2;;
    --password) NEW_PASS="$2"; shift 2;;    --ai-hosts) AI_HOSTS="$2"; shift 2;;
    --tls) TLS=1; shift;;                   --tls-cert) TLS=1; TLS_CERT_SRC="$2"; shift 2;;
    --no-tls) TLS=0; TLS_CERT_SRC=""; TLS_KEY_SRC=""; shift;;
    --password-file) [ -r "$2" ] || die "--password-file: cannot read $2"; NEW_PASS="$(head -n1 "$2")"; shift 2;;
    --tls-key) TLS=1; TLS_KEY_SRC="$2"; shift 2;;  --tz) TZ_NAME="$2"; shift 2;;
    --stack) STACK="$2"; shift 2;;          --import-history) IMPORT="$2"; shift 2;;
    --sites) SITES="$2"; shift 2;;          --home) HOME_LOC="$2"; shift 2;;
    --support) SUPPORT="$2"; shift 2;;
    --abuseipdb-key) ABUSEIPDB_KEY="$2"; ABUSEIPDB_FLAG=1; shift 2;;  --virustotal-key) VIRUSTOTAL_KEY="$2"; VIRUSTOTAL_FLAG=1; shift 2;;
    --proxycheck-key) PROXYCHECK_KEY="$2"; shift 2;;  --geoip-online-daily) GEOIP_ONLINE_DAILY="$2"; shift 2;;
    --purge) PURGE=1; shift;;               -h|--help) sed -n '2,16p' "$0"; exit 0;;
    *) die "unknown option: $1";;
  esac
done

command -v docker >/dev/null || die "docker is not installed"

# ---------------------------------------------------------------- simple commands
case "$CMD" in
  status)
    docker service ls --filter "name=$SERVICE" || true; docker service ps "$SERVICE" --no-trunc 2>/dev/null | head -5 || true
    sch=http; [ "$TLS" = 1 ] && sch=https
    printf 'health: '; curl -sk -m 5 -o /dev/null -w '%{http_code}\n' "$sch://127.0.0.1:$PORT/healthz" || echo unreachable
    exit 0;;
  logs) exec docker service logs --tail 100 "$SERVICE";;
  uninstall)
    info "Removing service"; docker service rm "$SERVICE" 2>/dev/null || true
    sleep 3
    for s in $(docker secret ls --filter "label=$LABEL=1" --format '{{.Name}}'); do docker secret rm "$s" >/dev/null 2>&1 || true; done
    if [ "$PURGE" = 1 ]; then
      docker volume rm "$VOLUME" >/dev/null 2>&1 && info "Deleted stored history volume" || true
      docker image rm "$IMAGE:$VERSION" "$IMAGE:latest" >/dev/null 2>&1 || true
      rm -rf "$CONF_DIR"; info "Deleted $CONF_DIR"
    else
      info "Kept history volume '$VOLUME' and $CONF_DIR (use --purge to delete)"
    fi
    info "Uninstalled"; exit 0;;
esac

# ---------------------------------------------------------------- preflight
[ "$(docker info --format '{{.Swarm.LocalNodeState}}' 2>/dev/null)" = active ] \
  || die "Docker Swarm is not active here. UTMStack v11 runs as a Swarm stack; run this on its manager node."
[ "$(docker info --format '{{.Swarm.ControlAvailable}}')" = true ] || die "this node is not a Swarm manager"

if [ -z "$STACK" ]; then
  mapfile -t found < <(docker service ls --format '{{.Name}}' | sed -n 's/_node1$//p')
  [ "${#found[@]}" -eq 1 ] || die "could not pick the UTMStack stack automatically (found: ${found[*]:-none}); pass --stack NAME"
  STACK="${found[0]}"
fi
OSSVC="${STACK}_node1"; BESVC="${STACK}_backend"
docker service inspect "$OSSVC" >/dev/null 2>&1 || die "service $OSSVC not found"
docker service inspect "$BESVC" >/dev/null 2>&1 || die "service $BESVC not found"
info "UTMStack stack: $STACK"

NETID="$(docker service inspect "$OSSVC" --format '{{range .Spec.TaskTemplate.Networks}}{{.Target}} {{end}}' | awk '{print $1}')"
NET="$(docker network inspect "$NETID" --format '{{.Name}}')"
[ -n "$NET" ] || die "could not determine the network of $OSSVC"

benv() { docker service inspect "$BESVC" --format '{{range .Spec.TaskTemplate.ContainerSpec.Env}}{{println .}}{{end}}' | sed -n "s/^$1=//p" | head -1; }
ES_HOST="$(benv ELASTICSEARCH_HOST)"; ES_HOST="${ES_HOST:-node1}"
ES_PORT="$(benv ELASTICSEARCH_PORT)"; ES_PORT="${ES_PORT:-9200}"
ES_USER="$(benv ELASTICSEARCH_USER)"; ES_PASS="$(benv ELASTICSEARCH_PASSWORD)"

# Which protocol does OpenSearch speak, and do the backend's credentials work? (checked from inside node1)
OSCID="$(docker ps -q --filter "name=${OSSVC}\." | head -1)"
SCHEME=https; [ -z "$ES_USER" ] && SCHEME=http
if [ -n "$OSCID" ]; then
  probe() { printf '%s\n' "${ES_PASS:-x}" | docker exec -i -e U="${ES_USER:-}" "$OSCID" sh -c \
    'read -r P; if [ -n "$U" ]; then curl -sk -m 8 -o /dev/null -w "%{http_code}" -u "$U:$P" '"$1"'/_cluster/health; else curl -sk -m 8 -o /dev/null -w "%{http_code}" '"$1"'/_cluster/health; fi' 2>/dev/null || true; }
  code="$(probe "$SCHEME://localhost:$ES_PORT")"
  if [ "$code" = 000 ] || [ -z "$code" ]; then
    other=http; [ "$SCHEME" = http ] && other=https
    code2="$(probe "$other://localhost:$ES_PORT")"; [ "$code2" = 200 ] && { warn "OpenSearch speaks $other, not $SCHEME as the backend config implies"; SCHEME=$other; code=200; }
  fi
  case "$code" in
    200) info "OpenSearch reachable ($SCHEME, $([ -n "$ES_USER" ] && echo "user $ES_USER" || echo "no auth"))";;
    401) die "OpenSearch rejects the credentials the UTMStack backend itself uses (HTTP 401). UTMStack is broken independently of this dashboard; see README 'Troubleshooting'.";;
    *)   warn "OpenSearch health check returned '$code'; continuing anyway";;
  esac
else
  warn "node1 is not running on this host; skipping the OpenSearch preflight"
fi

# ---------------------------------------------------------------- settings
[ -n "$TZ_NAME" ] || TZ_NAME="$(timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || echo UTC)"
mkdir -p "$CONF_DIR"; chmod 700 "$CONF_DIR"

GENERATED=0
if [ -n "$NEW_PASS" ]; then DASH_PASS="$NEW_PASS"
elif [ -s "$PASS_FILE" ] && [ "$CMD" != password ]; then DASH_PASS="$(cat "$PASS_FILE")"
else DASH_PASS="$(head -c 24 /dev/urandom | base64 | tr -d '/+=\n' | cut -c1-20)"; GENERATED=1; fi
[ "${#DASH_PASS}" -ge 8 ] || die "the dashboard password must be at least 8 characters"
[ -z "$NEW_PASS" ] || [ "${#NEW_PASS}" -ge 12 ] || die "a new dashboard password must be at least 12 characters"
printf '%s' "$DASH_PASS" > "$PASS_FILE"; chmod 600 "$PASS_FILE"

CERT=""; KEY=""
if [ "$TLS" = 1 ]; then
  if [ -n "$TLS_CERT_SRC" ] && [ -n "$TLS_KEY_SRC" ]; then CERT="$TLS_CERT_SRC"; KEY="$TLS_KEY_SRC"
  else
    CERT="$CONF_DIR/tls/cert.pem"; KEY="$CONF_DIR/tls/key.pem"
    if [ ! -s "$CERT" ]; then
      command -v openssl >/dev/null || die "openssl is needed for --tls"
      mkdir -p "$CONF_DIR/tls"; chmod 700 "$CONF_DIR/tls"
      san="DNS:$(hostname)"; for ip in $(hostname -I 2>/dev/null); do san="$san,IP:$ip"; done
      openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj "/CN=$(hostname)" -addext "subjectAltName=$san" \
        -keyout "$KEY" -out "$CERT" >/dev/null 2>&1 || die "could not generate a TLS certificate"
      chmod 600 "$KEY"; info "Generated a self-signed certificate (browsers will warn once)"
    fi
  fi
  [ -s "$CERT" ] && [ -s "$KEY" ] || die "TLS certificate/key not found"
fi

HOSTFS=""; for d in /utmstack/locks /utmstack/updates /utmstack; do [ -d "$d" ] && { HOSTFS="$d"; break; }; done

# ---------------------------------------------------------------- build
info "Building image $IMAGE:$VERSION (needs to pull python:3.12-slim the first time)"
docker build -q -t "$IMAGE:$VERSION" -t "$IMAGE:latest" "$SRC" >/dev/null

docker volume create "$VOLUME" >/dev/null
if [ -n "$IMPORT" ]; then
  [ -f "$IMPORT" ] || die "--import-history: $IMPORT not found"
  info "Importing history from $IMPORT"
  docker run --rm -u 0 --entrypoint sh -v "$VOLUME:/data" -v "$(readlink -f "$IMPORT"):/in/history.db:ro" "$IMAGE:$VERSION" \
    -c 'cp /in/history.db /data/history.db && chown 10001:10001 /data/history.db'
fi

# A login or key saved in the dashboard's Settings panel overrides the installer's. When the installer is told to
# set one, the saved override is removed so the installer's value really takes effect (e.g. revoking a password).
CLEAR=()
{ [ -n "$NEW_PASS" ] || [ "$CMD" = password ]; } && CLEAR+=(dash_pass)
[ "$DASH_USER_FLAG" = 1 ] && CLEAR+=(dash_user)
[ "$ABUSEIPDB_FLAG" = 1 ] && CLEAR+=(abuseipdb_key)
[ "$VIRUSTOTAL_FLAG" = 1 ] && CLEAR+=(virustotal_key)
if [ "${#CLEAR[@]}" -gt 0 ]; then
  docker run --rm --entrypoint python3 -v "$VOLUME:/data" "$IMAGE:$VERSION" -I /app/settings_store.py /data --clear "${CLEAR[@]}" \
    | sed 's/^/    settings panel override /' || warn "could not clear the settings-panel override for: ${CLEAR[*]}"
fi

# ---------------------------------------------------------------- secrets + service
TS="$(date +%s)"
mksecret() { printf '%s' "$2" | docker secret create --label "$LABEL=1" "$1_$TS" - >/dev/null; }
mkfilesecret() { docker secret create --label "$LABEL=1" "$1_$TS" "$2" >/dev/null; }
SECRETS=(); mksecret observatory_dash_pass "$DASH_PASS"; SECRETS+=(--secret "source=observatory_dash_pass_$TS,target=dash_pass,uid=10001,mode=0400")
ENVS=(--env "OS_URL=$SCHEME://$ES_HOST:$ES_PORT" --env "DASH_USER=$DASH_USER" --env "DASH_PASS_FILE=/run/secrets/dash_pass"
      --env "TZ=$TZ_NAME" --env "HOST_NAME=$(hostname)" --env "AI_HOSTS=$AI_HOSTS"
      --env "SITE_LOCATIONS=$SITES" --env "HOME_LOCATION=$HOME_LOC"
      --env "SUPPORT_CONTACT=$SUPPORT" --env "INSTALLED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)")
if [ -n "$ES_USER" ]; then
  mksecret observatory_os_pass "$ES_PASS"; SECRETS+=(--secret "source=observatory_os_pass_$TS,target=os_pass,uid=10001,mode=0400")
  ENVS+=(--env "OS_USER=$ES_USER" --env "OS_PASS_FILE=/run/secrets/os_pass")
fi
if [ "$TLS" = 1 ]; then
  mkfilesecret observatory_tls_cert "$CERT"; mkfilesecret observatory_tls_key "$KEY"
  SECRETS+=(--secret "source=observatory_tls_cert_$TS,target=tls_cert,uid=10001,mode=0400" --secret "source=observatory_tls_key_$TS,target=tls_key,uid=10001,mode=0400")
  ENVS+=(--env TLS_CERT=/run/secrets/tls_cert --env TLS_KEY=/run/secrets/tls_key)
fi
ENVS+=(--env "GEOIP_ONLINE_DAILY=$GEOIP_ONLINE_DAILY")
if [ -n "$PROXYCHECK_KEY" ]; then
  mksecret observatory_proxycheck_key "$PROXYCHECK_KEY"; SECRETS+=(--secret "source=observatory_proxycheck_key_$TS,target=proxycheck_key,uid=10001,mode=0400")
  ENVS+=(--env "PROXYCHECK_KEY_FILE=/run/secrets/proxycheck_key")
fi
if [ -n "$ABUSEIPDB_KEY" ]; then
  mksecret observatory_abuseipdb_key "$ABUSEIPDB_KEY"; SECRETS+=(--secret "source=observatory_abuseipdb_key_$TS,target=abuseipdb_key,uid=10001,mode=0400")
  ENVS+=(--env "ABUSEIPDB_KEY_FILE=/run/secrets/abuseipdb_key")
fi
if [ -n "$VIRUSTOTAL_KEY" ]; then
  mksecret observatory_virustotal_key "$VIRUSTOTAL_KEY"; SECRETS+=(--secret "source=observatory_virustotal_key_$TS,target=virustotal_key,uid=10001,mode=0400")
  ENVS+=(--env "VIRUSTOTAL_KEY_FILE=/run/secrets/virustotal_key")
fi
MOUNTS=(--mount "type=volume,source=$VOLUME,target=/data" --mount "type=tmpfs,destination=/tmp")
[ -n "$HOSTFS" ] && { MOUNTS+=(--mount "type=bind,source=$HOSTFS,target=/hostfs,readonly"); ENVS+=(--env DISK_PATH=/hostfs); }

if docker service inspect "$SERVICE" >/dev/null 2>&1; then
  info "Replacing existing service"; docker service rm "$SERVICE" >/dev/null
  for _ in $(seq 1 30); do docker service inspect "$SERVICE" >/dev/null 2>&1 || break; sleep 1; done
fi
info "Starting service on network $NET, port $PORT"
docker service create --detach --name "$SERVICE" --label "$LABEL=1" --network "$NET" \
  --constraint node.role==manager --replicas 1 --no-resolve-image \
  --publish "published=$PORT,target=8765,protocol=tcp" \
  --read-only --cap-drop ALL --limit-memory 512m --limit-cpu 1 --restart-condition any \
  "${MOUNTS[@]}" "${SECRETS[@]}" "${ENVS[@]}" "$IMAGE:$VERSION" >/dev/null

# drop secrets from earlier installs now that nothing uses them
for s in $(docker secret ls --filter "label=$LABEL=1" --format '{{.Name}}'); do
  case "$s" in *_"$TS") ;; *) docker secret rm "$s" >/dev/null 2>&1 || true;; esac
done

# ---------------------------------------------------------------- verify
sch=http; [ "$TLS" = 1 ] && sch=https
info "Waiting for the dashboard to answer"
ok=0
for _ in $(seq 1 45); do
  [ "$(curl -sk -m 4 -o /dev/null -w '%{http_code}' "$sch://127.0.0.1:$PORT/healthz" || true)" = 200 ] && { ok=1; break; }
  sleep 2
done
if [ "$ok" != 1 ]; then docker service logs --tail 30 "$SERVICE" 2>&1 || true; die "the dashboard did not come up; see the log above"; fi
sleep 6
# credentials go to curl on stdin (-K -), not on its command line where other users could see them in ps
auth="$(printf 'user = "%s"\n' "$(printf '%s' "$DASH_USER:$DASH_PASS" | sed 's/[\\"]/\\&/g')" \
  | curl -sk -m 15 -K - -o /dev/null -w '%{http_code}' "$sch://127.0.0.1:$PORT/api/data" || true)"
[ "$auth" = 200 ] || warn "login check returned HTTP $auth"

{ printf 'PORT=%q\nDASH_USER=%q\nAI_HOSTS=%q\nTLS=%q\nTZ_NAME=%q\nSTACK=%q\nSITES=%q\nHOME_LOC=%q\nSUPPORT=%q\nABUSEIPDB_KEY=%q\nVIRUSTOTAL_KEY=%q\nPROXYCHECK_KEY=%q\nGEOIP_ONLINE_DAILY=%q\n' \
    "$PORT" "$DASH_USER" "$AI_HOSTS" "$TLS" "$TZ_NAME" "$STACK" "$SITES" "$HOME_LOC" "$SUPPORT" "$ABUSEIPDB_KEY" "$VIRUSTOTAL_KEY" "$PROXYCHECK_KEY" "$GEOIP_ONLINE_DAILY"
  [ -n "$TLS_CERT_SRC" ] && printf 'TLS_CERT_SRC=%q\nTLS_KEY_SRC=%q\n' "$TLS_CERT_SRC" "$TLS_KEY_SRC"; } > "$CONF"; chmod 600 "$CONF"

echo
info "UTMStack Observatory $VERSION is running"
for ip in $(hostname -I 2>/dev/null); do case "$ip" in 172.1[6-9].*|172.2*.*|172.3[01].*) ;; *) echo "    $sch://$ip:$PORT/";; esac; done
echo "    user: $DASH_USER"
if [ "$GENERATED" = 1 ]; then echo "    password: $DASH_PASS   (shown once; also in $PASS_FILE)"
elif [ -n "$NEW_PASS" ]; then echo "    password: (the one you set)"; else echo "    password: (unchanged; stored in $PASS_FILE)"; fi
echo "    password file: $PASS_FILE    config: $CONF"
[ "$TLS" = 1 ] || warn "plain HTTP: the login travels unencrypted. Use a trusted network/VPN, or re-run with --tls."
echo "    The published port listens on all interfaces; restrict it with your firewall if needed."
