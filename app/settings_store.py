"""Live-editable settings that would otherwise only be set via install.sh flags (no HTTP here).

Stored as a flat JSON object of known keys -> string values, in the same raw format install.sh's
own flags take (e.g. "sites" is "Name=lat,lon,City;IP=lat,lon", "support" is "Name|email|phone|url")
so server.py can parse a stored value with the exact same function it already uses for the env var.
A key absent from the file means "use the env/install-time default"; an empty string means
"explicitly cleared". Secrets (dash_pass, the API keys) are written here but never read back out
to a client -- callers that need to show state use settings_store.configured(), not load().
"""
import json
import os
import tempfile
import time

FILE = "settings.json"
MAX_VALUE_CHARS = 2000
MAX_BYTES = 16 * 1024
CACHE_TTL_S = 2            # load() is on the hot path (every authorized() call); avoid a disk read per request
KEYS = {"dash_user", "dash_pass", "abuseipdb_key", "virustotal_key", "support", "home", "sites", "ai_hosts", "report_hour"}
SECRET_KEYS = {"dash_pass", "abuseipdb_key", "virustotal_key"}

_cache = {"t": 0.0, "dir": None, "data": {}}


def load(data_dir):
    now = time.time()
    if _cache["dir"] == data_dir and now - _cache["t"] < CACHE_TTL_S:
        return _cache["data"]
    try:
        with open(os.path.join(data_dir, FILE)) as f:
            d = json.load(f)
        d = d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        d = {}
    _cache.update(t=now, dir=data_dir, data=d)
    return d


def get(data_dir, key, default=None):
    v = load(data_dir).get(key)
    return v if v else default   # "" (explicitly cleared) falls through to default, same as "unset"


def configured(data_dir, key):
    """True if this (secret) key has a non-empty value, without ever exposing the value itself."""
    return bool(load(data_dir).get(key))


def save(data_dir, patch):
    if not isinstance(patch, dict):
        raise ValueError("request body must be a JSON object")
    unknown = set(patch) - KEYS
    if unknown:
        raise ValueError("unknown setting(s): %s" % ", ".join(sorted(unknown)))
    for k, v in patch.items():
        if not isinstance(v, str):
            raise ValueError("%s must be a string" % k)
        if len(v) > MAX_VALUE_CHARS:
            raise ValueError("%s is longer than %d characters" % (k, MAX_VALUE_CHARS))
    current = load(data_dir)
    current.update(patch)
    body = json.dumps(current, separators=(",", ":"))
    if len(body) > MAX_BYTES:
        raise ValueError("settings are larger than %d KB" % (MAX_BYTES // 1024))
    fd, tmp = tempfile.mkstemp(dir=data_dir, prefix=".settings-")
    with os.fdopen(fd, "w") as f:
        f.write(body)
    os.replace(tmp, os.path.join(data_dir, FILE))        # atomic: a crash never leaves half a file
    _cache.update(t=time.time(), dir=data_dir, data=current)   # next request sees it now, not after CACHE_TTL_S
    return current


def public_state(data_dir):
    """Everything safe to send back to the browser: real values for non-secrets, booleans for secrets."""
    d = load(data_dir)
    out = {k: d.get(k, "") for k in KEYS - SECRET_KEYS}
    for k in SECRET_KEYS:
        out[k + "_configured"] = bool(d.get(k))
    return out
