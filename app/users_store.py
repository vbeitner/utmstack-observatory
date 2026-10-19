# Copyright (c) 2026 Victor Beitner. All rights reserved. See LICENSE.
"""Dashboard users (invited email addresses with a role), browser sessions and one-time sign-in links (no HTTP here).

users.json in DATA_DIR holds the invited users and the open sessions. Session and link tokens are never stored,
only their SHA-256, so a copy of the file signs nobody in. Sign-in links live in memory only: a restart voids
the links still in flight (they last minutes), not the sessions.
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import tempfile
import threading
import time

FILE = "users.json"
ROLES = ("admin", "viewer")
MAX_USERS = 500
MAX_SESSIONS = 2000
EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")

_lock = threading.RLock()
_cache = {"dir": None, "data": None}
_links = {}                                       # sha256(token) -> {"email", "until"}


def _digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


def norm_email(email):
    """Lower-cased address, or ValueError for anything that is not a plain single address."""
    e = (email or "").strip().lower() if isinstance(email, str) else ""
    if len(e) > 254 or not EMAIL_RE.match(e):
        raise ValueError("enter a valid email address")
    return e


def _load(data_dir):
    if _cache["dir"] == data_dir and _cache["data"] is not None:
        return _cache["data"]
    try:
        with open(os.path.join(data_dir, FILE)) as f:
            d = json.load(f)
    except (OSError, ValueError):
        d = {}
    d = d if isinstance(d, dict) else {}
    d["users"] = d.get("users") if isinstance(d.get("users"), dict) else {}
    d["sessions"] = d.get("sessions") if isinstance(d.get("sessions"), dict) else {}
    _cache.update(dir=data_dir, data=d)
    return d


def _save(data_dir, d):
    fd, tmp = tempfile.mkstemp(dir=data_dir, prefix=".users-")
    with os.fdopen(fd, "w") as f:
        f.write(json.dumps(d, separators=(",", ":")))
    os.chmod(tmp, 0o600)
    os.replace(tmp, os.path.join(data_dir, FILE))   # atomic: a crash never leaves half a file
    _cache.update(dir=data_dir, data=d)


# ---------------------------------------------------------------- users
def has_users(data_dir):
    with _lock:
        return bool(_load(data_dir)["users"])


def get_user(data_dir, email):
    with _lock:
        u = _load(data_dir)["users"].get((email or "").lower())
        return dict(u, email=email.lower()) if u else None


def list_users(data_dir):
    with _lock:
        users = _load(data_dir)["users"]
        return [dict(users[e], email=e) for e in sorted(users)]


def set_user(data_dir, email, role, by=""):
    """Invite a new user or change an existing one's role."""
    email = norm_email(email)
    if role not in ROLES:
        raise ValueError("role must be admin or viewer")
    with _lock:
        d = _load(data_dir)
        u = d["users"].get(email)
        if u is None and len(d["users"]) >= MAX_USERS:
            raise ValueError("at most %d users" % MAX_USERS)
        d["users"][email] = dict(u or {"added": int(time.time()), "added_by": by, "last_login": 0}, role=role)
        _save(data_dir, d)
        return dict(d["users"][email], email=email)


def remove_user(data_dir, email):
    """Delete the user and every session they hold. Returns False if there was no such user."""
    email = (email or "").strip().lower()
    with _lock:
        d = _load(data_dir)
        if d["users"].pop(email, None) is None:
            return False
        d["sessions"] = {k: s for k, s in d["sessions"].items() if s.get("email") != email}
        _save(data_dir, d)
        for k in [k for k, v in _links.items() if v["email"] == email]:
            del _links[k]
    return True


def seed_admin(data_dir, email):
    """install.sh --admin-email: make sure that address exists as an admin (never demotes or removes anyone)."""
    email = norm_email(email)
    with _lock:
        u = get_user(data_dir, email)
        if not u or u["role"] != "admin":
            set_user(data_dir, email, "admin", by="install.sh")
            return True
    return False


# ---------------------------------------------------------------- sign-in links
def new_link(email, minutes):
    """A one-time token for this (already verified as invited) address."""
    now = time.time()
    with _lock:
        for k in [k for k, v in _links.items() if v["until"] < now]:
            del _links[k]
        if len(_links) > 5000:
            _links.clear()
        token = secrets.token_urlsafe(32)
        _links[_digest(token)] = {"email": email, "until": now + minutes * 60}
    return token


def use_link(data_dir, token):
    """Spend a sign-in token. Returns the user (still invited, link not expired) or None. A token works once."""
    if not isinstance(token, str) or not 20 <= len(token) <= 100:
        return None
    with _lock:
        hit = _links.pop(_digest(token), None)
        if not hit or hit["until"] < time.time():
            return None
        return get_user(data_dir, hit["email"])


# ---------------------------------------------------------------- sessions
def new_session(data_dir, email, method, days, cred_tag=""):
    """method 'link' (email set) or 'password' (break-glass admin, email None). cred_tag pins a password session
    to the password it was opened with, so changing the password ends it."""
    now = int(time.time())
    token = secrets.token_urlsafe(32)
    with _lock:
        d = _load(data_dir)
        sess = {k: s for k, s in d["sessions"].items() if s.get("until", 0) > now}
        if len(sess) >= MAX_SESSIONS:                     # drop the oldest rather than refuse a sign-in
            for k in sorted(sess, key=lambda k: sess[k].get("auth", 0))[:len(sess) - MAX_SESSIONS + 1]:
                del sess[k]
        sess[_digest(token)] = {"email": email, "method": method, "auth": now, "until": now + int(days * 86400),
                                "cred": cred_tag}
        d["sessions"] = sess
        if email and email in d["users"]:
            d["users"][email]["last_login"] = now
        _save(data_dir, d)
    return token


def get_session(data_dir, token, cred_tag=""):
    """The signed-in identity for a session cookie, or None. Role is read from the user list on every request,
    so a demotion or removal takes effect at once."""
    if not isinstance(token, str) or not 20 <= len(token) <= 100:
        return None
    with _lock:
        d = _load(data_dir)
        s = d["sessions"].get(_digest(token))
        if not s or s.get("until", 0) <= time.time():
            return None
        if s.get("method") == "link":
            u = d["users"].get(s.get("email") or "")
            if not u:
                return None
            role = u.get("role")
        else:
            if not hmac.compare_digest(str(s.get("cred", "")), str(cred_tag)):
                return None
            role = "admin"
        return {"email": s.get("email"), "role": role, "method": s.get("method"), "auth_time": s.get("auth", 0)}


def end_session(data_dir, token):
    if not isinstance(token, str):
        return
    with _lock:
        d = _load(data_dir)
        if d["sessions"].pop(_digest(token), None) is not None:
            _save(data_dir, d)


def reset_cache():                                  # tests
    with _lock:
        _cache.update(dir=None, data=None)
        _links.clear()
