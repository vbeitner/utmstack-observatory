# Copyright (c) 2026 Victor Beitner. All rights reserved. See LICENSE.
"""Outgoing email for sign-in links: SMTP (any relay) or Microsoft 365 through the Graph API. Standard library only.

cfg is a plain dict (see server.mail_config()):
  method       "smtp" | "graph" | ""      ("" = email off)
  from         sender address; for Graph the mailbox the app sends as
  smtp_host, smtp_port, smtp_security ("starttls" | "tls" | "none"), smtp_user, smtp_pass
  graph_tenant, graph_client_id, graph_secret   (Entra app registration with the Mail.Send application permission)
Certificates are always verified: these are public mail services, unlike UTMStack's internal OpenSearch.
"""
import json
import smtplib
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from email.message import EmailMessage
from email.utils import formataddr, make_msgid

TIMEOUT_S = 20
GRAPH_LOGIN = "https://login.microsoftonline.com"
GRAPH_API = "https://graph.microsoft.com/v1.0"
_token = {"key": None, "value": None, "until": 0.0}
_token_lock = threading.Lock()


def configured(cfg):
    """None when email can be sent with this cfg, else a short reason for the Settings panel."""
    m = cfg.get("method")
    if not m:
        return "email is off"
    if not cfg.get("from"):
        return "set the sender address"
    if m == "smtp":
        return None if cfg.get("smtp_host") else "set the SMTP server"
    if m == "graph":
        missing = [n for n, k in (("tenant ID", "graph_tenant"), ("client ID", "graph_client_id"),
                                  ("client secret", "graph_secret")) if not cfg.get(k)]
        return "set the Microsoft 365 " + ", ".join(missing) if missing else None
    return "unknown email method %r" % m


def send(cfg, to, subject, text, html=None):
    """Send one message; raises RuntimeError with a short, loggable reason on failure."""
    why = configured(cfg)
    if why:
        raise RuntimeError("email not set up: " + why)
    if cfg["method"] == "smtp":
        _send_smtp(cfg, to, subject, text, html)
    else:
        _send_graph(cfg, to, subject, text, html)


def _send_smtp(cfg, to, subject, text, html):
    msg = EmailMessage()
    msg["From"] = formataddr(("UTMStack Observatory", cfg["from"]))
    msg["To"] = to
    msg["Subject"] = subject
    msg["Message-ID"] = make_msgid(domain=cfg["from"].rpartition("@")[2] or None)
    msg["Auto-Submitted"] = "auto-generated"
    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype="html")
    sec = cfg.get("smtp_security") or "starttls"
    port = int(cfg.get("smtp_port") or (465 if sec == "tls" else 587 if sec == "starttls" else 25))
    ctx = ssl.create_default_context()
    try:
        if sec == "tls":
            s = smtplib.SMTP_SSL(cfg["smtp_host"], port, timeout=TIMEOUT_S, context=ctx)
        else:
            s = smtplib.SMTP(cfg["smtp_host"], port, timeout=TIMEOUT_S)
        with s:
            s.ehlo()
            if sec == "starttls":
                s.starttls(context=ctx)
                s.ehlo()
            if cfg.get("smtp_user"):
                s.login(cfg["smtp_user"], cfg.get("smtp_pass", ""))
            s.send_message(msg)
    except smtplib.SMTPAuthenticationError as e:
        raise RuntimeError("SMTP login refused (%s)" % e.smtp_code)
    except smtplib.SMTPException as e:
        raise RuntimeError("SMTP error: %s" % str(e)[:200])
    except (OSError, ssl.SSLError) as e:
        raise RuntimeError("cannot reach SMTP server %s:%d: %s" % (cfg["smtp_host"], port, str(e)[:160]))


def _http(url, data, headers):
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S, context=ssl.create_default_context()) as r:
            body = r.read()
            return r.status, json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        try:
            j = json.loads(e.read() or b"{}")
        except ValueError:
            j = {}
        err = j.get("error")
        detail = (err.get("message") if isinstance(err, dict) else j.get("error_description") or err) or ""
        raise RuntimeError("Microsoft 365 answered HTTP %d: %s" % (e.code, str(detail).split("\r")[0][:200]))
    except (OSError, ValueError) as e:
        raise RuntimeError("cannot reach Microsoft 365: %s" % str(e)[:160])


def _graph_token(cfg):
    key = (cfg["graph_tenant"], cfg["graph_client_id"], cfg["graph_secret"])
    with _token_lock:
        if _token["key"] == key and _token["until"] > time.time() + 60:
            return _token["value"]
        _, j = _http("%s/%s/oauth2/v2.0/token" % (GRAPH_LOGIN, urllib.parse.quote(cfg["graph_tenant"], safe="")),
                     urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": cfg["graph_client_id"],
                                             "client_secret": cfg["graph_secret"],
                                             "scope": "https://graph.microsoft.com/.default"}).encode(),
                     {"Content-Type": "application/x-www-form-urlencoded"})
        if not j.get("access_token"):
            raise RuntimeError("Microsoft 365 returned no access token")
        _token.update(key=key, value=j["access_token"], until=time.time() + int(j.get("expires_in", 3600)))
        return _token["value"]


def _send_graph(cfg, to, subject, text, html):
    body = {"message": {"subject": subject,
                        "body": {"contentType": "HTML", "content": html} if html else {"contentType": "Text", "content": text},
                        "toRecipients": [{"emailAddress": {"address": to}}]},
            "saveToSentItems": False}
    _http("%s/users/%s/sendMail" % (GRAPH_API, urllib.parse.quote(cfg["from"], safe="@")), json.dumps(body).encode(),
          {"Content-Type": "application/json", "Authorization": "Bearer " + _graph_token(cfg)})
