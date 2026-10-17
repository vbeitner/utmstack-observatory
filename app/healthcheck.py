import os, ssl, sys, urllib.request

scheme = "https" if os.environ.get("TLS_CERT") else "http"
try:
    ctx = ssl._create_unverified_context() if scheme == "https" else None
    urllib.request.urlopen("%s://127.0.0.1:%s/healthz" % (scheme, os.environ.get("PORT", "8765")), timeout=4, context=ctx)
except Exception:
    sys.exit(1)
