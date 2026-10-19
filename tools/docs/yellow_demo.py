# Copyright (c) 2026 Victor Beitner. All rights reserved. See LICENSE.
"""Demo data everywhere, except a SIEM-health panel backed by a fake yellow cluster that the Apply fix button can
repair. Only for documentation screenshots: python3 yellow_demo.py <repo>/app [port]"""
import os
import sys
import tempfile
import threading

app = os.path.abspath(sys.argv[1])
port = int(sys.argv[2]) if len(sys.argv) > 2 else 8798
sys.path.insert(0, app)
sys.path.insert(0, os.path.join(os.path.dirname(app), "tests"))
os.environ.update(OS_URL="http://127.0.0.1:9", DATA_DIR=tempfile.mkdtemp(), BIND="127.0.0.1", PORT=str(port),
                  DASH_PASS=os.environ.get("DEMO_PASS", "demo-password-1"), OS_USER="observatory_reader",
                  OS_FIX_USER="observatory_fixer", OS_FIX_PASS="x")
import server  # noqa: E402
import demo  # noqa: E402
from test_health_fix import FakeCluster  # noqa: E402

real_cluster = server.api_cluster
demo.install(vars(server))
cluster = FakeCluster()
server.os_call, server._call_http, server.api_cluster = cluster.read, cluster.write, real_cluster
server.FIX_SETTLE_S = 0.3
threading.Thread(target=server.refresher, daemon=True).start()
print("ready on", port, flush=True)
server.Server(("127.0.0.1", port), server.Handler).serve_forever()
