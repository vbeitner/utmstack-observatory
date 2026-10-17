"""Start server.py exactly as the container does (python3 -I, see Dockerfile CMD) and make sure it gets as far as
listening. Isolated mode (-I) leaves the script's own folder off sys.path, so a sibling-module import that works in
unit tests can still crash the real service. Run: python3 -m unittest discover -s tests -v"""
import os
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class ContainerStart(unittest.TestCase):
    def test_server_starts_in_isolated_mode(self):
        env = {"PATH": os.environ.get("PATH", ""), "OS_URL": "http://127.0.0.1:9", "DATA_DIR": tempfile.mkdtemp(),
               "BIND": "127.0.0.1", "PORT": "0"}
        p = subprocess.Popen([sys.executable, "-I", os.path.join(ROOT, "app", "server.py")], env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            deadline, out = time.time() + 10, ""
            while time.time() < deadline:
                line = p.stdout.readline()
                out += line
                if "UTMStack Observatory" in line and " on http" in line:
                    break
                if p.poll() is not None:
                    out += p.stdout.read()
                    break
            self.assertIn(" on http", out, "server did not start:\n" + out[-1500:])
        finally:
            p.kill()
            p.wait()


if __name__ == "__main__":
    unittest.main()
