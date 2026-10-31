"""Legacy real-address unit: install.sh removes what an older install left behind and never installs it (no root,
iptables and systemctl faked).
Run: python3 -m unittest discover -s tests -v"""
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INSTALL = os.path.join(ROOT, "install.sh")

# Stand-in for the script an older install wrote: records that it was asked to stop (and so delete its NAT rule).
OLD_SCRIPT = '#!/bin/sh\necho "old-script $*" >> "$LOG"\n'
UNIT = "utmstack-observatory-real-ip.service"


@unittest.skipUnless(shutil.which("bash"), "needs bash")
class LegacyRealIp(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.bin = os.path.join(self.d, "bin"); os.mkdir(self.bin)
        for name, body in (("iptables", '#!/bin/sh\necho "iptables $*" >> "$LOG"\n'),
                           ("systemctl", '#!/bin/sh\necho "systemctl $*" >> "$LOG"\n')):
            p = os.path.join(self.bin, name)
            with open(p, "w") as f:
                f.write(body)
            os.chmod(p, 0o755)
        self.log = os.path.join(self.d, "log")
        self.script = os.path.join(self.d, "realip.sh")

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def run_fn(self, fn, **env):
        e = dict(os.environ, PATH=self.bin + ":" + os.environ["PATH"], LOG=self.log,
                 REALIP_SCRIPT=self.script, SYSTEMD_DIR=self.d, INSTALL=INSTALL, **env)
        p = subprocess.run(["bash", "-c", 'source "$INSTALL"; info(){ echo "$*"; }; warn(){ echo "W: $*"; }; %s' % fn],
                           env=e, capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        return p.stdout

    def log_text(self):
        return open(self.log).read() if os.path.exists(self.log) else ""

    def plant_legacy(self):
        with open(os.path.join(self.d, UNIT), "w") as f:
            f.write("[Unit]\nDescription=old\n")
        with open(self.script, "w") as f:
            f.write(OLD_SCRIPT)
        os.chmod(self.script, 0o755)

    def test_removes_a_legacy_unit_and_its_rule(self):
        self.plant_legacy()
        out = self.run_fn("remove_legacy_real_ip")
        self.assertFalse(os.path.exists(os.path.join(self.d, UNIT)))
        self.assertFalse(os.path.exists(self.script))
        log = self.log_text()
        self.assertIn("systemctl disable --now utmstack-observatory-real-ip", log)
        self.assertIn("old-script stop", log)
        self.assertIn("Removed the legacy", out)

    def test_nothing_left_behind_means_nothing_done(self):
        out = self.run_fn("remove_legacy_real_ip")
        self.assertEqual(self.log_text(), "")
        self.assertEqual(out, "")

    def test_installer_never_installs_the_unit_or_a_nat_rule(self):
        src = open(INSTALL).read()
        self.assertNotIn("ensure_real_ip", src)
        self.assertNotIn("iptables -t nat -I", src)
        self.assertNotIn("REAL_IP_RULE=%q", src)


if __name__ == "__main__":
    unittest.main()
