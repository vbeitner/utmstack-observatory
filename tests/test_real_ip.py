"""Tailscale real client addresses: install.sh's rule script and systemd unit (no root, iptables faked).
Run: python3 -m unittest discover -s tests -v"""
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INSTALL = os.path.join(ROOT, "install.sh")

FAKE_IPTABLES = r'''#!/bin/sh
# records calls; -S ts-postrouting succeeds, -D fails once the rule is gone (it never existed here)
echo "$*" >> "$LOG"
case "$*" in *"-S ts-postrouting"*) exit 0;; *"-D POSTROUTING"*) exit 1;; esac
exit 0
'''


@unittest.skipUnless(shutil.which("bash"), "needs bash")
class RealIp(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.bin = os.path.join(self.d, "bin"); os.mkdir(self.bin)
        for name, body in (("iptables", FAKE_IPTABLES), ("ip", "#!/bin/sh\nexit ${IP_RC:-0}\n"),
                           ("systemctl", "#!/bin/sh\necho \"systemctl $*\" >> \"$LOG\"\n")):
            p = os.path.join(self.bin, name)
            with open(p, "w") as f:
                f.write(body)
            os.chmod(p, 0o755)
        self.log = os.path.join(self.d, "log")

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def run_fn(self, fn, **env):
        e = dict(os.environ, PATH=self.bin + ":" + os.environ["PATH"], LOG=self.log,
                 REALIP_SCRIPT=os.path.join(self.d, "realip.sh"), SYSTEMD_DIR=self.d, INSTALL=INSTALL, **env)
        p = subprocess.run(["bash", "-c", 'source "$INSTALL"; info(){ echo "$*"; }; warn(){ echo "W: $*"; }; %s' % fn],
                           env=e, capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        return p.stdout

    def log_text(self):
        return open(self.log).read() if os.path.exists(self.log) else ""

    def test_installs_unit_and_puts_the_rule_first(self):
        out = self.run_fn("ensure_real_ip")
        unit = open(os.path.join(self.d, "utmstack-observatory-real-ip.service")).read()
        self.assertIn("PartOf=tailscaled.service", unit)
        self.assertIn("WantedBy=multi-user.target tailscaled.service", unit)
        self.assertIn("systemctl restart utmstack-observatory-real-ip", self.log_text())
        subprocess.run([os.path.join(self.d, "realip.sh"), "start"], env=dict(os.environ, PATH=self.bin + ":" + os.environ["PATH"], LOG=self.log), check=True)
        ins = [l for l in self.log_text().splitlines() if "-I POSTROUTING" in l]
        self.assertEqual(len(ins), 1)
        self.assertIn("-I POSTROUTING 1 -o docker_gwbridge -p tcp --dport 8765 -m mark --mark 0x40000/0xff0000", ins[0])
        self.assertIn("-j ACCEPT", ins[0])
        self.assertIn("keep their own address", out)

    def test_no_tailscale_means_nothing_installed(self):
        self.run_fn("ensure_real_ip", IP_RC="1")
        self.assertFalse(os.path.exists(os.path.join(self.d, "utmstack-observatory-real-ip.service")))
        self.assertEqual(self.log_text(), "")

    def test_opt_out_removes_it(self):
        self.run_fn("ensure_real_ip")
        self.run_fn("REAL_IP_RULE=0 ensure_real_ip")
        self.assertFalse(os.path.exists(os.path.join(self.d, "utmstack-observatory-real-ip.service")))
        self.assertFalse(os.path.exists(os.path.join(self.d, "realip.sh")))
        self.assertIn("systemctl disable --now utmstack-observatory-real-ip", self.log_text())


if __name__ == "__main__":
    unittest.main()
