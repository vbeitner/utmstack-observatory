"""Swarm ingress hides client addresses: the one-time startup hint and the installer's host-mode publish.
Run: python3 -m unittest discover -s tests -v"""
import importlib
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "app"))

# /proc/net/route of a Swarm task on the ingress (10.0.0.0/24), a stack overlay (10.0.1.0/24) and docker_gwbridge
ROUTE = """Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth2	00000000	010012AC	0003	0	0	0	00000000	0	0	0
eth0	0000000A	00000000	0001	0	0	0	00FFFFFF	0	0	0
eth1	0001000A	00000000	0001	0	0	0	00FFFFFF	0	0	0
eth2	000012AC	00000000	0001	0	0	0	0000FFFF	0	0	0
"""


def load():
    os.environ.update(OS_URL="http://127.0.0.1:9", DATA_DIR=tempfile.mkdtemp())
    import server
    return importlib.reload(server)


class SharedAddressHint(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s = load()
        f = tempfile.NamedTemporaryFile("w", suffix=".route", delete=False)
        f.write(ROUTE)
        f.close()
        cls.nets = cls.s.connected_subnets(f.name)

    def test_connected_subnets_parses_proc_net_route(self):
        self.assertEqual([str(n) for n in self.nets], ["10.0.0.0/24", "10.0.1.0/24", "172.18.0.0/16"])
        self.assertEqual(self.s.connected_subnets("/nonexistent/route"), [])

    def watch(self, after=5):
        return self.s.SharedAddressWatch(after, self.nets)

    def test_hint_once_when_every_connection_comes_from_the_ingress_gateway(self):
        w = self.watch()
        out = [w.seen("10.0.0.2") for _ in range(10)]
        self.assertEqual([o for o in out if o], [out[4]])
        self.assertIn("10.0.0.2", out[4])
        self.assertIn("mode=host", out[4])

    def test_no_hint_with_real_client_addresses(self):
        w = self.watch()
        self.assertFalse(any(w.seen(ip) for ip in ["100.70.1.5"] * 3 + ["100.70.1.9"] + ["100.70.1.5"] * 10))

    def test_no_hint_for_a_single_user_outside_the_container_networks(self):
        w = self.watch()
        self.assertFalse(any(w.seen("192.168.1.20") for _ in range(10)))

    def test_loopback_healthchecks_are_ignored(self):
        w = self.watch()
        self.assertFalse(any(w.seen("127.0.0.1") for _ in range(20)))
        self.assertTrue(any(w.seen("10.0.0.2") for _ in range(5)))

    def test_disabled_with_zero_or_without_subnets(self):
        self.assertFalse(any(self.s.SharedAddressWatch(0, self.nets).seen("10.0.0.2") for _ in range(10)))
        self.assertFalse(any(self.s.SharedAddressWatch(5, []).seen("10.0.0.2") for _ in range(10)))


class InstallerPublish(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(ROOT, "install.sh")) as f:
            self.sh = f.read()

    def test_port_is_published_in_host_mode_on_this_node(self):
        self.assertIn('--publish "published=$PORT,target=8765,protocol=tcp,mode=host"', self.sh)
        self.assertIn("node.id==$(docker info --format '{{.Swarm.NodeID}}')", self.sh)

    def test_installer_waits_for_the_old_container_to_free_the_port(self):
        rm = self.sh.index('docker service rm "$SERVICE" >/dev/null')
        wait = self.sh.index('label=com.docker.swarm.service.name=$SERVICE')
        create = self.sh.index("docker service create")
        self.assertLess(rm, wait)
        self.assertLess(wait, create)

    def test_login_check_skipped_when_settings_panel_overrides_the_login(self):
        self.assertIn("--configured dash_user dash_pass", self.sh)
        self.assertIn('if [ -n "$OVERRIDDEN" ]; then', self.sh)

    def test_settings_store_reports_overridden_keys_by_name_only(self):
        d = tempfile.mkdtemp()
        run = lambda: subprocess.run([sys.executable, "-I", os.path.join(ROOT, "app", "settings_store.py"), d,
                                      "--configured", "dash_user", "dash_pass"], capture_output=True, text=True)
        self.assertEqual(run().stdout.strip(), "")
        with open(os.path.join(d, "settings.json"), "w") as f:
            f.write('{"dash_pass":"pbkdf2$secret-hash","dash_user":"","home":"1,2"}')
        r = run()
        self.assertEqual((r.returncode, r.stdout.strip()), (0, "dash_pass"))
        self.assertNotIn("secret", r.stdout)


if __name__ == "__main__":
    unittest.main()
