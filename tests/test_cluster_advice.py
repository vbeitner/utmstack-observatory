"""The 'make OpenSearch green' advice must be runnable as printed. Run: python3 -m unittest discover -s tests -v"""
import importlib
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "app"))

INDICES = ["v11-alert-2026.10.17", "v11-log-linux-2026.10.17", "security-auditlog-2026.10.17",
           ".opendistro-ism-config", ".opendistro-job-scheduler-lock", "top_queries-2026.10.17",
           ".plugins-ml-config", "v11-log-x';id;'-2026.10.17", "evil$(touch /tmp/p)-2026.10.17"]


def load():
    os.environ.update(OS_URL="http://127.0.0.1:9", DATA_DIR=tempfile.mkdtemp())
    import server
    s = importlib.reload(server)

    def call(path, body=None, method="POST"):
        if path.startswith("/_cluster/health"):
            return {"status": "yellow", "number_of_data_nodes": 1, "active_primary_shards": 6, "active_shards": 6}
        if path.startswith("/_cat/shards"):
            return [{"index": i, "shard": "0", "prirep": "r", "state": "UNASSIGNED", "unassigned.reason": "INDEX_CREATED"} for i in INDICES]
        if path.startswith("/_cat/indices"):
            return [{"index": i, "health": "yellow", "pri": "1", "rep": "1", "pri.store.size": "100"} for i in INDICES]
        if path.startswith("/_cluster/allocation/explain"):
            return {"index": INDICES[0], "shard": 0, "primary": False, "allocate_explanation": "same_shard", "node_allocation_decisions": []}
        raise AssertionError(path)
    s.os_call = call
    return s


class ClusterAdvice(unittest.TestCase):
    def setUp(self):
        self.fix = load().api_cluster()["fix"]
        self.cmds = [st["cmd"] for st in self.fix["steps"]]

    def test_commands_use_sudo_for_every_docker_call(self):
        for c in self.cmds:
            self.assertNotRegex(c, r"(?<!sudo )docker (ps|exec|service)", c)

    def test_password_is_read_from_the_backend_service_not_typed(self):
        joined = "\n".join(self.cmds)
        self.assertNotIn("YOUR_OPENSEARCH_PASSWORD", joined)
        self.assertIn("ELASTICSEARCH_PASSWORD", joined)
        self.assertNotIn("-u admin:'", joined)              # never on a command line, only via stdin

    def test_system_indices_are_in_their_own_step(self):
        data = self.fix["steps"][0]
        system = [st for st in self.fix["steps"] if st["op"]["path"].endswith("/_settings?expand_wildcards=all")]
        self.assertIn("v11-alert-*", data["cmd"])
        self.assertNotIn(".opendistro", data["cmd"])
        # one request per system family: the security plugin refuses a whole request if any one index is protected
        targets = [st["cmd"].split("https://localhost:9200/")[1].split("/_settings")[0] for st in system]
        self.assertEqual(sorted(targets), sorted(["security-auditlog-*", ".opendistro-ism-config",
                                                  ".opendistro-job-scheduler-lock", ".plugins-ml-config"]))
        for st in system:
            self.assertIn("expand_wildcards=all", st["cmd"])   # hidden indices need it

    def test_explains_what_a_403_on_a_system_index_means(self):
        self.assertIn("certificate", self.fix["protected_note"])

    def test_hostile_index_names_never_reach_the_shell(self):
        joined = "\n".join(self.cmds)
        for bad in ("';id;'", "$(touch", "id;"):
            self.assertNotIn(bad, joined)
        self.assertTrue(any("v11-log-x" in m for m in self.fix["manual"]))   # reported, not silently dropped

    def test_undated_families_keep_their_exact_name(self):
        joined = "\n".join(self.cmds)
        self.assertIn("/.plugins-ml-config/_settings", joined)
        self.assertNotIn(".plugins-ml-config-*", joined)

    def test_template_is_legacy_low_order_so_utmstack_templates_win(self):
        template = self.fix["steps"][-1]["cmd"]
        self.assertIn("/_template/single-node-no-replicas", template)
        self.assertIn('\\"v11-alert-*\\"', template)
        self.assertNotIn("ism-config", template)               # single existing index: a template can never apply
        self.assertNotIn("_index_template", template)
        self.assertIn('\\"order\\":0', template)

    def test_explanation_does_not_claim_utmstack_template_covers_its_indices(self):
        notes = " ".join(n["text"] for n in load().api_cluster()["notes"])
        self.assertNotIn("sets 0 replicas for its alert, log", notes)


if __name__ == "__main__":
    unittest.main()
