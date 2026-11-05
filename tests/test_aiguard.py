"""zenos-aiguard: which AI services stay reachable for the exposed level (system/sbin/zenos_aiguard.py). The decision
is zenos-decide's (formal/ZenosFormal/Flow.lean); build it first: cd formal && lake build. The end-to-end part runs
in a private network namespace and is skipped where unprivileged namespaces are not available."""
import json, os, shutil, subprocess, sys, tempfile, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "../system/sbin"))
sys.path.insert(0, os.path.join(HERE, "../system/lib"))
import zdecide
import zenos_aiguard as G


def put(path, obj):
    with open(path, "w") as f:
        f.write(obj if isinstance(obj, str) else json.dumps(obj))


class Decision(unittest.TestCase):
    def test_reachable_matches_the_proven_ceilings(self):
        ceiling = {"external-ai": 2, "gov-ai": 3, "ministry-ai": 5}
        for level in range(0, 6):
            svcs = G.decide(level, [{"host": "h", "port": 443, "kind": k} for k in G.KINDS])
            for s in svcs:
                self.assertEqual(s["allow"], level <= 1 or level <= ceiling[s["kind"]], (level, s["kind"]))
                self.assertEqual(s["allow"], zdecide.flow(level, s["kind"]))

    def test_no_answer_is_a_block(self):
        def broken(*a):
            raise RuntimeError("zenos-decide missing")
        svcs = G.decide(0, [{"host": "h", "port": 443, "kind": "ministry-ai"}], flow=broken)
        self.assertFalse(svcs[0]["allow"])
        svcs = G.decide(0, [{"host": "h", "port": 443, "kind": "gov-ai"}], flow=lambda *a: 1)   # not exactly True
        self.assertFalse(svcs[0]["allow"])

    def test_rules_reject_only_what_is_not_allowed(self):
        v4, v6 = G.rules([{"host": "a", "port": 443, "kind": "external-ai", "allow": False, "addrs": ["192.0.2.1", "2001:db8::1"]},
                          {"host": "b", "port": 8443, "kind": "gov-ai", "allow": True, "addrs": ["192.0.2.2"]}])
        self.assertEqual(v4, ["-A ZENOS_AI -d 192.0.2.1/32 -p tcp --dport 443 -j REJECT --reject-with tcp-reset"])
        self.assertEqual(v6, ["-A ZENOS_AI -d 2001:db8::1/128 -p tcp --dport 443 -j REJECT --reject-with tcp-reset"])

    def test_registry_learned_and_bad_entries(self):
        with tempfile.TemporaryDirectory() as d:
            G.REGISTRY, G.LEARNED, G.EXPOSED = d + "/ai.json", d + "/learned.json", d + "/exposed.json"
            put(G.REGISTRY, {"services": [{"url": "https://gov.example/v1", "kind": "gov-ai"},
                                          {"url": "https://odd.example/v1", "kind": "trusted"},
                                          {"url": "ftp://x.example/"}]})
            put(G.LEARNED, ["https://gov.example/", "https://api.example:8443/v1"])
            got = {(s["host"], s["port"]): s["kind"] for s in G.services()}
            self.assertEqual(got, {("gov.example", 443): "gov-ai", ("odd.example", 443): "external-ai",
                                   ("api.example", 8443): "external-ai"})
            self.assertEqual(G.exposure(), 0)
            put(G.EXPOSED, {"level": 3})
            self.assertEqual(G.exposure(), 3)
            for bad in ("not json", '{"level": "x"}', "{}"):
                put(G.EXPOSED, bad)
                self.assertEqual(G.exposure(), 5, bad)   # a record that cannot be read counts as the highest level

    def test_learning_is_bounded(self):
        """any local account can ask, so it can add only so much: LEARN_RATE new services an hour, MAX_LEARNED in all"""
        with tempfile.TemporaryDirectory() as d:
            G.REGISTRY, G.LEARNED = d + "/ai.json", d + "/learned.json"
            G.LOG, G.LEDGER = d + "/g.log", d + "/l.jsonl"
            g = G.Guard()
            for i in range(G.LEARN_RATE + 5):
                g.learn(("h%d.example" % i, 443), uid=1001)
            self.assertEqual(len(json.load(open(G.LEARNED))), G.LEARN_RATE)
            g.learn(("other.example", 443), uid=1002)                     # another account has its own allowance
            self.assertEqual(len(json.load(open(G.LEARNED))), G.LEARN_RATE + 1)
            g.learn(("bad host$(x)", 443), uid=1003)
            self.assertEqual(len(json.load(open(G.LEARNED))), G.LEARN_RATE + 1)
            put(G.LEARNED, ["https://x%d.example/" % i for i in range(G.MAX_LEARNED)])
            g.learn(("full.example", 443), uid=1004)
            self.assertEqual(len(json.load(open(G.LEARNED))), G.MAX_LEARNED)

    def test_target(self):
        self.assertEqual(G.target("https://API.Example.com/v1"), ("api.example.com", 443))
        self.assertEqual(G.target("http://10.0.0.5:8000/v1"), ("10.0.0.5", 8000))
        self.assertIsNone(G.target("file:///etc/passwd"))
        self.assertIsNone(G.target("not a url"))


@unittest.skipUnless(shutil.which("unshare") and shutil.which("iptables"), "needs unshare and iptables")
class Kernel(unittest.TestCase):
    def test_in_a_private_network_namespace(self):
        r = subprocess.run(["unshare", "-rn", sys.executable, os.path.join(HERE, "netns_aiguard.py")],
                           capture_output=True, text=True, timeout=120)
        if r.returncode != 0 and "Operation not permitted" in r.stderr:
            self.skipTest("unprivileged network namespaces are not available here")
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout.strip().splitlines()[-1])
        for lvl, ext, gov, mins in ((0, 1, 1, 1), (1, 1, 1, 1), (2, 1, 1, 1), (3, 0, 1, 1), (4, 0, 0, 1), (5, 0, 0, 1)):
            ok, seen, e, g, m = out[str(lvl)]
            self.assertTrue(ok, lvl)
            self.assertEqual(seen, lvl)
            self.assertEqual([e, g, m], [bool(ext), bool(gov), bool(mins)], lvl)
        self.assertFalse(out["check_new"]["allow"])
        self.assertEqual(out["check_new"]["kind"], "external-ai")
        self.assertFalse(out["new_reach"])
        self.assertTrue(out["check_gov"]["allow"])
        self.assertTrue(out["unhooked_reach"])        # with the hook removed the block is gone ...
        self.assertFalse(out["rehooked_reach"])       # ... until the guard's next pass puts it back
        self.assertEqual(out["broken"], [False, False, True])
        self.assertEqual(out["after_reset"], [True, True, True, True])


if __name__ == "__main__":
    unittest.main()
