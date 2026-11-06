"""The release ledger: a package goes in only when a majority of the audit nodes hold the same record, signed by
enough release officers. Three audit nodes run on 127.0.0.1 in this process."""
import base64, io, json, os, shutil, socket, subprocess, sys, tempfile, threading, time, unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path[0:0] = [str(REPO / "system" / "lib"), str(REPO / "system" / "sbin")]
import zdecide, zsupply, zident                                  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey   # noqa: E402
from cryptography.hazmat.primitives import serialization          # noqa: E402


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def raw(k):
    return k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def make_deb(d, name, version, payload):
    root = d / f"{name}-{version}-{abs(hash(payload)) % 10**6}"
    (root / "DEBIAN").mkdir(parents=True)
    (root / "DEBIAN" / "control").write_text(f"Package: {name}\nVersion: {version}\nArchitecture: all\n"
                                             f"Maintainer: test <t@example.invalid>\nDescription: test\n")
    (root / "etc").mkdir()
    (root / "etc" / f"{name}.conf").write_text("setting = 1\n")
    (root / "DEBIAN" / "conffiles").write_text(f"/etc/{name}.conf\n")
    (root / "usr" / "bin").mkdir(parents=True)
    (root / "usr" / "bin" / name).write_bytes(payload)
    out = d / f"{root.name}.deb"
    subprocess.run(["dpkg-deb", "--root-owner-group", "--build", str(root), str(out)], check=True, capture_output=True)
    return out


@unittest.skipUnless(shutil.which("dpkg-deb"), "dpkg-deb is not installed")
class ReleaseLedger(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import zenos_auditnode
        cls.tmp = Path(tempfile.mkdtemp(prefix="zenos-supply-"))
        cls.officers = {n: Ed25519PrivateKey.generate() for n in ("ito", "kato", "mori")}
        cls.keys = {n: raw(k) for n, k in cls.officers.items()}
        cls.publisher = zident.FileIdentity(cls.tmp / "publisher.key")
        cls.nodes, cls.pcnodes = [], []
        for i in range(3):
            node = zenos_auditnode.Node(cls.tmp / f"node{i}")
            node.publishers = ("zenos-release",)
            node.enroll("zenos-release", base64.b64encode(cls.publisher.pub()).decode())
            port = free_port()
            threading.Thread(target=zenos_auditnode.serve, args=(node, "127.0.0.1", port), daemon=True).start()
            cls.nodes.append(node)
            cls.pcnodes.append({"name": f"node{i}", "url": f"http://127.0.0.1:{port}", "pub": node.pub_b64()})
            for _ in range(50):
                try:
                    socket.create_connection(("127.0.0.1", port), timeout=1).close()
                    break
                except OSError:
                    time.sleep(0.1)
        cls.deb = make_deb(cls.tmp, "zenos-demo", "1.0", b"#!/bin/sh\necho real\n")

    def record(self, deb, signers, rings=None):
        rec = {"manifest": zsupply.manifest(deb, rings=rings)}
        for n in signers:
            zsupply.sign(rec, self.officers[n], n)
        return rec

    def publish(self, rec, nodes):
        """the publisher ships the record to the given audit nodes (its own "releases" chain)"""
        import zledger, zenos_auditship as S
        led = self.tmp / f"releases-{id(nodes)}-{time.time()}.jsonl"
        zledger.append(str(led), "release" if "manifest" in rec else "revoke", "pub", "zenos-release", record=rec)
        for i in nodes:
            n = self.nodes[i]
            held = n.held("zenos-release", "releases")
            recs = [json.loads(l) for l in led.read_text().splitlines()]
            # continue the chain this node already holds
            import zledger as L
            body = {k: v for k, v in recs[0].items() if k not in ("hash", "prev")}
            prev = held[-1] if held else L.GENESIS
            body["prev"] = prev
            body["hash"] = __import__("hashlib").sha256(prev.encode() + L._canon({k: v for k, v in body.items() if k != "hash"})).hexdigest()
            b = S.sign(self.publisher, {"machine": "zenos-release", "chain": "releases", "from": len(held), "records": [body]})
            code, ans = n.accept(b)
            self.assertEqual(code, 200, ans)

    def decide(self, deb, required=2, ring=1, nodes=None, keys=None):
        ok, why, _ = zsupply.decide(deb, nodes or self.pcnodes, keys if keys is not None else self.keys, required, ring)
        return ok, why

    # ------------------------------------------------------------------
    def test_a_released_package_goes_in(self):
        rec = self.record(self.deb, ["ito", "kato"])
        self.publish(rec, [0, 1, 2])
        self.assertEqual(self.decide(self.deb), (True, None))
        self.assertEqual(rec["manifest"]["conffiles"], ["/etc/zenos-demo.conf"])
        self.assertIn("/usr/bin/zenos-demo", rec["manifest"]["files"])

    def test_one_officer_is_not_enough(self):
        deb = make_deb(self.tmp, "zenos-one", "1.0", b"one key")
        self.publish(self.record(deb, ["ito"]), [0, 1, 2])
        self.assertEqual(self.decide(deb), (False, "signatures"))

    def test_one_audit_node_is_not_enough(self):
        """a record that only one node holds (that node taken over) does not let the package in"""
        deb = make_deb(self.tmp, "zenos-onenode", "1.0", b"one node")
        self.publish(self.record(deb, ["ito", "kato"]), [2])
        self.assertEqual(self.decide(deb), (False, "ledger"))

    def test_a_file_not_in_the_ledger_stays_out(self):
        """the NetamLoader pattern: real package, one changed file inside"""
        self.publish(self.record(self.deb, ["ito", "kato"]), [0, 1, 2])
        evil = make_deb(self.tmp, "zenos-demo", "1.0", b"#!/bin/sh\necho changed\n")
        ok, why = self.decide(evil)
        self.assertFalse(ok)
        self.assertIn(why, ("hash", "ledger"))

    def test_forged_node_answers_do_not_count(self):
        deb = make_deb(self.tmp, "zenos-forged", "1.0", b"forged")
        self.publish(self.record(deb, ["ito", "kato"]), [0, 1, 2])
        wrong = [dict(n, pub=base64.b64encode(raw(Ed25519PrivateKey.generate())).decode()) for n in self.pcnodes[:2]]
        self.assertEqual(self.decide(deb, nodes=wrong + self.pcnodes[2:]), (False, "ledger"))

    def test_revoked_and_rings(self):
        deb = make_deb(self.tmp, "zenos-ring", "2.0", b"rings")
        rec = self.record(deb, ["ito", "kato"], rings={"0": 0, "1": int(time.time()) + 86400})
        self.publish(rec, [0, 1, 2])
        self.assertEqual(self.decide(deb, ring=0), (True, None))
        self.assertEqual(self.decide(deb, ring=1), (False, "ring"))            # not this PC's turn yet
        rv = {"revoke": {"sha256": rec["manifest"]["sha256"], "reason": "test", "t": 1}}
        for n in ("kato", "mori"):
            zsupply.sign(rv, self.officers[n], n)
        self.publish(rv, [0, 1])
        self.assertEqual(self.decide(deb, ring=0), (False, "revoked"))

    def test_tricks_with_records(self):
        deb = make_deb(self.tmp, "zenos-tricks", "1.0", b"tricks")
        rec = self.record(deb, ["ito", "kato"])
        self.publish(rec, [0, 1, 2])
        # the publisher adds a "revoke" field to the genuine release record: not a revocation
        forged = dict(rec, revoke={"sha256": rec["manifest"]["sha256"], "reason": "x", "t": 1})
        self.publish(forged, [0, 1, 2])
        # a copy with its signatures stripped, and another record for the same file far in the future
        self.publish({"manifest": rec["manifest"], "sigs": []}, [0])
        later = self.record(deb, ["ito", "kato"], rings={"1": 4_000_000_000})
        self.publish(later, [0, 1, 2])
        self.assertEqual(self.decide(deb), (True, None))
        # a genuine revocation, held by a single node, is enough to keep it out
        rv = {"revoke": {"sha256": rec["manifest"]["sha256"], "reason": "bad build", "t": 2}}
        for n in ("ito", "mori"):
            zsupply.sign(rv, self.officers[n], n)
        self.publish(rv, [2])
        self.assertEqual(self.decide(deb), (False, "revoked"))

    def test_one_node_serving_a_malformed_record_changes_nothing(self):
        """one node of three adds a record of the wrong shape: it is skipped, the majority's record still decides"""
        deb = make_deb(self.tmp, "zenos-shapes", "1.0", b"shapes")
        rec = self.record(deb, ["ito", "kato"])
        sha = rec["manifest"]["sha256"]
        bad = [{"manifest": {"sha256": sha, "rings": {"1": "x"}}}, {"manifest": {"sha256": sha, "rings": ["1"]}},
               dict(rec, sigs=5), {"revoke": {"sha256": sha}, "sigs": ["x"]}, "junk", None]
        def get(node, s):
            return [rec] + (bad if node["name"] == "n2" else [])
        nodes = [{"name": f"n{i}"} for i in range(3)]
        self.assertEqual(zsupply.decide(deb, nodes, self.keys, 2, 1, get=get)[:2], (True, None))
        self.assertEqual(zsupply.decide(deb, nodes, self.keys, 2, 1, get=lambda n, s: {"not": "a list"})[0], False)

    def test_apt_hook(self):
        import zenos_pkgcheck as P
        led = self.tmp / "pc-ledger.jsonl"
        P.LEDGER = str(led)
        saved = (zsupply.KEYS, zsupply.AUDIT_CONF)
        kd = self.tmp / "release-keys"
        kd.mkdir(exist_ok=True)
        for n, k in self.keys.items():
            (kd / f"{n}.pub").write_bytes(k)
        (self.tmp / "audit.json").write_text(json.dumps({"nodes": self.pcnodes}))
        zsupply.KEYS, zsupply.AUDIT_CONF = kd, self.tmp / "audit.json"
        try:
            good = make_deb(self.tmp, "zenos-hook", "1.0", b"hook")
            self.publish(self.record(good, ["kato", "mori"]), [0, 1, 2])
            bad = make_deb(self.tmp, "zenos-hook", "1.0", b"hook, changed")
            err = io.StringIO()
            self.assertEqual(P.check([str(good)], {"mode": "enforce", "required": 2, "ring": 1}, out=err), 0)
            self.assertEqual(P.check([str(good), str(bad)], {"mode": "enforce", "required": 2, "ring": 1}, out=err), 1)
            self.assertEqual(P.check([str(bad)], {"mode": "warn", "required": 2, "ring": 1}, out=err), 0)
            self.assertEqual(P.check([str(bad)], {"mode": "enforce", "broken": True}, out=err), 1)
            events = [json.loads(l)["event"] for l in led.read_text().splitlines()]
            self.assertEqual(events, ["pkg-allowed", "pkg-allowed", "pkg-refused", "pkg-would-refuse", "pkg-refused"])
        finally:
            zsupply.KEYS, zsupply.AUDIT_CONF = saved


class DpkgWrapper(unittest.TestCase):
    """dpkg reads a root-only copy, checked by its SHA-256; a file swapped after apt's check is never installed"""
    def test_copies_checked_again(self):
        import importlib
        tmp = Path(tempfile.mkdtemp(prefix="zenos-dpkgw-"))
        fake = tmp / "dpkg"
        fake.write_text("#!/bin/sh\nfor a in \"$@\"; do case \"$a\" in *.deb) sha256sum \"$a\" >> " + str(tmp / "read") + ";; esac; done\n")
        fake.chmod(0o755)
        os.environ.update(ZENOS_REAL_DPKG=str(fake), ZENOS_DPKG_STAGE=str(tmp / "stage"),
                          ZENOS_PKGCHECK_CACHE=str(tmp / "cache.json"), ZENOS_PKGCHECK_LEDGER=str(tmp / "l.jsonl"),
                          ZENOS_SUPPLY_CONF=str(tmp / "supply.json"))
        (tmp / "supply.json").write_text(json.dumps({"mode": "enforce", "required": 2, "ring": 1}))
        import zsupply as Z, zenos_pkgcheck as P
        importlib.reload(Z); importlib.reload(P)
        import importlib.machinery, importlib.util
        loader = importlib.machinery.SourceFileLoader("zdpkg", str(REPO / "system" / "sbin" / "zenos-dpkg"))
        W = importlib.util.module_from_spec(importlib.util.spec_from_loader("zdpkg", loader))
        loader.exec_module(W)
        good = make_deb(tmp, "zenos-w", "1.0", b"good")
        P.remember(Z.sha256_file(good))                       # what apt's check allowed a moment ago
        self.assertEqual(W.main(["--unpack", str(good)]), 0)
        self.assertEqual((tmp / "read").read_text().split()[0], Z.sha256_file(good))
        evil = make_deb(tmp, "zenos-w", "1.0", b"swapped after the check")
        shutil.copy(evil, good)                                # the swap in the download folder
        P.zsupply.audit_nodes = lambda: []
        self.assertEqual(W.main(["--unpack", str(good)]), 2)
        self.assertEqual(len((tmp / "read").read_text().splitlines()), 1)   # dpkg never saw the swapped file
        self.assertEqual(os.listdir(tmp / "stage"), [])
        renamed = tmp / "package"                              # a package without the .deb name is checked too
        shutil.copy(evil, renamed)
        self.assertEqual(W.main(["--install", str(renamed)]), 2)
        self.assertEqual(W.main(["-R", "--install", str(tmp)]), 2)          # a whole folder: refused
        self.assertEqual(W.main(["-iR", str(tmp)]), 2)
        os.mkfifo(tmp / "pipe.deb")                            # a pipe could hand dpkg other bytes
        self.assertEqual(W.main(["--install", str(tmp / "pipe.deb")]), 2)
        dash = tmp / "-x.deb"                                  # after "--", a name starting with "-" is a file
        shutil.copy(evil, dash)
        os.chdir(tmp)
        try:
            self.assertEqual(W.main(["--install", "--", "-x.deb"]), 2)
        finally:
            os.chdir(REPO)
        self.assertEqual(len((tmp / "read").read_text().splitlines()), 1)
        for k in ("ZENOS_REAL_DPKG", "ZENOS_DPKG_STAGE", "ZENOS_PKGCHECK_CACHE", "ZENOS_PKGCHECK_LEDGER", "ZENOS_SUPPLY_CONF"):
            os.environ.pop(k, None)
        importlib.reload(Z); importlib.reload(P)


if __name__ == "__main__":
    unittest.main()
