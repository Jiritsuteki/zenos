"""Kernel hardening and outside visibility (0.1.2): the sysctl and module settings the package installs, the restart
window for kernel fixes, and what the audit node learns from a PC's signed status (system/sbin/zenos_auditship.py,
zenos_auditnode.py, zenos_restartwindow.py). The audit node's chain check runs zenos-decide: cd formal && lake build."""
import base64, hashlib, json, os, sys, tempfile, time, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "../system/sbin"))
sys.path.insert(0, os.path.join(HERE, "../system/lib"))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import zledger
import zenos_auditnode as an
import zenos_auditship as ship
import zenos_restartwindow as rw


def read(p):
    with open(p) as f:
        return f.read()


class KernelSettings(unittest.TestCase):
    def test_sysctl(self):
        kv = {}
        for line in read(os.path.join(HERE, "../system/sysctl.d/60-zenos-hardening.conf")).splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            k, _, v = line.partition("=")
            self.assertTrue(k.strip() and v.strip(), line)
            self.assertNotIn(k.strip(), kv, "set twice: " + k)
            kv[k.strip()] = v.strip()
        self.assertEqual(kv["net.mptcp.enabled"], "0")
        self.assertEqual(kv["kernel.io_uring_disabled"], "2")
        self.assertEqual(kv["kernel.unprivileged_bpf_disabled"], "1")
        self.assertEqual(kv["kernel.kptr_restrict"], "1")       # 2 would hide symbols from the root sentinel too

    def test_lockdown(self):
        g = read(os.path.join(HERE, "../system/grub.d/zenos-hardening.cfg"))
        line = [l for l in g.splitlines() if l.startswith("GRUB_CMDLINE_LINUX_DEFAULT=")]
        self.assertEqual(len(line), 1)
        self.assertIn("$GRUB_CMDLINE_LINUX_DEFAULT ", line[0])      # adds to the existing line, never replaces it
        self.assertIn("lockdown=integrity", line[0])
        self.assertIn("lockdown=integrity", read(os.path.join(HERE, "../packaging/iso/build-iso.sh")))

    def test_modules(self):
        mods = []
        for line in read(os.path.join(HERE, "../system/modprobe.d/zenos-blacklist.conf")).splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            w = line.split()
            self.assertEqual((w[0], w[2], len(w)), ("install", "/bin/false", 3), line)
            mods.append(w[1])
        for m in ("dccp", "sctp", "rds", "tipc", "firewire-ohci"):
            self.assertIn(m, mods)
        for needed in ("squashfs", "overlay", "isofs", "vfat", "exfat", "ext4", "udf", "usb_storage", "dm_crypt", "nf_tables", "bluetooth"):
            self.assertNotIn(needed, mods, needed + " is needed by the live image, USB drives, encryption or the firewall")


class RestartWindow(unittest.TestCase):
    def test_decide(self):
        now = time.time()
        user = lambda idle, since: ("1", "user", idle, since)
        self.assertEqual(rw.decide("no-session", False, [], now, 3)[0], False)
        self.assertEqual(rw.decide("off", True, [], now, 3)[0], False)
        self.assertEqual(rw.decide("no-session", True, [("c1", "greeter", False, 0)], now, 14)[0], True)
        self.assertEqual(rw.decide("no-session", True, [user(True, now - 7200)], now, 3)[0], False)
        self.assertEqual(rw.decide("idle", True, [user(True, now - 7200)], now, 3)[0], True)
        self.assertEqual(rw.decide("idle", True, [user(True, now - 600)], now, 3)[0], False)     # idle, but not an hour
        self.assertEqual(rw.decide("idle", True, [user(True, now - 7200)], now, 14)[0], False)   # not at night
        self.assertEqual(rw.decide("idle", True, [user(False, 0)], now, 3)[0], False)

    def test_fix_waiting(self):
        with tempfile.TemporaryDirectory() as d:
            flag = os.path.join(d, "reboot-required")
            self.assertFalse(rw.fix_waiting("6.12.113+deb13-amd64", "6.12.113+deb13-amd64", flag)[0])
            self.assertTrue(rw.fix_waiting("6.12.112+deb13-amd64", "6.12.113+deb13-amd64", flag)[0])
            self.assertFalse(rw.fix_waiting("6.12.113+deb13-amd64", "6.12.99+deb13-amd64", flag)[0])   # 113 > 99, numerically
            open(flag, "w").close()
            self.assertTrue(rw.fix_waiting("6.12.113+deb13-amd64", "6.12.113+deb13-amd64", flag)[0])

    def test_policy(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "policy.conf")
            rw.POLICY = p
            self.assertEqual(rw.policy(), "no-session")
            with open(p, "w") as f:
                f.write("terminal = allowed\nkernel_restart = idle   # at night\n")
            self.assertEqual(rw.policy(), "idle")
            with open(p, "w") as f:
                f.write("kernel_restart = always\n")
            self.assertEqual(rw.policy(), "no-session")         # an unknown value keeps the default


class AuditStatus(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.node = an.Node(self.d.name + "/node")
        self.key = Ed25519PrivateKey.generate()
        pub = base64.b64encode(self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
        self.node.enroll("pc-1", pub)
        self.ledger = self.d.name + "/l.jsonl"
        zledger.append(self.ledger, "boot", "root", "pc-1")

    def tearDown(self):
        self.d.cleanup()

    def records(self):
        with open(self.ledger) as f:
            return [json.loads(l) for l in f if l.strip()]

    def alerts(self):
        p = os.path.join(self.d.name, "node", "alerts.jsonl")
        with open(p) as f:
            return [json.loads(l)["event"] for l in f if l.strip()]

    def send(self, st, tamper=False):
        b = {"machine": "pc-1", "chain": "guard", "from": 0, "records": self.records(), "status": st}
        ship.sign(self.key, b)
        if tamper:
            b["status"] = dict(st, services={k: "active" for k in st["services"]})
        return self.node.accept(b)

    def st(self, **kw):
        s = {"t": 0, "kernel": "6.12.113+deb13-amd64", "kernel_newest": "6.12.113+deb13-amd64", "reboot_required": False,
             "services": {k: "active" for k in ship.WATCHED}}
        s.update(kw)
        return s

    def test_status_alerts(self):
        self.assertEqual(self.send(self.st())[0], 200)
        self.assertNotIn("service-down", self.alerts())
        down = self.st(services=dict(self.st()["services"], **{"zenos-guardd": "inactive"}))
        self.assertEqual(self.send(down)[0], 200)
        self.assertEqual(self.alerts().count("service-down"), 1)
        self.send(down)
        self.assertEqual(self.alerts().count("service-down"), 1)            # once, not on every heartbeat
        self.send(self.st())
        self.assertIn("service-back", self.alerts())
        self.send(self.st(kernel="6.12.112+deb13-amd64"))
        self.assertIn("kernel-fix-not-applied", self.alerts())
        self.send(self.st())
        self.assertIn("kernel-fix-applied", self.alerts())

    def test_forged_status_is_flagged_and_the_batch_still_counts(self):
        down = self.st(services=dict(self.st()["services"], **{"zenos-keyd": "failed"}))
        code, ans = self.send(down, tamper=True)
        self.assertEqual(code, 200)                                           # the ledger itself was signed correctly
        self.assertIn("bad-status-signature", self.alerts())
        self.assertNotIn("service-down", self.alerts())

    def test_batch_without_status_still_accepted(self):
        b = {"machine": "pc-1", "chain": "guard", "from": 0, "records": self.records()}
        ship.sign(self.key, b)
        self.assertNotIn("status_sig", b)
        self.assertEqual(self.node.accept(b)[0], 200)

    def test_a_record_that_is_not_an_object_is_refused(self):
        self.assertEqual(self.send(self.st())[0], 200)
        for bad in ([1], ["x"], [None], [[1]]):
            b = {"machine": "pc-1", "chain": "guard", "from": 0, "records": bad}
            ship.sign(self.key, b)
            self.assertEqual(self.node.accept(b)[0], 400, bad)                 # an answer, not a crash

    def test_silence_in_seconds(self):
        self.send(self.st())
        seen = os.path.join(self.d.name, "node", "machines", "pc-1.seen")
        with open(seen, "w") as f:
            f.write(str(time.time() - 120))
        self.node.check_silence(90)
        self.assertIn("machine-silent", self.alerts())



class OpenHolders(unittest.TestCase):
    """the network stays cut while the process that received L4+ plaintext, or anything it started, is alive; the
    user's own flag file cannot lift it"""
    def test_holders_and_their_children(self):
        import subprocess, importlib
        with tempfile.TemporaryDirectory() as d:
            os.environ["HOME"] = d
            import zenos_netsentinel as ns
            importlib.reload(ns)
            path = os.path.join(d, "holders.json")
            parent = subprocess.Popen([sys.executable, "-c",
                                       "import subprocess,sys,time;subprocess.Popen(['sleep','30']);time.sleep(1.5)"])
            time.sleep(0.5)
            start = open("/proc/%d/stat" % parent.pid).read().rsplit(")", 1)[1].split()[19]
            with open(path, "w") as f:
                json.dump([{"pid": parent.pid, "start": start, "level": 4}], f)
            self.assertTrue(ns.holders_alive(path))                      # the holder and its child are recorded
            kids = [h for h in json.load(open(path)) if h["pid"] != parent.pid]
            self.assertTrue(kids)
            parent.wait()
            self.assertTrue(ns.holders_alive(path))                      # the holder exited, its child still holds
            for k in kids:
                os.kill(k["pid"], 9)
            time.sleep(0.3)
            self.assertFalse(ns.holders_alive(path))
            with open(path, "w") as f:
                json.dump([{"pid": os.getpid(), "start": "0", "level": 4}], f)   # a reused pid is not the holder
            self.assertFalse(ns.holders_alive(path))
            with open(path, "w") as f:
                json.dump([{"pid": os.getpid(), "start": open("/proc/self/stat").read().rsplit(")", 1)[1].split()[19], "level": 3}], f)
            self.assertFalse(ns.holders_alive(path))                    # L3 does not cut the network


if __name__ == "__main__":
    unittest.main()
