"""zenos-launchd starts the browser and the messenger; zenos-credd serves only a process it started
(system/sbin/zenos_launchd.py, system/sbin/zenos_credd.py)."""
import json, os, subprocess, sys, tempfile, time, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "../system/sbin"))
sys.path.insert(0, os.path.join(HERE, "../system/lib"))
import zenos_launchd as L                                               # noqa: E402


class Launchd(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="zenos-launch-")
        L.LAUNCHED = L.Path(self.d) / "launched.json"

    def test_requests_are_held_to_their_shapes(self):
        from unittest import mock
        self.enterContext(mock.patch.object(L, "trusted", lambda p: True))   # the install check is not tested here
        ok, why = L.command("browser", ["https://example.org/"], {"DISPLAY": ":0", "LD_PRELOAD": "/tmp/x.so",
                                                                  "PYTHONPATH": "/tmp", "LANG": "ja_JP.UTF-8"})
        argv, env = ok
        self.assertEqual(argv[:2], [L.PY, "-I"])
        self.assertEqual(env.get("DISPLAY"), ":0")
        self.assertNotIn("LD_PRELOAD", env)                             # nothing that loads other code
        self.assertNotIn("PYTHONPATH", env)
        self.assertIsNone(L.command("browser", ["--remote-debugging-port=9"], {})[0])
        self.assertIsNone(L.command("messenger", ["zenos", "80"], {})[0])
        self.assertIsNone(L.command("messenger", ["../x", "8096"], {})[0])
        self.assertIsNone(L.command("shell", [], {})[0])
        argv, env = L.command("messenger", ["zenos", "8096"], {"NODE_OPTIONS": "--require=/tmp/evil.js"})[0]
        self.assertNotIn("NODE_OPTIONS", env)
        self.assertIsNone(L.command("browser", ["x"], {"DISPLAY": ":0\nLD_PRELOAD=/tmp/x"})[0][1].get("DISPLAY"))

    def test_only_a_persons_account(self):
        self.assertFalse(L.launch({"op": "launch", "program": "browser", "args": []}, 0)["ok"])
        self.assertFalse(L.launch({"op": "launch", "program": "browser", "args": []}, 65534)["ok"])

    def test_the_vault_serves_only_a_recorded_process(self):
        import zenos_credd as C
        p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(5)"])
        try:
            time.sleep(0.2)
            L.record(p.pid, os.getuid(), "browser")
            path = str(L.LAUNCHED)
            self.assertTrue(C.launched(p.pid, os.getuid(), "browser", path))
            self.assertFalse(C.launched(p.pid, os.getuid(), "messenger", path))     # another program
            self.assertFalse(C.launched(p.pid, os.getuid() + 1, "browser", path))   # another person
            self.assertFalse(C.launched(os.getpid(), os.getuid(), "browser", path)) # not started by the launcher
            recs = json.loads(L.LAUNCHED.read_text())
            recs[0]["start"] = "0"                                                  # a reused pid is not it
            L.LAUNCHED.write_text(json.dumps(recs))
            self.assertFalse(C.launched(p.pid, os.getuid(), "browser", path))
        finally:
            p.kill()
            p.wait()
        # with zenos-launchd installed, a process with the right name but no record is refused
        unit = os.path.join(self.d, "zenos-launchd.service")
        open(unit, "w").close()
        from unittest import mock
        with mock.patch.object(C, "LAUNCH_UNITS", [unit]), mock.patch.object(C, "LAUNCHED", str(L.LAUNCHED)), \
                mock.patch.object(C, "caller", lambda pid: "browser"):
            r = C.handle({"op": "accounts", "origin": "https://bank.example"}, os.getuid(), os.getpid())
        self.assertFalse(r["ok"])


if __name__ == "__main__":
    unittest.main()
