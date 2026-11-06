"""zenos-guardd works as root in the user's folders: it never follows a link or blocks on a pipe there, keeps the
use count of a pre-filed operation itself, and lets only root-owned programs keep running during a stop
(system/sbin/zenos_guardd.py)."""
import json, os, subprocess, sys, tempfile, time, unittest
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "../system/sbin"))
sys.path.insert(0, os.path.join(HERE, "../system/lib"))
import zenos_guardd as G                                                    # noqa: E402


class GuardPaths(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="zenos-guard-"))
        G.USB = self.d / "USB Drive"
        G.USB.mkdir()
        G.QUAR = self.d / "quarantine"
        G.DESK = self.d

    def test_a_link_or_pipe_in_the_user_folder_is_not_followed(self):
        secret = self.d / "root-only.txt"
        secret.write_text("root's file")
        (self.d / "plan.json").symlink_to(secret)
        with self.assertRaises(OSError):
            G.read_user_json(self.d / "plan.json")
        os.mkfifo(self.d / "pipe.json")
        with self.assertRaises(ValueError):
            G.read_user_json(self.d / "pipe.json")                           # returns at once, never blocks
        os.mkfifo(G.USB / "x.zen")
        t = time.time()
        self.assertEqual(G.level_of(G.USB / "x.zen"), 1)
        self.assertLess(time.time() - t, 2)

    def test_every_file_in_the_exit_counts_whatever_its_name_or_folder(self):
        halts = []
        from unittest import mock
        G.HALT, G.SYSD = self.d / "halt.json", self.d / "sys3"
        G.PLAN_USE, G.DATA = G.SYSD / "pu.json", self.d / "data3"
        sealed = G.Z.MAGIC + b'{"level": 5}\n' + b"sig\nct"
        (G.USB / "sub").mkdir()
        with mock.patch.object(G, "halt", lambda rule, paths, level, culprit=None: halts.append((rule, level))):
            for name, data in (("x.zen.tmp", sealed), (".hidden", sealed), ("sub/y.zen", sealed)):
                halts.clear(); G.xfers.clear()
                (G.USB / name).write_bytes(data)
                G.on_arrival(str(G.USB / name), 4242)
                self.assertEqual(halts, [("exfiltration", 5)], name)
            halts.clear(); G.xfers.clear()
            for i in range(G.BULK_XFER_N):
                f = G.USB / "sub" / f"f{i}.part"
                f.write_text("plain")
                G.on_arrival(str(f), 4242)
            self.assertEqual(halts[-1][0], "bulk-transfer")
        self.assertTrue(G.in_security(G.DESK / "Red · L4" / "deep" / "a.zen") if "Red · L4" in G.Z.FOLDERS else True)

    def test_quarantine_moves_files_not_links(self):
        secret = self.d / "root-only.txt"
        secret.write_text("root's file")
        (G.USB / "link.txt").symlink_to(secret)
        (G.USB / "real.txt").write_text("copied to the drive")
        moved = G.quarantine([G.USB / "link.txt", G.USB / "real.txt"], "h1")
        self.assertEqual(moved, ["real.txt"])
        self.assertTrue((G.USB / "link.txt").is_symlink())
        self.assertEqual(secret.read_text(), "root's file")

    def test_a_command_line_does_not_exempt_a_program_from_the_stop(self):
        script = self.d / "msg" / "client.js"
        script.parent.mkdir()
        script.write_text("setTimeout(()=>{}, 5000)")
        p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(5)", "/usr/share/zenos/msg/client.js"])
        try:
            time.sleep(0.2)
            self.assertFalse(G.exempt(p.pid, "Xorg"))                       # the name is the program's own to choose
            self.assertFalse(G.exempt(p.pid, "python3"))
        finally:
            p.kill()
        self.assertFalse(G.trusted(script))                                  # a file the user can change
        # code given with -c, ending in a comment that "resolves" to an exempt script, is not that script
        from unittest import mock
        code = "import time; time.sleep(5)  #/../../../../../../../.." + os.path.realpath(os.path.join(HERE, "../core/bin/approval_server.py"))
        p = subprocess.Popen([sys.executable, "-c", code])
        try:
            time.sleep(0.2)
            with mock.patch.object(G, "trusted", lambda path: True):
                self.assertFalse(G.exempt(p.pid, "python3"))
        finally:
            p.kill()

    def test_one_signature_counts_once_and_never_for_the_requester(self):
        G.SYSD = self.d / "sys2"
        G.PLAN_USE = G.SYSD / "plan-use.json"
        G.DATA = self.d / "data2"
        (G.DATA / "plans").mkdir(parents=True)
        G.USER = "tester"
        core = {"id": "r2", "kind": "plan", "requester": "tester", "level": 5, "reason": "x",
                "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "scope": {"rule": "usb-export", "max_files": 1, "minutes": 5}}
        import base64, hashlib
        digest = hashlib.sha256(json.dumps(core, sort_keys=True, ensure_ascii=False).encode()).digest()
        g = {"request": "r2", "expires": time.time() + 999, "digest": base64.b64encode(digest).decode(), "core": core,
             "approvals": [{"approver": "sato"}, {"approver": "x/sato"}, {"approver": "y/sato"}, {"approver": "tester"}]}
        (G.DATA / "plans" / "r2.json").write_text(json.dumps(g))
        from unittest import mock
        with mock.patch.object(G.zapprove, "check", lambda *a: (True, "", {})):
            self.assertFalse(G.plan_allows("usb-export", 5))               # L5 needs 3 distinct officers

    def test_plan_use_is_counted_by_the_guard(self):
        G.SYSD = self.d / "sys"
        G.PLAN_USE = G.SYSD / "plan-use.json"
        G.DATA = self.d / "data"
        (G.DATA / "plans").mkdir(parents=True)
        G.USER = "tester"
        core = {"id": "r1", "kind": "plan", "requester": "tester", "level": 2, "reason": "x",
                "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "scope": {"rule": "usb-export", "max_files": 1, "minutes": 5}}
        import base64, hashlib
        digest = hashlib.sha256(json.dumps(core, sort_keys=True, ensure_ascii=False).encode()).digest()
        g = {"request": "r1", "expires": time.time() + 999999, "used": 0, "digest": base64.b64encode(digest).decode(),
             "approvals": [{"approver": "a"}, {"approver": "b"}], "core": core}
        (G.DATA / "plans" / "r1.json").write_text(json.dumps(g))
        from unittest import mock                                             # the signatures are not what is tested
        self.enterContext(mock.patch.object(G.zapprove, "check", lambda *a: (True, "", {})))
        self.assertTrue(G.plan_allows("usb-export", 2))
        g["used"] = 0                                                         # the user resets the count in the file
        (G.DATA / "plans" / "r1.json").write_text(json.dumps(g))
        self.assertFalse(G.plan_allows("usb-export", 2))                      # the guard's own count stands
        self.assertEqual(json.loads((G.DATA / "plans" / "r1.json").read_text())["used"], 0)   # never written as root


class DeskLevel(unittest.TestCase):
    """the apps' copy check: a level folder is the one on the Desktop, not any folder with its name in the path"""
    def test_only_the_desktop_level_folder_counts(self):
        import zformat
        with tempfile.TemporaryDirectory() as t:
            desk = os.path.join(t, "Desktop")
            for d in ("Desktop/Red · L4/sub", "Documents/Red · L4", "Desktop/x/Black · L5", "Red · L4 trap"):
                os.makedirs(os.path.join(t, d))
            os.symlink(os.path.join(t, "Documents"), os.path.join(desk, "Black · L5"))
            L = lambda d: zformat.desk_level(os.path.join(t, d), desk)
            self.assertEqual(L("Desktop/Red · L4"), 4)
            self.assertEqual(L("Desktop/Red · L4/sub"), 4)
            self.assertEqual(L("Documents/Red · L4"), 1)               # the name elsewhere
            self.assertEqual(L("Desktop/x/Black · L5"), 1)             # deeper on the Desktop, not the level folder
            self.assertEqual(L("Red · L4 trap"), 1)
            self.assertEqual(L("Desktop/Black · L5"), 1)               # a link named like it leads elsewhere
            self.assertEqual(L("Desktop"), 1)


if __name__ == "__main__":
    unittest.main()
