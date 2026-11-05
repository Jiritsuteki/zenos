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


if __name__ == "__main__":
    unittest.main()
