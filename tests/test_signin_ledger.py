"""Sign-ins to the PC in the ledger (zenos_signinledger.py): journal lines as systemd-logind and PAM write them on
Debian 13, turned into sign-in, sign-out, failed password and lock lines in the hash-chained ledger."""
import json, sys, tempfile, unittest
from unittest import mock
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path[0:0] = [str(REPO / "system" / "lib"), str(REPO / "system" / "sbin")]
import zledger, zenos_signinledger as S                     # noqa: E402


class Logind:
    def __init__(self):
        self.s = {}

    def __call__(self, sid):
        return dict(self.s.get(str(sid), {}))


def start(sid, user):
    return {"MESSAGE_ID": S.SESSION_START, "SESSION_ID": sid, "USER_ID": user,
            "MESSAGE": f"New session {sid} of user {user}.", "SYSLOG_IDENTIFIER": "systemd-logind",
            "_UID": "0", "_COMM": "systemd-logind"}


def stop(sid):
    return {"MESSAGE_ID": S.SESSION_STOP, "SESSION_ID": sid, "MESSAGE": f"Removed session {sid}.", "_UID": "0",
            "_COMM": "systemd-logind"}


class SigninLedger(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="zenos-signin-"))
        self.ledger = str(self.tmp / "access-ledger.jsonl")
        self.t = [1000.0]
        self.logind = Logind()
        self.rec = S.Recorder(lambda ev, actor, **f: zledger.append(self.ledger, ev, actor, "desk-0423", **f),
                              self.logind, lambda: self.t[0])

    def lines(self):
        return [json.loads(l) for l in Path(self.ledger).read_text().splitlines()]

    def test_a_sign_in_and_out_at_the_login_screen(self):
        self.logind.s["3"] = {"Class": "user", "Service": "sddm", "Type": "wayland", "Seat": "seat0", "TTY": "tty2",
                              "Remote": "no", "LockedHint": "no"}
        self.assertEqual(self.rec.entry(start("3", "tanaka")), "sign-in")
        self.t[0] += 3600
        self.assertEqual(self.rec.entry(stop("3")), "sign-out")
        a, b = self.lines()
        self.assertEqual((a["event"], a["actor"], a["how"], a["seat"], a["session"]),
                         ("sign-in", "tanaka", "login screen", "seat0", "3"))
        self.assertNotIn("remote", a)
        self.assertEqual((b["event"], b["actor"], b["minutes"]), ("sign-out", "tanaka", 60.0))
        self.assertEqual(zledger.verify(self.ledger)[0], True)

    def test_a_remote_sign_in_names_where_it_came_from(self):
        self.logind.s["7"] = {"Class": "user", "Service": "sshd", "Type": "tty", "TTY": "pts/0", "Remote": "yes",
                              "RemoteHost": "10.1.2.3"}
        self.rec.entry(start("7", "sato"))
        (a,) = self.lines()
        self.assertEqual((a["how"], a["remote"], a["from"]), ("ssh", True, "10.1.2.3"))

    def test_the_login_screen_and_background_sessions_are_not_sign_ins(self):
        self.logind.s["c1"] = {"Class": "greeter", "Service": "sddm-greeter"}
        self.logind.s["4"] = {"Class": "manager", "Service": "systemd-user"}
        self.assertIsNone(self.rec.entry(start("c1", "sddm")))
        self.assertIsNone(self.rec.entry(start("4", "tanaka")))
        self.assertIsNone(self.rec.entry(stop("c1")))
        self.assertFalse(Path(self.ledger).exists())

    def test_wrong_passwords_are_recorded(self):
        msgs = ["pam_unix(sddm:auth): authentication failure; logname= uid=0 euid=0 tty=:0 ruser= rhost=  user=tanaka",
                "pam_unix(kde:auth): authentication failure; logname= uid=1000 euid=1000 tty= ruser= rhost=  user=tanaka",
                "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.9  user=root",
                "pam_unix(sudo:auth): authentication failure; logname=tanaka uid=1000 euid=0 tty=/dev/pts/1 ruser=tanaka rhost=  user=tanaka"]

        with mock.patch.object(S, "_root_owned", lambda p: True):
            for m in msgs:
                src = {"_UID": "1000", "_EXE": "/usr/lib/x86_64-linux-gnu/libexec/kscreenlocker_greet"} if "(kde:" in m else {"_UID": "0"}
                self.assertEqual(self.rec.entry(dict(src, MESSAGE=m)), "sign-in-failed")
        got = [(l["actor"], l["how"], l.get("from")) for l in self.lines()]
        self.assertEqual(got, [("tanaka", "login screen", None), ("tanaka", "lock screen", None),
                               ("root", "ssh", "203.0.113.9"), ("tanaka", "sudo", None)])
        # the summary lines sudo and sshd add on top are not counted twice
        self.assertIsNone(self.rec.entry({"MESSAGE": "Failed password for root from 203.0.113.9 port 22 ssh2", "_UID": "0"}))
        self.assertIsNone(self.rec.entry({"MESSAGE": "tanaka : 1 incorrect password attempt ; TTY=pts/1"}))

    def test_entries_any_account_can_write_are_not_recorded(self):
        """every account can write to the journal and choose MESSAGE_ID and MESSAGE; only journald's own fields count"""
        self.logind.s["3"] = {"Class": "user", "Service": "sddm", "LockedHint": "no"}
        self.rec.entry(start("3", "tanaka"))
        forged = [dict(stop("3"), _UID="1000", _COMM="systemd-logind"),            # a fake sign-out of a real session
                  dict(start("77", "suzuki"), _UID="1000"),
                  dict(start("78", "suzuki"), _COMM="logger"),
                  {"MESSAGE": "pam_unix(sshd:auth): authentication failure; rhost=203.0.113.9 user=suzuki", "_UID": "1000"}]
        for e in forged:
            self.assertIsNone(self.rec.entry(e))
        self.assertEqual([l["event"] for l in self.lines()], ["sign-in"])
        self.logind.s["3"]["State"] = "active"                                   # logind still has the session
        self.assertIsNone(self.rec.entry(stop("3")))

    def test_locking_and_unlocking_the_screen(self):
        self.logind.s["3"] = {"Class": "user", "Service": "sddm", "LockedHint": "no"}
        self.rec.entry(start("3", "tanaka"))
        self.assertEqual(self.rec.poll_locks(), [])
        self.logind.s["3"]["LockedHint"] = "yes"
        self.assertEqual(self.rec.poll_locks(), ["screen-locked"])
        self.assertEqual(self.rec.poll_locks(), [])
        self.logind.s["3"]["LockedHint"] = "no"
        self.assertEqual(self.rec.poll_locks(), ["screen-unlocked"])
        self.assertEqual([l["event"] for l in self.lines()], ["sign-in", "screen-locked", "screen-unlocked"])

    def test_a_session_open_before_the_service_started_is_watched_without_a_made_up_sign_in(self):
        self.logind.s["2"] = {"Class": "user", "Service": "sddm", "LockedHint": "no"}
        self.rec.adopt("2", "tanaka")
        self.assertFalse(Path(self.ledger).exists())
        self.logind.s["2"]["LockedHint"] = "yes"
        self.assertEqual(self.rec.poll_locks(), ["screen-locked"])
        self.assertEqual(self.rec.entry(stop("2")), "sign-out")

    def test_the_cursor_is_kept_so_a_restart_skips_nothing(self):
        old, S.CURSOR = S.CURSOR, str(self.tmp / "cursor")
        self.addCleanup(setattr, S, "CURSOR", old)
        S.handle(self.rec, json.dumps({"MESSAGE": "unrelated", "__CURSOR": "s=abc;i=1"}).encode())
        S.handle(self.rec, b"not json")
        self.assertEqual(Path(S.CURSOR).read_text(), "s=abc;i=1")


if __name__ == "__main__":
    unittest.main()
