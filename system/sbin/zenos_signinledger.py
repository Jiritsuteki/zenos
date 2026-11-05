#!/usr/bin/env python3
"""ZENOS: sign-ins to the PC in the tamper-evident ledger (root service).

Writes to /var/log/zenos/access-ledger.jsonl, the same hash-chained ledger the approvals and file openings go to
(shipped to the audit nodes by zenos-auditship):

  sign-in          a person's session began: who, how (login screen, text console, ssh), the seat or terminal,
                   and for a remote session the machine it came from
  sign-out         that session ended (with how long it lasted)
  sign-in-failed   a wrong password: who was tried, through which program (login screen, lock screen, sudo, su,
                   ssh), and from where when it came over the network
  screen-locked    the session's screen was locked
  screen-unlocked  and unlocked again (by the person's password on the lock screen)

Where it comes from: the system journal. systemd-logind writes a line when a session starts and ends, PAM writes a
line for each wrong password, and the lock state is the session's LockedHint that the lock screen sets. Nothing is
read from the people's files and nothing leaves the PC except through the ledger's own shipping.

The journal position is kept in /var/lib/zenos/signin-ledger.cursor, so a restart of this service (or of the PC)
does not skip or repeat lines. The login screen's own session (the greeter) and the background sessions systemd
keeps for each user are not sign-ins and are left out.

What this does not see: a person who reaches the PC without a session (a program already running as them), and
anything done while the journal itself is stopped. The ledger shows the gap: no line, not a false one.
"""
import json, os, re, select, socket, subprocess, sys, time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "lib", "zenos"))
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "lib"))
import zledger                                       # noqa: E402  (no ledger, no service: it fails loudly)

LEDGER = os.environ.get("ZENOS_SIGNIN_LEDGER", "/var/log/zenos/access-ledger.jsonl")
CURSOR = os.environ.get("ZENOS_SIGNIN_CURSOR", "/var/lib/zenos/signin-ledger.cursor")
SESSION_START = "8d45620c1a4348dbb17410da57c60c66"      # systemd's message id: "New session %s of user %s."
SESSION_STOP = "3354939424b4456d9802ca8333ed424a"       # "Removed session %s."
AUTH_FAIL = re.compile(r"pam_\w+\(([\w.-]+):auth\): authentication failure;(.*)$")
NOT_PEOPLE = {"greeter", "lock-screen", "manager", "manager-early", "background", "background-light"}
HOW = {"sddm": "login screen", "sddm-autologin": "login screen (automatic)", "login": "text console",
       "sshd": "ssh", "kde": "lock screen", "kscreensaver": "lock screen", "sudo": "sudo", "su": "su",
       "su-l": "su", "polkit-1": "administrator prompt", "xrdp-sesman": "remote desktop", "gdm-password":
       "login screen"}


def device():
    try:
        return socket.gethostname()
    except OSError:
        return "pc"


def show_session(sid):
    """the session's properties from logind (empty when it is gone)"""
    try:
        out = subprocess.run(["loginctl", "show-session", str(sid), "-p", "Name", "-p", "Service", "-p", "Type",
                              "-p", "Class", "-p", "Remote", "-p", "RemoteHost", "-p", "RemoteUser", "-p", "TTY",
                              "-p", "Seat", "-p", "LockedHint"],
                             capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    return dict(l.split("=", 1) for l in out.splitlines() if "=" in l)


def _kv(text):
    """'logname= uid=0 euid=0 tty=:0 ruser= rhost=  user=tanaka' -> {...} (empty values left out)"""
    out = {}
    for part in text.split():
        if "=" in part:
            k, v = part.split("=", 1)
            if v:
                out[k] = v
    return out


class Recorder:
    """turns journal entries and lock states into ledger lines; `write(event, actor, **fields)` does the writing"""

    def __init__(self, write, show=show_session, now=time.time):
        self.write, self.show, self.now = write, show, now
        self.sessions = {}            # session id -> {"user", "since", "locked"}

    def entry(self, e):
        mid = e.get("MESSAGE_ID")
        if mid == SESSION_START:
            return self._start(e)
        if mid == SESSION_STOP:
            return self._stop(e)
        m = AUTH_FAIL.search(str(e.get("MESSAGE", "")))
        if m:
            kv = _kv(m.group(2))
            service = m.group(1)
            f = {"how": HOW.get(service, service), "service": service}
            if kv.get("rhost"):
                f["from"] = kv["rhost"]
            if kv.get("tty"):
                f["terminal"] = kv["tty"]
            self.write("sign-in-failed", kv.get("user", "(unknown)"), **f)
            return "sign-in-failed"
        return None

    def _start(self, e):
        sid, user = str(e.get("SESSION_ID", "")), str(e.get("USER_ID", ""))
        p = self.show(sid)
        if not sid or p.get("Class") in NOT_PEOPLE or user in ("sddm", "gdm", "lightdm"):
            return None
        service = p.get("Service", "")
        f = {"session": sid, "how": HOW.get(service, service or "unknown"), "service": service}
        if p.get("Type"):
            f["type"] = p["Type"]
        if p.get("Seat"):
            f["seat"] = p["Seat"]
        if p.get("TTY"):
            f["terminal"] = p["TTY"]
        if p.get("Remote") == "yes":
            f["remote"] = True
            if p.get("RemoteHost"):
                f["from"] = p["RemoteHost"]
        self.sessions[sid] = {"user": user, "since": self.now(), "locked": p.get("LockedHint") == "yes"}
        self.write("sign-in", user, **f)
        return "sign-in"

    def _stop(self, e):
        sid = str(e.get("SESSION_ID", ""))
        s = self.sessions.pop(sid, None)
        if s is None:
            return None               # a session that was not a sign-in (greeter, background) or began before us
        self.write("sign-out", s["user"], session=sid, minutes=round((self.now() - s["since"]) / 60, 1))
        return "sign-out"

    def poll_locks(self):
        """compare each session's lock state with the last one seen; returns the events written"""
        out = []
        for sid, s in list(self.sessions.items()):
            p = self.show(sid)
            if not p:
                continue
            locked = p.get("LockedHint") == "yes"
            if locked != s["locked"]:
                s["locked"] = locked
                ev = "screen-locked" if locked else "screen-unlocked"
                self.write(ev, s["user"], session=sid)
                out.append(ev)
        return out

    def adopt(self, sid, user):
        """a session already open when the service starts: watched from now on, no sign-in line made up for it"""
        p = self.show(sid)
        if p and p.get("Class") not in NOT_PEOPLE:
            self.sessions[str(sid)] = {"user": user, "since": self.now(), "locked": p.get("LockedHint") == "yes"}


def ledger_writer(event, actor, **fields):
    zledger.append(LEDGER, event, actor, device(), **fields)


def open_sessions():
    try:
        out = subprocess.run(["loginctl", "list-sessions", "--no-legend"], capture_output=True, text=True,
                             timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    rows = []
    for l in out.splitlines():
        f = l.split()
        if len(f) >= 3:
            rows.append((f[0], f[2]))
    return rows


def main():
    rec = Recorder(ledger_writer)
    for sid, user in open_sessions():
        rec.adopt(sid, user)
    cmd = ["journalctl", "-f", "-o", "json"]
    try:
        cur = open(CURSOR).read().strip()
    except OSError:
        cur = ""
    cmd += ["--after-cursor", cur, "--no-tail"] if cur else ["-n", "0"]
    j = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    fd, buf, last_poll = j.stdout.fileno(), b"", 0.0
    while True:
        ready, _, _ = select.select([fd], [], [], 2)
        if ready:
            chunk = os.read(fd, 65536)
            if not chunk:
                sys.exit("journalctl stopped")
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                handle(rec, line)
        if time.time() - last_poll >= 2:
            last_poll = time.time()
            rec.poll_locks()


def handle(rec, line):
    try:
        e = json.loads(line)
    except ValueError:
        return
    try:
        rec.entry(e)
    except Exception as ex:                          # one odd line never stops the record
        print("signin-ledger:", ex, file=sys.stderr)
    if e.get("__CURSOR"):
        try:
            os.makedirs(os.path.dirname(CURSOR), exist_ok=True)
            tmp = CURSOR + ".tmp"
            with open(tmp, "w") as f:
                f.write(e["__CURSOR"])
            os.replace(tmp, CURSOR)
        except OSError:
            pass

if __name__ == "__main__":
    main()
