#!/usr/bin/env python3
"""ZENOS guard (root): watches the security folders and the external exit, and enforces the stop.

Why root: a watcher that runs as the user can be stopped or edited by the user, and so can its state. Here the
detection, the stop state (/var/lib/zenos/halt.json), the release requests, the quarantine and the officers'
public keys (/etc/zenos/approvers) all belong to root. The user can read the state but cannot lift a stop.

Detection   fanotify reports every open of a protected file and every finished write to the exit, together with
            the process id (inotify, used only for moves into the exit, cannot say who did it).
Rules       exfiltration   a protected file (L2+) reaches the USB Drive
            bulk-transfer  5 or more files reach the USB Drive within 30 seconds
            bulk-read      6 or more different protected files are opened within 20 seconds
Stop        every process of the desktop user is frozen (SIGSTOP), except the display server and the messenger
            (it carries the release request to the officers); anything new the user starts is frozen within a
            second. Files that reached the exit are moved to root's quarantine. A full-screen notice runs as root.
Release     the officers' signatures arrive over /run/zenos/guardd.sock and are verified against the
            administrator-installed public keys; with enough of them the processes involved are killed (the
            operation is cancelled, not resumed) and everything else is thawed.
Pre-filed operations approved in advance are honoured: the event is recorded instead of stopping the PC.
"""
import base64, stat, ctypes, ctypes.util, hashlib, json, os, pwd, select, signal, socket, struct, subprocess, sys
import threading, time
from collections import deque
from pathlib import Path

# the ZENOS library is ../lib/zenos beside this program (/usr/lib/zenos, root-owned)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "lib", "zenos"))
import zconf
try:
    import zledger
except Exception:
    zledger = None
import zformat as Z                    # file format, levels and the request digest, shared with the desktop side
import zdecide                         # the proven decisions (formal/): answers, release, officers a release needs
import zapprove                        # an officer's signature: a browser key, or a passkey in the phone's secure chip
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SYSD = Path("/var/lib/zenos")
HALT = SYSD / "halt.json"
REQ = SYSD / "requests"
QUAR = SYSD / "quarantine"
PUB = Path("/etc/zenos/approvers")
SOCK = "/run/zenos/guardd.sock"
LOG = Path("/var/log/zenos/guard.jsonl")
LEDGER = "/var/log/zenos/access-ledger.jsonl"
BULK_READ_N, BULK_READ_SEC = 6, 20
BULK_XFER_N, BULK_XFER_SEC = 5, 30
RULE_TEXT = {"exfiltration": "a protected file was copied to the USB Drive",
             "bulk-transfer": "many files were copied to the USB Drive at once",
             "bulk-read": "many protected files were opened at once"}
# the display path keeps running so the stop notice can be seen: X server and the compositing window manager
# (when KWin composites, nothing new reaches the screen while it is frozen)
DISPLAY_SERVERS = {"Xorg", "Xvnc", "Xtigervnc", "Xwayland", "X", "kwin_x11", "kwin_wayland", "kscreenlocker_greet"}
ME = os.getpid()
lock = threading.RLock()
reads, xfers, recent_write = deque(), deque(), {}
lock_proc = None

USER = PW = HOME = DATA = DESK = USB = None      # set by init_user() once the desktop user exists


def init_user():
    """wait until the desktop user exists and has logged in once (their security folders are made at login)"""
    global USER, PW, HOME, DATA, DESK, USB
    while True:
        try:
            USER = zconf.user()
            PW = pwd.getpwnam(USER)
            HOME = Path(PW.pw_dir)
            DATA = Path(zconf.data(USER))
            DESK = desktop_dir()
            USB = DESK / "USB Drive"
            if USB.is_dir():
                return
        except KeyError:
            pass
        time.sleep(5)


def desktop_dir():
    try:
        for line in open(HOME / ".config/user-dirs.dirs"):
            if line.startswith("XDG_DESKTOP_DIR="):
                return Path(line.split("=", 1)[1].strip().strip('"').replace("$HOME", str(HOME)))
    except OSError:
        pass
    return HOME / "Desktop"


def log(**kw):
    kw = {"t": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **kw}
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG, "a") as f:
        f.write(json.dumps(kw, ensure_ascii=False) + "\n")
    if zledger is not None:
        try:
            zledger.append(LEDGER, kw.get("event", "guard"), "guardd", "endpoint", **{k: v for k, v in kw.items() if k not in ("t", "event")})
        except Exception:
            pass
    print(json.dumps(kw, ensure_ascii=False), flush=True)


def write_json(p, obj, mode=0o644):
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name("." + p.name + ".tmp")
    tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=1))
    os.chmod(tmp, mode)
    os.replace(tmp, p)


def halted():
    try:
        h = json.loads(HALT.read_text())
        return h if h.get("status") == "halted" else None
    except Exception:
        return None


# ---------------- levels ----------------
def folder_level(p):
    p = Path(p)
    if p.parent.parent == DESK and p.parent.name in Z.FOLDERS:
        return Z.FOLDERS[p.parent.name][0]
    return 1


def level_of(p):
    """the level written in a sealed file's header (read by the guard itself; its own opens are ignored)"""
    p = Path(p)
    try:
        if p.suffix == ".zen":
            fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)   # a pipe named *.zen must not stop the guard
            try:
                head = os.read(fd, 4096) if stat.S_ISREG(os.fstat(fd).st_mode) else b""
            finally:
                os.close(fd)
            if head.startswith(Z.MAGIC):
                return int(json.loads(head[len(Z.MAGIC):].split(b"\n", 1)[0])["level"])
    except Exception:
        pass
    return folder_level(p)


def in_security(p):
    p = Path(p)
    return p.parent.parent == DESK and p.parent.name in Z.FOLDERS


# ---------------- fanotify ----------------
FAN_CLASS_NOTIF, FAN_CLOEXEC, FAN_NONBLOCK = 0x0, 0x1, 0x2
FAN_MARK_ADD = 0x1
FAN_OPEN, FAN_CLOSE_WRITE, FAN_EVENT_ON_CHILD = 0x20, 0x8, 0x08000000
AT_FDCWD = -100
_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
META = struct.Struct("IBBHQii")      # event_len, vers, reserved, metadata_len, mask, fd, pid


def fan_open(paths):
    fd = _libc.fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC, os.O_RDONLY | os.O_LARGEFILE)
    if fd < 0:
        raise OSError(ctypes.get_errno(), "fanotify_init")
    for p in paths:
        r = _libc.fanotify_mark(fd, FAN_MARK_ADD, ctypes.c_uint64(FAN_OPEN | FAN_CLOSE_WRITE | FAN_EVENT_ON_CHILD),
                                AT_FDCWD, os.fsencode(str(p)))
        if r < 0:
            raise OSError(ctypes.get_errno(), "fanotify_mark " + str(p))
    return fd


def fan_events(fd):
    buf = os.read(fd, 65536)
    off = 0
    while off + META.size <= len(buf):
        ev_len, vers, _, meta_len, mask, efd, pid = META.unpack_from(buf, off)
        if ev_len == 0:
            break
        path = None
        if efd >= 0:
            try:
                path = os.readlink(f"/proc/self/fd/{efd}")
            except OSError:
                pass
            os.close(efd)
        yield mask, pid, path
        off += ev_len


# ---------------- the user's processes ----------------
def user_procs():
    out = []
    for d in Path("/proc").iterdir():
        if not d.name.isdigit():
            continue
        try:
            if d.stat().st_uid != PW.pw_uid:
                continue
            comm = (d / "comm").read_text().strip()
            cmd = (d / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="ignore").strip()
            out.append((int(d.name), comm, cmd))
        except OSError:
            continue
    return out


EXEMPT_SCRIPTS = ("msg/relay.js", "msg/client.js", "approval_server.py", "zenos_lock.py")
INTERPRETERS = ("node", "nodejs", "python3")


def trusted(path):
    """a file only root can change: it and every folder above it owned by root and not writable by anyone else"""
    try:
        p = os.path.realpath(path)
        while True:
            st = os.lstat(p)
            if st.st_uid != 0 or st.st_mode & 0o022:
                return False
            if p == "/":
                return True
            p = os.path.dirname(p)
    except OSError:
        return False


def exempt(pid, comm):
    """Only the display path and ZENOS's own carriers of the release request keep running. The process name and its
    command line are the user's to choose, so they decide nothing alone: the program the kernel runs must be one only
    root can change, and for a script, the script file too (the messenger carries the request to the officers; the
    approval page is how they answer; the lock screen shows the stop)."""
    try:
        exe = os.readlink(f"/proc/{pid}/exe")
        argv = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
    except OSError:
        return False
    if exe.endswith(" (deleted)") or not trusted(exe):
        return False
    base = os.path.basename(exe)
    if comm in DISPLAY_SERVERS and base in DISPLAY_SERVERS:
        return True
    if not (base in INTERPRETERS or base.startswith("python3.")):
        return False
    script = next((a.decode(errors="ignore") for a in argv[1:] if a and not a.startswith(b"-")), "")
    if not script.startswith("/"):
        try:
            script = os.path.join(os.readlink(f"/proc/{pid}/cwd"), script)
        except OSError:
            return False
    real = os.path.realpath(script)
    return any(real.endswith("/" + x) for x in EXEMPT_SCRIPTS) and trusted(real)


def holders(paths):
    roots = [str(p) for p in paths] + [str(USB)] + [str(DESK / n) for n in Z.FOLDERS]
    out = []
    for pid, comm, cmd in user_procs():
        try:
            d = Path(f"/proc/{pid}")
            hit = any(any(os.readlink(fd).startswith(r) for r in roots) for fd in (d / "fd").iterdir())
            if not hit:                                    # a script working inside the folder (its current directory)
                cwd = os.readlink(d / "cwd")
                hit = any(cwd.startswith(r) for r in roots)
            if hit:
                out.append({"pid": pid, "comm": comm, "cmd": cmd[:120]})
        except OSError:
            continue
    return out


def freeze_all():
    """stop every non-exempt process of the user; returns the pids stopped now"""
    stopped = []
    for pid, comm, cmd in user_procs():
        if exempt(pid, comm):
            continue
        try:
            st = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
            if st != "T":
                os.kill(pid, signal.SIGSTOP)
                stopped.append(pid)
        except OSError:
            pass
    return stopped


def thaw_all():
    for pid, comm, cmd in user_procs():
        try:
            os.kill(pid, signal.SIGCONT)
        except OSError:
            pass


def session_env():
    """DISPLAY and XAUTHORITY of the user's graphical session, taken from a running session process"""
    for pid, comm, cmd in user_procs():
        if comm not in ("plasmashell", "kwin_x11", "ksmserver", "startplasma-x11", "xfce4-session", "gnome-shell", "Xtigervnc", "Xvnc"):
            continue
        try:
            env = dict(x.split("=", 1) for x in Path(f"/proc/{pid}/environ").read_bytes().decode(errors="ignore").split("\0") if "=" in x)
            if comm in ("Xtigervnc", "Xvnc"):
                disp = next((a for a in cmd.split() if a.startswith(":")), None)
                if disp:
                    return {"DISPLAY": disp, "XAUTHORITY": env.get("XAUTHORITY", str(HOME / ".Xauthority"))}
            if env.get("DISPLAY"):
                return {"DISPLAY": env["DISPLAY"], "XAUTHORITY": env.get("XAUTHORITY", str(HOME / ".Xauthority"))}
        except OSError:
            continue
    return None


def ensure_lock():
    """the stop notice runs as root on the user's screen; if it is closed it comes back"""
    global lock_proc
    if lock_proc is not None and lock_proc.poll() is None:
        return
    env = session_env()
    if not env:
        return
    full = dict(os.environ, HOME="/root", **env)
    lock_proc = subprocess.Popen([sys.executable, "-I", os.path.join(zconf.root(), "bin", "zenos_lock.py")],
                                 env=full, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)


# ---------------- requests and approvals ----------------
def roster():
    return zapprove.roster(PUB)



def pubkey(name):
    return Ed25519PublicKey.from_public_bytes((PUB / f"{os.path.basename(name)}.pub").read_bytes())


def release_required(level):
    return zdecide.release_required(roster(), USER, level)


def new_release(level, rule, files, hid):
    REQ.mkdir(parents=True, exist_ok=True)
    rid = time.strftime("%Y%m%d-%H%M%S") + "-" + os.urandom(2).hex()
    code = f"{int.from_bytes(os.urandom(2), 'big') % 10000:04d}"
    r = {"id": rid, "kind": "release", "requester": USER, "level": level, "label": Z.LABEL[level],
         "reason": RULE_TEXT[rule], "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
         "required": release_required(level), "code": code, "status": "pending", "approvals": [],
         "scope": {"halt": hid, "rule": rule, "files": [Path(f).name for f in files][:20]}}
    write_json(REQ / f"{rid}.json", r)
    return r


def with_sig_ok(r):
    """the request with each approval's signature checked against the enrolled key (the decision trusts this)"""
    digest = Z.request_digest(r)
    out = []
    for a in r.get("approvals", []):
        ok = zapprove.check(PUB, a.get("approver", ""), a.get("sig", ""), digest, r.get("level", 0))[0]
        out.append({"approver": a.get("approver", ""), "sig_ok": ok})
    return dict(r, approvals=out)


def verified(r):
    """(release?, the officers that count), decided by zenos-decide"""
    return zdecide.release(True, with_sig_ok(r), roster())


PLAN_USE = SYSD / "plan-use.json"      # how much of each plan is used, kept by the guard (the plan file is the user's)
PLAN_WAIT = 24 * 3600                   # the longest a plan may wait for its approvals after it was filed


def read_user_json(p, limit=1 << 20):
    """a JSON file in the user's folder, read as root: never through a link, never a pipe or device, size-capped"""
    fd = os.open(str(p), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > limit:
            raise ValueError("not a regular file within bounds")
        return json.loads(os.read(fd, limit + 1))
    finally:
        os.close(fd)


def plan_allows(rule, level, n=1):
    """a pre-filed operation approved by enough officers (signatures checked with the installed public keys). What
    the officers did not sign is not taken from the user's file: the count used is kept here, and the plan ends at
    the earliest of its own "expires", the minutes the officers approved counted from when the guard first saw it,
    and a day after the request was filed."""
    from datetime import datetime
    pdir = DATA / "plans"
    try:
        use = json.loads(PLAN_USE.read_text())
    except Exception:
        use = {}
    for p in sorted(pdir.glob("*.json")) if pdir.is_dir() else []:
        try:
            g = read_user_json(p)
            core, sc = g.get("core", {}), g.get("core", {}).get("scope", {})
            digest = hashlib.sha256(json.dumps(core, sort_keys=True, ensure_ascii=False).encode()).digest()
            if base64.b64decode(g["digest"]) != digest:
                continue
            key = base64.b64encode(digest).decode()
            u = use.get(key) or {"used": 0, "first": time.time()}
            minutes = float(sc.get("minutes", 0))
            created = datetime.strptime(str(core["created"]), "%Y-%m-%dT%H:%M:%S%z").timestamp()
            ends = min(float(g["expires"]), u["first"] + minutes * 60, created + PLAN_WAIT + minutes * 60)
            if (sc.get("rule") != rule or core.get("requester") != USER or level > core.get("level", 0)
                    or time.time() > ends or u["used"] + n > sc.get("max_files", 0)):
                use.setdefault(key, u)
                continue
            ok = set()
            for a in g["approvals"]:
                if zapprove.check(PUB, a.get("approver", ""), a.get("sig", ""), digest, core.get("level", 0))[0]:
                    ok.add(a["approver"])
            if len(ok) >= Z.REQUIRED[core["level"]]:
                u["used"] += n
                use[key] = u
                write_json(PLAN_USE, use, 0o600)
                log(event="anomaly-permitted", rule=rule, level=level, plan=g.get("request"), used=u["used"])
                return True
        except Exception:
            continue
    return False


# ---------------- stop and release ----------------
def quarantine(paths, hid):
    q = QUAR / hid
    q.mkdir(parents=True, exist_ok=True)
    os.chmod(QUAR, 0o700)
    moved = []
    for p in paths:
        p = Path(p)
        try:
            st = os.lstat(p)
        except OSError:
            continue
        if p.parent != USB or not stat.S_ISREG(st.st_mode):     # a link or a pipe is not followed as root
            continue
        try:
            os.replace(p, q / p.name)
            moved.append(p.name)
        except OSError:                                         # another file system (the drive): copy without
            try:                                                # following a link, then remove the original
                src = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                try:
                    if not stat.S_ISREG(os.fstat(src).st_mode):
                        continue
                    dst = os.open(q / p.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    try:
                        while True:
                            b = os.read(src, 1 << 20)
                            if not b:
                                break
                            os.write(dst, b)
                    finally:
                        os.close(dst)
                finally:
                    os.close(src)
                os.unlink(p)
                moved.append(p.name)
            except Exception:
                pass
    return moved


def halt(rule, paths, level, culprit=None):
    with lock:
        if halted():
            return
        hid = time.strftime("%Y%m%d-%H%M%S")
        procs = holders(paths)
        if culprit and not any(x["pid"] == culprit for x in procs):
            try:
                procs.append({"pid": culprit, "comm": Path(f"/proc/{culprit}/comm").read_text().strip(), "cmd": ""})
            except OSError:
                pass
        for pr in procs:                                  # the operation itself first
            try:
                os.kill(pr["pid"], signal.SIGSTOP)
            except OSError:
                pass
        frozen = freeze_all()
        moved = quarantine(paths, hid)
        r = new_release(level, rule, paths, hid)
        h = {"id": hid, "status": "halted", "t": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "rule": rule,
             "rule_text": RULE_TEXT[rule], "level": level, "files": [Path(p).name for p in paths][:20],
             "quarantined": moved, "pids": procs, "frozen": len(frozen), "request": r["id"], "code": r["code"],
             "required": r["required"], "by": "zenos-guardd"}
        write_json(HALT, h)
        # a desktop lock screen would hide the stop notice (the window manager keeps it on top); the officers must
        # see who stopped and why, so the session's own lock is lifted. The PC itself stays stopped.
        # (if the session is not known to logind, the notice shows as soon as the user unlocks their screen)
        subprocess.run(["loginctl", "unlock-sessions"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log(event="halt", halt=hid, rule=rule, level=level, files=h["files"], frozen=len(frozen),
            operation=[f"{p['comm']}:{p['pid']}" for p in procs], quarantined=moved, request=r["id"])
        ensure_lock()


def release(h, r, approvers):
    with lock:
        for pr in h.get("pids", []):                      # the stopped operation is cancelled
            try:
                os.kill(pr["pid"], signal.SIGKILL)
            except OSError:
                pass
        thaw_all()
        h.update(status="released", released=time.strftime("%Y-%m-%dT%H:%M:%S%z"), released_by=sorted(approvers))
        write_json(HALT, h)
        log(event="release", halt=h["id"], request=r["id"], approvers=sorted(approvers))


def enforce_loop():
    while True:
        try:
            h = halted()
            if h:
                freeze_all()                               # anything new the user starts stops too
                ensure_lock()
                rp = REQ / f"{h['request']}.json"
                r = json.loads(rp.read_text())
                if r["status"] == "declined":              # declined: the stop stays and a new request goes out
                    n = new_release(h["level"], h["rule"], h["files"], h["id"])
                    h.update(request=n["id"], code=n["code"], required=n["required"])
                    write_json(HALT, h)
                    log(event="release-request-renewed", halt=h["id"], request=n["id"])
                else:
                    go, ok = verified(r)
                    if go:
                        r["status"] = "approved"
                        write_json(rp, r)
                        release(h, r, ok)
        except Exception as e:
            print("enforce:", e, file=sys.stderr, flush=True)
        time.sleep(1.0)


# ---------------- events ----------------
def on_open(p, pid):
    now = time.time()
    if pid == ME or halted() or Path(p).suffix != ".zen" or not in_security(p):
        return
    if now - recent_write.get(p, 0) < 5:                   # the guard sealing a file just saved
        return
    with lock:
        reads.append((now, p))
        while reads and now - reads[0][0] > BULK_READ_SEC:
            reads.popleft()
        distinct = {x for _, x in reads}
        if len(distinct) >= BULK_READ_N:
            files = sorted(distinct)
            lvl = max(level_of(x) for x in files)
            reads.clear()
            if not plan_allows("bulk-read", lvl, len(files)):
                halt("bulk-read", files, lvl, culprit=pid)


def on_arrival(p, pid=None):
    now = time.time()
    p = str(p)
    recent_write[p] = now
    path = Path(p)
    if path.parent != USB or path.name.startswith(".") or path.suffix in (".part", ".tmp"):
        return
    if halted():
        h = halted()
        moved = quarantine([path], h["id"])
        if moved:
            log(event="quarantine", halt=h["id"], files=moved)
        return
    lvl = level_of(path)
    with lock:
        while xfers and now - xfers[0][0] > BULK_XFER_SEC:
            xfers.popleft()
        if lvl >= 2:
            if not plan_allows("usb-export", lvl):
                halt("exfiltration", [x for _, x in xfers if Path(x).exists()] + [p], lvl, culprit=pid)
            return
        xfers.append((now, p))
        if len(xfers) >= BULK_XFER_N:
            if plan_allows("usb-export", lvl):
                xfers.pop()
            else:
                halt("bulk-transfer", [x for _, x in xfers], max(level_of(x) for _, x in xfers), culprit=pid)


def watch():
    # only folders that exist (they belong to the user; the guard never creates them as root)
    dirs = [USB] + [DESK / n for n in Z.FOLDERS if (DESK / n).is_dir()]
    fd = fan_open(dirs)
    # moves into the exit do not produce a finished write; inotify sees them (without a process id)
    ino = subprocess.Popen(["inotifywait", "-m", "-q", "-e", "moved_to", "--format", "%w%f", str(USB)],
                           stdout=subprocess.PIPE, text=True)
    log(event="guard-start", user=USER, desktop=str(DESK), watching=[str(d) for d in dirs], fanotify=True)
    checked = time.time()
    while True:
        if time.time() - checked > 15:                    # another person signed in: watch their folders instead
            checked = time.time()
            try:
                now_user = zconf.user()
            except Exception:
                now_user = USER
            if now_user != USER and not halted():
                log(event="guard-user-changed", old=USER, new=now_user)
                ino.kill()
                os.close(fd)
                return
        rl, _, _ = select.select([fd, ino.stdout], [], [], 5)
        if fd in rl:
            for mask, pid, path in fan_events(fd):
                if not path:
                    continue
                try:
                    if mask & FAN_CLOSE_WRITE:
                        if pid != ME:
                            on_arrival(path, pid)
                    elif mask & FAN_OPEN:
                        on_open(path, pid)
                except Exception as e:
                    print("event:", e, file=sys.stderr, flush=True)
        if ino.stdout in rl:
            line = ino.stdout.readline()
            if line:
                on_arrival(line.rstrip("\n"))


# ---------------- terminals ----------------
# Staff never need a terminal, and a shell bypasses every app-level control. The guard answers each start of a
# terminal program: the desktop user is refused, root and other accounts (administrators) are not. Only these
# program files are marked, so nothing else waits for the guard; if the guard stops, the kernel lets them start.
TERMINALS = ["konsole", "xterm", "uxterm", "gnome-terminal", "gnome-terminal-server", "kgx", "xfce4-terminal",
             "qterminal", "lxterminal", "mate-terminal", "terminator", "tilix", "kitty", "alacritty", "foot",
             "wezterm", "wezterm-gui", "urxvt", "rxvt", "st", "sakura", "terminology", "yakuake", "cool-retro-term",
             "x-terminal-emulator"]
FAN_CLASS_CONTENT, FAN_OPEN_EXEC_PERM, FAN_ALLOW, FAN_DENY = 0x4, 0x00040000, 0x01, 0x02
POLICY = Path("/etc/zenos/policy.conf")


def policy(key, default):
    try:
        for line in POLICY.read_text().splitlines():
            k, _, v = line.partition("=")
            if k.strip() == key:
                return v.strip()
    except OSError:
        pass
    return default


def proc_uid(pid):
    try:
        for line in open(f"/proc/{pid}/status"):
            if line.startswith("Uid:"):
                return int(line.split()[1])
    except OSError:
        pass
    return -1


# screen capture tools: refused while a sealed file of L3 or above is on the desktop user's screen
SCREENSHOTS = ["spectacle", "ksnip", "flameshot", "gnome-screenshot", "scrot", "maim", "import", "xwd", "grim",
               "shutter", "kazam", "simplescreenrecorder", "obs", "peek", "vokoscreenNG", "recordmydesktop"]


def sealed_on_screen():
    """the highest sealed level any of the user's windows shows (zenos.py marks every viewer it starts)"""
    top = 0
    for pid, comm, cmd in user_procs():
        try:
            for kv in Path(f"/proc/{pid}/environ").read_bytes().split(b"\0"):
                if kv.startswith(b"ZENOS_SEALED_LEVEL="):
                    top = max(top, int(kv.split(b"=", 1)[1] or 0))
        except (OSError, ValueError):
            continue
    return top


def program_paths(names):
    out = set()
    for d in ("/usr/bin", "/usr/local/bin", "/bin"):
        for n in names:
            p = os.path.join(d, n)
            if os.path.exists(p):
                out.add(os.path.realpath(p))
    return out


def terminal_guard():
    terms = program_paths(TERMINALS) if policy("terminal", "blocked") == "blocked" else set()
    shots = program_paths(SCREENSHOTS) if policy("screenshots", "blocked-while-sealed") == "blocked-while-sealed" else set()
    paths = terms | shots
    if not paths:
        log(event="terminal-guard", state="off (policy or nothing to guard)")
        return
    fd = _libc.fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC, os.O_RDONLY | os.O_LARGEFILE)
    if fd < 0:
        log(event="terminal-guard", state="unavailable", errno=ctypes.get_errno())
        return
    for p in sorted(paths):
        if _libc.fanotify_mark(fd, FAN_MARK_ADD, ctypes.c_uint64(FAN_OPEN_EXEC_PERM), AT_FDCWD, os.fsencode(p)) < 0:
            log(event="terminal-guard", state="mark-failed", path=p, errno=ctypes.get_errno())
    log(event="terminal-guard", state="on", programs=sorted(paths))
    last = {}
    try:                     # every event must be answered, or that program would wait forever
        while True:
            try:
                buf = os.read(fd, 8192)
            except InterruptedError:
                continue
            off = 0
            while off + META.size <= len(buf):
                ev_len, vers, _, meta_len, mask, efd, pid = META.unpack_from(buf, off)
                if ev_len == 0:
                    break
                off += ev_len
                if efd < 0:
                    continue
                deny, why = False, ""
                try:
                    if PW is not None and proc_uid(pid) == PW.pw_uid:
                        prog = os.readlink(f"/proc/self/fd/{efd}")
                        if prog in terms:
                            deny, why = True, "terminal"
                        elif prog in shots:
                            lvl = sealed_on_screen()
                            deny, why = lvl >= 3, f"screenshot while L{lvl} is on screen"
                finally:
                    try:
                        os.write(fd, struct.pack("iI", efd, FAN_DENY if deny else FAN_ALLOW))
                    except OSError:
                        pass
                try:
                    if deny:
                        prog = os.readlink(f"/proc/self/fd/{efd}")
                        if time.time() - last.get(prog, 0) > 10:      # one line per program per 10 s
                            last[prog] = time.time()
                            log(event="program-blocked", program=prog, reason=why, pid=pid, user=USER)
                except Exception:
                    pass
                finally:
                    os.close(efd)
    finally:
        os.close(fd)         # if this thread ever ends, the kernel stops asking and allows


# ---------------- officers' answers ----------------
def handle(msg):
    op, rid = msg.get("op"), os.path.basename(str(msg.get("request", "")))
    if op == "status":
        return {"ok": True, "halt": halted()}
    rp = REQ / f"{rid}.json"
    if not rp.exists():
        return {"ok": False, "message": "Unknown request."}
    with lock:
        r = json.loads(rp.read_text())
        if r["status"] != "pending":
            return {"ok": False, "message": "This request is already decided."}
        who = os.path.basename(str(msg.get("approver", "")))
        if op not in ("approve", "decline"):
            return {"ok": False, "message": "Unknown operation."}
        digest = Z.request_digest(r)
        sig = str(msg.get("sig", ""))
        sig_ok, why, facts = zapprove.check(PUB, who, sig, digest if op == "approve" else b"decline:" + digest,
                                            r.get("level", 0), state=Path(REQ).parent / "approver-counters.json")
        if not sig_ok and why == "phone-not-near":
            log(event="approve-refused", request=rid, approver=who, reason="phone-not-near")
            return {"ok": False, "message": f"An L{r.get('level')} request must be approved on the PC's screen, with your "
                                            "phone near it (scan the QR code the PC shows). Nothing was recorded."}
        if sig_ok and facts.get("exception"):
            log(event="approval-exception", request=rid, approver=who, level=r.get("level"), kind="remote")
        code_ok = str(msg.get("code", "")).strip() == r["code"]
        result = zdecide.approve(with_sig_ok(r), roster(), who, op, sig_ok, code_ok)
        if result.startswith("refused:"):
            reason = result.split(":", 1)[1]
            log(event="approve-refused", request=rid, approver=who, reason=reason)
            return {"ok": False, "message": {
                "decided": "This request is already decided.",
                "not enrolled": "This officer is not enrolled on this PC.",
                "signature": "The signature does not verify. Nothing was recorded.",
                "code": "The match code does not match the requester's screen. Nothing was approved.",
                "requester": "The stopped user cannot approve their own release. Another officer must approve.",
                "already": "You have already approved this request. Another officer must approve.",
            }.get(reason, "Refused (%s). Nothing was recorded." % reason)}
        if result == "declined":
            r["status"] = "declined"
            r["declined_by"] = who
            write_json(rp, r)
            log(event="decline", request=rid, approver=who, **zapprove.ledger_fields(facts))
            return {"ok": True, "message": "Declined. The PC stays stopped and a new request is sent."}
        r["approvals"].append({"approver": who, "t": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "sig": sig})
        write_json(rp, r)
        log(event="approve", request=rid, approver=who, count=len(r["approvals"]), required=r["required"],
            **zapprove.ledger_fields(facts))
        left = 0 if verified(r)[0] else 1
        return {"ok": True, "message": f"Approved ({len(r['approvals'])}/{r['required']})." + (" The stop is released." if left <= 0 else "")}


def serve():
    os.makedirs(os.path.dirname(SOCK), exist_ok=True)
    try:
        os.unlink(SOCK)
    except OSError:
        pass
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(SOCK)
    os.chmod(SOCK, 0o666)            # anyone may deliver a signature; only valid ones count
    s.listen(8)
    while True:
        c, _ = s.accept()
        try:
            c.settimeout(10)
            buf = b""
            while not buf.endswith(b"\n") and len(buf) < 65536:
                chunk = c.recv(4096)
                if not chunk:
                    break
                buf += chunk
            out = handle(json.loads(buf or b"{}"))
        except Exception:
            out = {"ok": False, "message": "Bad request."}
        try:
            c.sendall((json.dumps(out, ensure_ascii=False) + "\n").encode())
        except OSError:
            pass
        c.close()


def enroll_demo():
    """Developer Preview: install the PoC officers' public keys (generated in the user's key store) as trusted.
    In production each officer enrolls the key of their own device; this shortcut exists only for demos."""
    src = DATA / "approvers"
    PUB.mkdir(parents=True, exist_ok=True)
    n = 0
    for p in src.glob("*.pub"):
        dst = PUB / p.name
        dst.write_bytes(p.read_bytes())
        os.chmod(dst, 0o644)
        n += 1
    print(f"enrolled {n} officer key(s) into {PUB}")


def enroll(name, key_b64):
    """install one officer's device key (shown in ZENOS Messages → Settings → Approval key). Run as root."""
    import re
    if not re.fullmatch(r"[a-z0-9_.-]{1,32}", name):
        sys.exit("The name must be the officer's account name (lowercase letters, digits, . _ -).")
    try:
        raw = base64.b64decode(key_b64, validate=True)
        Ed25519PublicKey.from_public_bytes(raw)
    except Exception:
        sys.exit("That is not an Ed25519 public key. Copy the whole line from the officer's Settings → Approval key.")
    PUB.mkdir(parents=True, exist_ok=True)
    os.chmod(PUB, 0o755)
    dst = PUB / f"{name}.pub"
    old = dst.read_bytes() if dst.exists() else None
    tmp = PUB / f".{name}.pub.tmp"
    tmp.write_bytes(raw)
    os.chmod(tmp, 0o644)
    os.replace(tmp, dst)
    fp = hashlib.sha256(raw).hexdigest()[:16].upper()
    log(event="officer-enrolled", officer=name, fingerprint=fp, replaced=old is not None and old != raw)
    print(f"enrolled {name} · fingerprint {' '.join(fp[i:i + 4] for i in range(0, 16, 4))}")


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "--enroll-passkey":
        # the officer's passkey, as ZENOS Messages → Settings → Approval key shows it after "Use a passkey"
        try:
            fp = zapprove.enroll_passkey(PUB, sys.argv[2], json.loads(base64.b64decode(sys.argv[3]).decode()))
        except (ValueError, zapprove.Refused) as e:
            sys.exit(f"That is not a passkey registration ({e}). Copy the whole line from the officer's Settings → Approval key.")
        log(event="officer-enrolled", officer=sys.argv[2], fingerprint=fp, key="passkey")
        print(f"enrolled {sys.argv[2]} (passkey) · fingerprint {' '.join(fp[i:i + 4] for i in range(0, 16, 4))}")
        sys.exit(0)
    if len(sys.argv) == 4 and sys.argv[1] == "--enroll":
        return enroll(sys.argv[2], sys.argv[3])
    if len(sys.argv) > 1 and sys.argv[1] == "--enroll-demo":
        init_user()
        return enroll_demo()
    for d in (SYSD, REQ):
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, 0o755)
    QUAR.mkdir(parents=True, exist_ok=True)
    os.chmod(QUAR, 0o700)
    init_user()
    threading.Thread(target=serve, daemon=True).start()
    threading.Thread(target=enforce_loop, daemon=True).start()
    threading.Thread(target=terminal_guard, daemon=True).start()
    while True:
        try:
            init_user()                                   # again after a change of desktop user
            watch()
        except Exception as e:
            print("watch:", e, file=sys.stderr, flush=True)
            time.sleep(5)


if __name__ == "__main__":
    main()
