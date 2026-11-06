#!/usr/bin/env python3
"""zenos-launchd: starts the browser and ZENOS Messages for the person who asks, so that zenos-credd can tell them
from look-alikes.

A password leaves the vault only for the real browser or messenger. Any program of the same user can name its
process like them, so a name proves nothing. A program this service starts is different: its parent is root, so
with kernel.yama.ptrace_scope = 1 (ZENOS's setting) no other program of the user can attach to it, read its memory
or change its code; it runs as the person who asked, with an environment chosen here (no LD_PRELOAD, no PYTHONPATH,
no NODE_OPTIONS), the installed root-owned program and its fixed interpreter. Each start is recorded as
(pid, start time, uid, program) in a root-owned file that zenos-credd reads; a process not in it is not the
browser or the messenger, whatever it is called.

Protocol: one JSON request per connection on /run/zenos/launch.sock (0666):
  {"op": "launch", "program": "browser", "args": [url...], "env": {"DISPLAY": ":0", ...}}
  {"op": "launch", "program": "messenger", "args": ["zenos", "8096"], "env": {...}}
The program runs as the connecting user (SO_PEERCRED), in its own session, in the user's home folder.
"""
import json, os, pwd, re, socket, struct, subprocess, sys, threading, time
from pathlib import Path

SOCK = os.environ.get("ZENOS_LAUNCH_SOCK", "/run/zenos/launch.sock")
LAUNCHED = Path(os.environ.get("ZENOS_LAUNCHED", "/run/zenos/launched.json"))
PY, NODE = "/usr/bin/python3", "/usr/bin/node"
BROWSER = os.environ.get("ZENOS_LAUNCH_BROWSER", "/usr/share/zenos/bin/zenos_webkit.py")
MESSENGER = os.environ.get("ZENOS_LAUNCH_MESSENGER", "/usr/share/zenos/msg/client.js")
NODE_OPTIONS_OK = {"", "--require=/usr/lib/zenos/zdistrust.js"}
LOCK = threading.Lock()

# what the program may inherit from the caller's session, and the shape each value must have
ENV_SHAPES = {
    "DISPLAY": r":\d{1,3}(\.\d{1,2})?",
    "XAUTHORITY": r"/[A-Za-z0-9._/@+-]{1,200}",
    "DBUS_SESSION_BUS_ADDRESS": r"unix:[A-Za-z0-9=,._/-]{1,200}",
    "LANG": r"[A-Za-z0-9_.@-]{1,40}",
    "LANGUAGE": r"[A-Za-z0-9_.@:-]{1,80}",
    "LC_ALL": r"[A-Za-z0-9_.@-]{1,40}",
    "XMODIFIERS": r"@im=[A-Za-z0-9_-]{1,20}",
    "GTK_IM_MODULE": r"[A-Za-z0-9_-]{1,20}",
    "QT_IM_MODULE": r"[A-Za-z0-9_-]{1,20}",
    "ZENOS_RELAY": r"https?://[A-Za-z0-9.:\[\]/_-]{1,200}",
}


def start_time(pid):
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
    except (OSError, IndexError):
        return None


def trusted(path):
    """a file only root can change: it and every folder above it owned by root and not writable by others"""
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


def record(pid, uid, kind):
    with LOCK:
        try:
            cur = json.loads(LAUNCHED.read_text())
        except Exception:
            cur = []
        cur = [h for h in cur if start_time(h.get("pid", 0)) == h.get("start")]
        cur.append({"pid": pid, "start": start_time(pid), "uid": uid, "program": kind, "t": time.time()})
        LAUNCHED.parent.mkdir(parents=True, exist_ok=True)
        tmp = LAUNCHED.with_name(LAUNCHED.name + ".tmp")
        tmp.write_text(json.dumps(cur))
        os.chmod(tmp, 0o644)
        os.replace(tmp, LAUNCHED)


def command(kind, args, env_in):
    """the program line and environment for a request, or a reason to refuse"""
    if not isinstance(args, list) or len(args) > 20 or not all(isinstance(a, str) and 0 < len(a) <= 4096
                                                              and "\0" not in a for a in args):
        return None, "bad arguments"
    if kind == "browser":
        if any(a.startswith("-") for a in args):
            return None, "the browser takes addresses and files, not options"
        prog, argv = BROWSER, [PY, "-I", BROWSER] + args
    elif kind == "messenger":
        if len(args) != 2 or not re.fullmatch(r"[a-z0-9_.-]{1,40}", args[0]) or not args[1].isdigit() \
                or not 1024 <= int(args[1]) <= 65535:
            return None, "the messenger takes an account and a port"
        prog, argv = MESSENGER, [NODE, MESSENGER] + args
    else:
        return None, "unknown program"
    if not (trusted(prog) and trusted(argv[0])):
        return None, "the program is not installed by root"
    env = {}
    for k, shape in ENV_SHAPES.items():
        v = env_in.get(k) if isinstance(env_in, dict) else None
        if isinstance(v, str) and re.fullmatch(shape, v):
            env[k] = v
    if kind == "messenger" and isinstance(env_in, dict) and env_in.get("NODE_OPTIONS", "") in NODE_OPTIONS_OK \
            and env_in.get("NODE_OPTIONS"):
        env["NODE_OPTIONS"] = env_in["NODE_OPTIONS"]
    if kind == "browser":
        env["GDK_BACKEND"] = "x11"
    return (argv, env), None


def launch(msg, uid):
    if msg.get("op") != "launch":
        return {"ok": False, "error": "unknown op"}
    try:
        pw = pwd.getpwuid(uid)
    except KeyError:
        return {"ok": False, "error": "unknown user"}
    if uid < 1000 or pw.pw_shell.endswith(("nologin", "false")):
        return {"ok": False, "error": "only a person's account can start these programs"}
    kind = msg.get("program")
    got, why = command(kind, msg.get("args", []), msg.get("env", {}))
    if not got:
        return {"ok": False, "error": why}
    argv, env = got
    env.update({"HOME": pw.pw_dir, "USER": pw.pw_name, "LOGNAME": pw.pw_name, "SHELL": pw.pw_shell,
                "PATH": "/usr/local/bin:/usr/bin:/bin", "XDG_RUNTIME_DIR": f"/run/user/{uid}"})
    groups = os.getgrouplist(pw.pw_name, pw.pw_gid)
    p = subprocess.Popen(argv, user=uid, group=pw.pw_gid, extra_groups=groups, env=env, cwd=pw.pw_dir,
                         start_new_session=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.STDOUT, close_fds=True, umask=0o077)
    threading.Thread(target=p.wait, daemon=True).start()        # reap it when it ends
    record(p.pid, uid, kind)
    return {"ok": True, "pid": p.pid}


def serve():
    try:
        os.unlink(SOCK)
    except FileNotFoundError:
        pass
    os.makedirs(os.path.dirname(SOCK), exist_ok=True)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(SOCK)
    os.chmod(SOCK, 0o666)
    s.listen(16)
    while True:
        c, _ = s.accept()
        threading.Thread(target=client, args=(c,), daemon=True).start()


def client(c):
    with c:
        try:
            c.settimeout(5)
            _pid, uid, _gid = struct.unpack("3i", c.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
            buf = b""
            while len(buf) < 65536:
                b = c.recv(65536)
                if not b:
                    break
                buf += b
                if buf.endswith(b"\n"):
                    break
            m = json.loads(buf or b"{}")
            out = launch(m if isinstance(m, dict) else {}, uid)
        except Exception as e:
            out = {"ok": False, "error": type(e).__name__}
        try:
            c.sendall(json.dumps(out).encode() + b"\n")
        except OSError:
            pass


def is_launched(pid, uid, kind, path=None):
    """for zenos-credd: was this process started by zenos-launchd as `kind` for `uid`, and is it still that process"""
    try:
        recs = json.loads(Path(path or LAUNCHED).read_text())
    except Exception:
        return False
    st = start_time(pid)
    return any(h.get("pid") == pid and h.get("start") == st and st and h.get("uid") == uid and h.get("program") == kind
               for h in recs if isinstance(h, dict))


if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit("zenos-launchd runs as root")
    serve()
