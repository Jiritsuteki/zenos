#!/usr/bin/env python3
"""ZENOS AI guard (root): which AI services this PC may reach, enforced in the kernel's packet filter.

Each AI service is a place in the proven flow decision (formal/ZenosFormal/Flow.lean): an AI outside the government
may hold at most L2, the government's AI L3, the ministry's own AI L5. Once a request has left an app, nothing on
the PC can tell which level of content it carries, so the guard goes by the highest level unsealed on this PC:
zenos-keyd records it in /run/zenos/exposed.json at every unseal and waits for the guard to confirm the rules before
it hands out the plaintext. For every AI service the guard asks zenos-decide whether content of that level may go
there. Where the answer is no (or no answer can be had), the service's addresses are rejected in the ZENOS_AI chain,
for every program on the PC, not only for the ZENOS apps.

The exposure only rises, until the PC restarts or the administrator resets it: once L3 content has been on the
screen it may still sit in some program's memory, so an outside AI stays out of reach. (A lower level never allows
more: formal/ZenosFormal/Flow.lean, `mayFlow_antitone`.)

  /etc/zenos/ai.json               {"services": [{"url": "https://ai.example.go.jp/v1", "kind": "gov-ai"}, ...]}
                                   kinds: external-ai, gov-ai, ministry-ai; written by the administrator. An entry
                                   with any other kind counts as external-ai, the strictest.
  /var/lib/zenos/ai-learned.json   services the apps were pointed at that the administrator did not list. They are
                                   always external-ai, so learning a service can only add a block, never lift one.
  zenos_aiguard.py                 run the guard (systemd: zenos-aiguard.service)
  zenos_aiguard.py status          the exposure and what is reachable now
  zenos_aiguard.py reset           as root: forget the exposure (after every sealed file is closed); recorded
Protocol: one JSON line per connection on /run/zenos/aiguard.sock
  {"op": "check", "url": U}  -> {"ok": true, "allow": bool, "kind", "level", "message"}   (learns U if unknown)
  {"op": "sync"}             -> {"ok": true, "level"}      rules applied for the current exposure (keyd calls this)
  {"op": "state"}            -> {"ok": true, "level", "services": [{"host", "port", "kind", "allow", "addrs"}]}

Not covered: a service reached under a name or address the guard was never told about. That is ordinary outbound
traffic, which the network sentinel (volume to unapproved destinations) and the open-time cut (L4 and above) watch.
"""
import ipaddress, json, os, re, socket, struct, subprocess, sys, threading, time
from urllib.parse import urlsplit

# the ZENOS library is ../lib/zenos beside this program (/usr/lib/zenos, root-owned)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "lib", "zenos"))
import zdecide
try:
    import zledger
except Exception:
    zledger = None

REGISTRY = os.environ.get("ZENOS_AI_REGISTRY", "/etc/zenos/ai.json")
LEARNED = os.environ.get("ZENOS_AI_LEARNED", "/var/lib/zenos/ai-learned.json")
MAX_LEARNED, LEARN_RATE = 256, 20
EXPOSED = os.environ.get("ZENOS_EXPOSED", "/run/zenos/exposed.json")
SOCK = os.environ.get("ZENOS_AIGUARD_SOCK", "/run/zenos/aiguard.sock")
LOG = os.environ.get("ZENOS_AIGUARD_LOG", "/var/log/zenos/aiguard.jsonl")
LEDGER = os.environ.get("ZENOS_AIGUARD_LEDGER", "/var/log/zenos/access-ledger.jsonl")
CHAIN = "ZENOS_AI"
KINDS = ("external-ai", "gov-ai", "ministry-ai")
KEEP_ADDR_SEC = 600            # an address a name resolved to stays blocked this long after it was last seen
NAME = {"external-ai": "an AI outside the government", "gov-ai": "the government's AI", "ministry-ai": "the ministry's AI"}


def log(**kw):
    kw = {"t": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **kw}
    try:
        os.makedirs(os.path.dirname(LOG), exist_ok=True)
        with open(LOG, "a") as f:
            f.write(json.dumps(kw, ensure_ascii=False) + "\n")
    except OSError:
        pass
    if zledger is not None:
        try:
            zledger.append(LEDGER, kw.get("event", "aiguard"), "aiguard", "aiguard",
                           **{k: v for k, v in kw.items() if k not in ("t", "event")})
        except Exception:
            pass


def target(url):
    """(host, port) of an http(s) URL, or None"""
    try:
        u = urlsplit(str(url).strip())
        if u.scheme not in ("http", "https") or not u.hostname:
            return None
        return u.hostname.lower().rstrip("."), u.port or (443 if u.scheme == "https" else 80)
    except ValueError:
        return None


def _load(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def exposure():
    """the highest level unsealed on this PC since boot or the last reset (0 if none)"""
    if not os.path.exists(EXPOSED):
        return 0
    try:
        with open(EXPOSED) as f:
            return max(0, min(5, int(json.load(f)["level"])))
    except Exception:
        return 5                   # a record that is there but cannot be read counts as the highest level


def services():
    """every AI service the guard knows: the administrator's list first, then the learned ones (external-ai)"""
    out, seen = [], set()
    reg = _load(REGISTRY, {})
    for s in (reg.get("services", []) if isinstance(reg, dict) else []):
        t = target(s.get("url", "")) if isinstance(s, dict) else None
        if t and t not in seen:
            kind = s.get("kind") if s.get("kind") in KINDS else "external-ai"
            out.append({"host": t[0], "port": t[1], "kind": kind, "listed": True})
            seen.add(t)
    for u in _load(LEARNED, []) if isinstance(_load(LEARNED, []), list) else []:
        t = target(u)
        if t and t not in seen:
            out.append({"host": t[0], "port": t[1], "kind": "external-ai", "listed": False})
            seen.add(t)
    return out


def decide(level, svcs, flow=zdecide.flow):
    """the proven decision for each service; anything but a clear yes is a no"""
    for s in svcs:
        try:
            s["allow"] = flow(level, s["kind"]) is True
        except Exception:
            s["allow"] = False
    return svcs


INFRA_CONF = os.environ.get("ZENOS_INFRA_CONF", "/etc/zenos/audit.json:/etc/zenos/keysvc.json:/etc/zenos/supply.json:"
                            "/etc/zenos/approval.json").split(":")


def infra_hosts():
    """host names of ZENOS's own servers (audit nodes, key service, ...) from root's configuration"""
    out = set()
    def walk(x):
        if isinstance(x, dict):
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
        elif isinstance(x, str) and "://" in x:
            t = target(x)
            if t:
                out.add(t[0])
    for f in INFRA_CONF:
        walk(_load(f, {}))
    return out


def protected_addrs(svcs, infra=None):
    """addresses a learned entry must never block: those of services the administrator listed and of ZENOS's own
    servers (a name anyone teaches could be made to point at them)"""
    out = set()
    for s in svcs:
        if s.get("listed"):
            out.update(s.get("addrs", []))
    for h in (infra if infra is not None else infra_hosts()):
        try:
            out.add(str(ipaddress.ip_address(h)))
        except ValueError:
            try:
                out.update(sa[0].split("%")[0] for fam, _, _, _, sa in socket.getaddrinfo(h, None)
                           if fam in (socket.AF_INET, socket.AF_INET6))
            except OSError:
                pass
    return out


def rules(svcs, infra=None):
    """the ZENOS_AI chain for IPv4 and IPv6: reject every address of a service that is not allowed. For a learned
    (unlisted) service, never an address of this machine, a private or link-local network, or a listed or ZENOS
    service: any local account can teach a name, and it must not be able to cut those off."""
    v4, v6 = [], []
    keep = protected_addrs(svcs, infra) if any(not s.get("listed") for s in svcs) else set()
    for s in svcs:
        if s.get("allow"):
            continue
        for a in sorted(s.get("addrs", [])):
            ip = ipaddress.ip_address(a)
            if not s.get("listed") and (a in keep or ip.is_loopback or ip.is_private or ip.is_link_local
                                        or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
                continue
            r = "-A %s -d %s/%d -p tcp --dport %d -j REJECT --reject-with tcp-reset" % (
                CHAIN, ip, ip.max_prefixlen, s["port"])
            (v4 if ip.version == 4 else v6).append(r)
    return sorted(set(v4)), sorted(set(v6))


def sh(*a, inp=None):
    return subprocess.run(a, input=inp, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


class Guard:
    def __init__(self):
        self.lock = threading.Lock()
        self.addrs = {}            # (host, port) -> {addr: last seen}
        self.applied = None        # (v4, v6) last written
        self.state = []
        self.learned_by = {}       # uid -> times it taught a new service (bounded per hour)

    def resolve(self, s):
        key, now = (s["host"], s["port"]), time.time()
        seen = self.addrs.setdefault(key, {})
        try:
            seen[str(ipaddress.ip_address(s["host"]))] = now
        except ValueError:
            try:
                for fam, _, _, _, sa in socket.getaddrinfo(s["host"], s["port"], 0, socket.SOCK_STREAM):
                    if fam in (socket.AF_INET, socket.AF_INET6):
                        seen[sa[0].split("%")[0]] = now
            except OSError:
                pass               # keep what was seen before; a name that never resolved has nothing to block
        for a in [a for a, t in seen.items() if now - t > KEEP_ADDR_SEC]:
            del seen[a]
        s["addrs"] = sorted(seen)
        return s

    def _write(self, tool, lines):
        body = "*filter\n:%s - [0:0]\n-F %s\n%s\nCOMMIT\n" % (CHAIN, CHAIN, "\n".join(lines))
        r = sh(tool + "-restore", "--noflush", inp=body)
        if r.returncode != 0:
            return False
        if sh(tool, "-C", "OUTPUT", "-j", CHAIN).returncode != 0:
            sh(tool, "-I", "OUTPUT", "1", "-j", CHAIN)
        return sh(tool, "-C", "OUTPUT", "-j", CHAIN).returncode == 0

    def hooked(self):
        return sh("iptables", "-C", "OUTPUT", "-j", CHAIN).returncode == 0

    def sync(self, force=False):
        """re-read everything, decide, and write the chain if it changed (or was removed). True when the kernel
        holds the rules for the current exposure."""
        with self.lock:
            level = exposure()
            svcs = decide(level, [self.resolve(s) for s in services()])
            v4, v6 = rules(svcs)
            ok = True
            if force or (v4, v6) != self.applied or not self.hooked():
                ok = self._write("iptables", v4)
                if v6 or shutil_which("ip6tables"):
                    ok = self._write("ip6tables", v6) and ok
                if ok:
                    before = {(s["host"], s["port"]) for s in self.state if not s.get("allow")}
                    self.applied = (v4, v6)
                    for s in svcs:
                        if not s["allow"] and (s["host"], s["port"]) not in before:
                            for a in s["addrs"]:          # sockets already open to it go too
                                sh("ss", "-K", "dst", a, "dport", "=", ":%d" % s["port"])
                    blocked = sorted("%s:%d" % (s["host"], s["port"]) for s in svcs if not s["allow"])
                    if [s for s in svcs if not s["allow"]] != [s for s in self.state if not s.get("allow")]:
                        log(event="ai-guard", level=level, blocked=blocked)
                else:
                    log(event="ai-guard-failed", level=level)
            self.state = svcs
            return ok, level

    def learn(self, t, uid=0):
        """Remember a service an app was pointed at. Any local account can ask, so what it can add is bounded: a host
        name of letters, digits, dots and dashes, at most MAX_LEARNED in all, and LEARN_RATE new ones per account
        an hour (the rest are still refused while exposed, just not remembered)."""
        if any((s["host"], s["port"]) == t for s in services()):
            return
        # a host name with a dot in it, never an address or "localhost": what is learned names a service, and
        # its addresses are filtered again when the rules are written (rules())
        h = t[0]
        if not re.fullmatch(r"(?=.{1,253}$)[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+", h) \
                or re.fullmatch(r"[0-9.]+", h) or h.endswith(".localhost") or not 0 < t[1] < 65536:
            return
        now = time.time()
        recent = [x for x in self.learned_by.get(uid, []) if now - x < 3600]
        if len(recent) >= LEARN_RATE:
            log(event="ai-learn-throttled", uid=uid)
            return
        cur = _load(LEARNED, [])
        cur = cur if isinstance(cur, list) else []
        if len(cur) >= MAX_LEARNED:
            log(event="ai-learn-full", uid=uid)
            return
        self.learned_by[uid] = recent + [now]
        cur.append("https://%s:%d/" % t)
        os.makedirs(os.path.dirname(LEARNED), exist_ok=True)
        tmp = LEARNED + ".tmp"
        with open(tmp, "w") as f:
            json.dump(cur, f)
        os.replace(tmp, LEARNED)
        log(event="ai-learned", host=t[0], port=t[1], kind="external-ai")

    def check(self, url, uid=0):
        t = target(url)
        if not t:
            return {"ok": True, "allow": False, "message": "Only http and https AI addresses can be used."}
        self.learn(t, uid)
        ok, level = self.sync()
        s = next((s for s in self.state if (s["host"], s["port"]) == t), None)
        if not ok or s is None:
            return {"ok": True, "allow": False, "level": level,
                    "message": "The network rules could not be confirmed, so no AI can be used right now."}
        if s["allow"]:
            return {"ok": True, "allow": True, "kind": s["kind"], "level": level, "message": ""}
        return {"ok": True, "allow": False, "kind": s["kind"], "level": level,
                "message": "An L%d file has been opened on this PC, so %s cannot be reached until the PC restarts "
                           "or the administrator resets it." % (level, NAME[s["kind"]])}

    def handle(self, msg, uid=0):
        op = msg.get("op")
        if op == "check":
            return self.check(msg.get("url", ""), uid)
        if op == "sync":
            ok, level = self.sync()
            return {"ok": ok, "level": level}
        if op == "state":
            self.sync()
            return {"ok": True, "level": exposure(),
                    "services": [{k: s.get(k) for k in ("host", "port", "kind", "allow", "addrs", "listed")}
                                 for s in self.state]}
        return {"ok": False, "error": "unknown op"}


def shutil_which(n):
    import shutil
    return shutil.which(n)


def reset():
    if os.geteuid() != 0:
        print("reset needs root (sudo)", file=sys.stderr)
        return 1
    before = exposure()
    try:
        os.unlink(EXPOSED)
    except FileNotFoundError:
        pass
    log(event="ai-exposure-reset", by=os.environ.get("SUDO_USER", "root"), level_before=before)
    try:
        ask({"op": "sync"})
    except OSError:
        pass
    print("exposure reset (was L%d)" % before)
    return 0


def ask(msg):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect(SOCK)
    s.sendall((json.dumps(msg) + "\n").encode())
    buf = b""
    while not buf.endswith(b"\n"):
        c = s.recv(65536)
        if not c:
            break
        buf += c
    s.close()
    return json.loads(buf or b"{}")


def serve(g):
    os.makedirs(os.path.dirname(SOCK), exist_ok=True)
    try:
        os.unlink(SOCK)
    except OSError:
        pass
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(SOCK)
    os.chmod(SOCK, 0o666)          # anyone may ask; an answer can only add blocks, never lift one
    srv.listen(16)

    def client(c):
        try:
            c.settimeout(15)
            buf = b""
            while not buf.endswith(b"\n") and len(buf) < 65536:
                chunk = c.recv(65536)
                if not chunk:
                    break
                buf += chunk
            uid = struct.unpack("3i", c.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))[1]
            out = g.handle(json.loads(buf or b"{}"), uid)
        except Exception:
            out = {"ok": False, "error": "bad request"}
        try:
            c.sendall((json.dumps(out) + "\n").encode())
        except OSError:
            pass
        c.close()

    while True:
        c, _ = srv.accept()
        threading.Thread(target=client, args=(c,), daemon=True).start()


def main():
    if sys.argv[1:] == ["reset"]:
        return reset()
    if sys.argv[1:] == ["status"]:
        print(json.dumps(ask({"op": "state"}), indent=1))
        return 0
    g = Guard()
    g.sync(force=True)
    log(event="aiguard-start", level=exposure())
    threading.Thread(target=serve, args=(g,), daemon=True).start()
    while True:                    # names move between addresses, and someone may remove the chain
        time.sleep(2)
        try:
            if not g.hooked():
                log(event="ai-guard-tamper")
                g.sync(force=True)
            else:
                g.sync()
        except Exception as e:
            log(event="ai-guard-error", error=str(e))


if __name__ == "__main__":
    sys.exit(main())
