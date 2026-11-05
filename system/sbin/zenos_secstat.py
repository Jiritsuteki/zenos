#!/usr/bin/env python3
"""ZENOS security monitor feed (root service).

Counts what the System Monitor's Security graph shows and raises plain alerts. Nothing leaves the machine.
  inbound  : new inbound TCP connections dropped by the ZENOS_IN firewall chain (packet counter), and the
             source/port of each from the rate-limited "ZENOS_IN_DROP " kernel log line
  contained: outbound destinations the network sentinel cut (ZENOS_OUT rules) and its incidents log
  sign-in  : failed passwords (sudo, su, login screen, lock screen, ssh) from the system journal
Alerts (deterministic thresholds, no AI): port scan, inbound burst, repeated failed sign-ins, sentinel incident,
firewall missing, security fixes not installed, restart pending after a fix. Written every 2 s to /run/zenos/secstat.json (world-readable, no secrets in it).
"""
import json, os, re, subprocess, threading, time
from collections import deque, Counter

OUT = "/run/zenos/secstat.json"
INCIDENTS = "/var/log/zenos/incidents.jsonl"
SCAN_PORTS, SCAN_WIN = 10, 60          # one source touching >= 10 different ports within 60 s
BURST_N, BURST_WIN = 50, 60            # >= 50 blocked attempts within 60 s
AUTH_N, AUTH_WIN = 5, 300              # >= 5 failed sign-ins within 5 min
QUIET = 600                            # the same alert is not repeated for 10 min
UPD_EVERY = 900                        # look for pending security fixes every 15 min
UPD_RED = 24 * 3600                    # a security fix still not installed after 24 h -> red
REBOOT_FLAG = "/run/reboot-required"
UU_STAMP = "/var/lib/apt/periodic/unattended-upgrades-stamp"
SEC_ORIGIN = re.compile(r"\((\S+) (\S+) \[")   # 'Inst pkg [old] (new Debian-Security:13/stable-security [amd64])'
# one line per wrong password: PAM's own record (sudo, su, login screen, lock screen and ssh all go through PAM);
# the summaries sudo/sshd add on top ("incorrect password attempts", "Failed password") would count it twice
AUTH_RE = re.compile(r"pam_\w+\([\w-]+:auth\): authentication failure", re.I)
DROP_RE = re.compile(r"ZENOS_IN_DROP .*?SRC=(\S+) .*?PROTO=(\S+)(?: .*?DPT=(\d+))?")
SAFE = re.compile(r"[^0-9A-Za-z.,:_ -]")             # alert text goes into a shell-quoted notify-send

# ---- remote operation (Tk 2026-10-21 00:50): the PC is driven from somewhere other than where it is -> RED ----
# Signals: a login session the system marks as remote, an established connection on a remote-desktop/ssh port
# whose peer is another machine, or a remote-control program holding a connection to another machine
# (these relay through the vendor's servers, so they get past the inbound lockdown).
REMOTE_PORTS = {22, 3389, 5938, 6568, 7070, 21115, 21116, 21117, 21118, 21119} | set(range(5900, 6000))
REMOTE_TOOLS = re.compile(r"^(anydesk|teamviewer\w*|TeamViewer\w*|rustdesk|x11vnc|x0vncserver|Xvnc|vncserver|krfb\w*|"
                          r"xrdp\w*|chrome-remote\w*|remoting_host|parsecd|splashtop\w*|meshagent|tacticalrmm|sshd\S*)$")
ALLOW_REMOTE = "/etc/zenos/remote-allow.json"      # ["10.1.2.0/24", ...] approved admin consoles (officer-set)
import ipaddress, sys
# the ZENOS library is ../lib/zenos beside this program (/usr/lib/zenos, root-owned)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "lib", "zenos"))
try:
    import zalarm
except Exception:
    zalarm = None


def own_addrs():
    out = set()
    for l in sh("ip", "-o", "addr").splitlines():
        f = l.split()
        if len(f) > 3:
            out.add(f[3].split("/")[0])
    return out


def allow_nets():
    try:
        return [ipaddress.ip_network(c) for c in json.load(open(ALLOW_REMOTE))]
    except Exception:
        return []


def other_machine(ip, mine, allow):
    ip = ip.strip("[]").split("%")[0]
    if ip.startswith("::ffff:"):
        ip = ip[7:]
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_loopback or ip in mine or any(a in n for n in allow))


def remote_operators():
    """[(what, peer)] for everything currently driving this PC from another machine"""
    mine, allow, found = own_addrs(), allow_nets(), []
    for sid in sh("loginctl", "list-sessions", "--no-legend").split("\n"):
        sid = sid.split()[0] if sid.split() else ""
        if not sid:
            continue
        p = dict(l.split("=", 1) for l in sh("loginctl", "show-session", sid, "-p", "Remote", "-p", "RemoteHost",
                                              "-p", "Service").splitlines() if "=" in l)
        if p.get("Remote") == "yes" and p.get("RemoteHost") and other_machine(p["RemoteHost"], mine, allow):
            found.append((p.get("Service") or "remote login", p["RemoteHost"]))
    for l in sh("ss", "-Htnp", "state", "established").splitlines():
        f = l.split()
        if len(f) < 4:
            continue
        local, peer = f[2], f[3]
        lport = int(local.rsplit(":", 1)[1]) if local.rsplit(":", 1)[-1].isdigit() else 0
        m = re.search(r'users:\(\("([^"]+)"', l)
        comm = m.group(1) if m else ""
        pip = peer.rsplit(":", 1)[0]
        if not other_machine(pip, mine, allow):
            continue
        if lport in REMOTE_PORTS or REMOTE_TOOLS.match(comm):
            found.append((comm or ("port %d" % lport), pip.strip("[]")))
    return sorted(set(found))


lock = threading.Lock()
drops = deque(maxlen=2000)             # (t, src, port) from the kernel log
auth = deque(maxlen=500)               # (t, service)
alerts = deque(maxlen=20)
last_alert = {}
auth_total = 0
start = time.time()


def sh(*a):
    return subprocess.run(a, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True).stdout


def chain_counts(chain, target):
    """packets matched by rules with this target in this chain, IPv4 + IPv6; None if the chain is missing"""
    total, seen = 0, False
    for ipt in ("iptables", "ip6tables"):
        out = sh(ipt, "-w", "-nvxL", chain)
        if not out.startswith("Chain"):
            continue
        seen = True
        for line in out.splitlines()[2:]:
            f = line.split()
            if len(f) > 2 and f[2] == target:
                total += int(f[0])
    return total if seen else None


def alert(key, sev, title, text):
    now = time.time()
    if now - last_alert.get(key, 0) < QUIET:
        return
    last_alert[key] = now
    alerts.append({"id": "%d-%s" % (int(now * 1000), key.split(":")[0]), "t": int(now), "sev": sev,
                   "title": title, "text": SAFE.sub("", text)[:160]})


def journal():
    global auth_total
    while True:
        p = subprocess.Popen(["journalctl", "-f", "-n", "0", "-o", "json"], stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, text=True)
        for line in p.stdout:
            try:
                e = json.loads(line)
            except ValueError:
                continue
            msg = e.get("MESSAGE")
            if not isinstance(msg, str):
                continue
            now = time.time()
            if e.get("_TRANSPORT") == "kernel":
                m = DROP_RE.search(msg)
                if m:
                    with lock:
                        drops.append((now, m.group(1), m.group(3) or m.group(2)))
            elif AUTH_RE.search(msg):
                svc = e.get("SYSLOG_IDENTIFIER") or e.get("_COMM") or "system"
                with lock:
                    auth.append((now, svc)); auth_total += 1
        time.sleep(2)


upd = {"security_pending": 0, "packages": [], "pending_since": None, "reboot_required": False,
       "reboot_since": None, "last_auto": None, "checked": None}


def pending_security():
    """packages with a fix waiting from Debian-Security, the ZENOS repository or NodeSource (simulation, no lock taken)"""
    out = sh("apt-get", "-s", "-o", "Debug::NoLocking=1", "dist-upgrade")
    pk = []
    for l in out.splitlines():
        if not l.startswith("Inst "):
            continue
        m = SEC_ORIGIN.search(l)
        src = m.group(2) if m else ""
        if "security" in src.lower() or src.startswith("ZENOS") or "nodistro" in l:
            pk.append(l.split()[1])
    return pk


def updates():
    while True:
        now = time.time()
        try:
            pk = pending_security()
        except Exception:
            pk = None
        rb = os.path.exists(REBOOT_FLAG)
        try:
            last = int(os.path.getmtime(UU_STAMP))
        except OSError:
            last = None
        with lock:
            if pk is not None:
                upd["security_pending"], upd["packages"] = len(pk), pk[:20]
                upd["pending_since"] = (upd["pending_since"] or int(now)) if pk else None
            upd["reboot_since"] = (upd["reboot_since"] or int(now)) if rb else None
            upd["reboot_required"], upd["last_auto"], upd["checked"] = rb, last, int(now)
        time.sleep(UPD_EVERY)


TRUST = "/run/zenos/trust.json"         # written by the trust agent (zenos_trustwatch.py)
trust_seen = set()


def read_trust():
    """the trust agent's alerts and a short summary of every trust route, for the monitor"""
    try:
        d = json.load(open(TRUST))
    except (OSError, ValueError):
        return {}
    return d


def trust_summary(d):
    if not d:
        return None
    return {"risk": d.get("risk"), "checked": d.get("t"),
            "feed": {k: (d.get("feed") or {}).get(k) for k in ("ok", "keys", "certificates", "checked")},
            "routes": [{"label": s.get("label"), "users": s.get("users"), "roots": s.get("roots"),
                        "protected": s.get("protected"), "distrusted": len(s.get("distrusted") or []),
                        "vouching": len(s.get("vouching") or []), "unreadable": bool(s.get("unreadable"))}
                       for s in d.get("stores", [])][:20]}


def incidents_since(pos):
    try:
        with open(INCIDENTS) as f:
            f.seek(pos)
            new = f.read()
            return f.tell(), [json.loads(l) for l in new.splitlines() if l.strip()]
    except (OSError, ValueError):
        return pos, []


def main():
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    threading.Thread(target=journal, daemon=True).start()
    threading.Thread(target=updates, daemon=True).start()
    try:
        pos = os.path.getsize(INCIDENTS)
    except OSError:
        pos = 0
    base_in = base_out = None
    contained_total = 0
    hist_in, hist_auth = deque(maxlen=60), deque(maxlen=60)
    prev_in, prev_auth = None, 0
    while True:
        now = time.time()
        tin = chain_counts("ZENOS_IN", "DROP")
        tout = chain_counts("ZENOS_OUT", "DROP") or 0
        fw_ok = tin is not None
        if fw_ok and base_in is None:
            base_in = tin
        if base_out is None:
            base_out = tout
        blocked = (tin - base_in) if fw_ok else 0
        if blocked < 0:                  # chain was re-created: counters restart
            base_in, blocked = tin, 0
        if not fw_ok:
            alert("fw", "red", "Firewall is off", "The inbound lockdown chain ZENOS_IN is missing.")
        remote = remote_operators()
        for what, peer in remote:
            if now - last_alert.get("remote:%s:%s" % (what, peer), 0) >= QUIET:
                alert("remote:%s:%s" % (what, peer), "red", "Remote control from another machine",
                      "%s is driving this PC from %s, not from where the PC is." % (what, peer))
                if zalarm is not None:
                    try:
                        zalarm.raise_alert("red", "ZENOS RED ALERT",
                                           "This PC is being operated from another machine (%s, %s)." % (peer, what))
                    except Exception:
                        pass
        trust = read_trust()
        for a in trust.get("alerts", []):
            if a.get("id") not in trust_seen and now - a.get("t", 0) < QUIET:
                alert("trust:" + a["id"], a.get("sev", "amber"), a.get("title", "Trust"), a.get("text", ""))
            trust_seen.add(a.get("id"))
        pos, inc = incidents_since(pos)
        for r in inc:
            ty = r.get("type", "")
            if ty == "egress":
                contained_total += 1
                alert("inc:egress:%s" % r.get("dst"), "red", "Outbound connection cut",
                      "Unapproved data to %s:%s was stopped by the sentinel." % (r.get("dst", "?"), r.get("port", "?")))
            elif ty == "listener":
                contained_total += 1
                alert("inc:listener:%s" % r.get("port"), "red", "Unexpected listening port closed",
                      "A program opened port %s to outside connections; the sentinel contained it." % r.get("port", "?"))
            elif ty == "firewall-tamper":
                alert("inc:fw", "red", "Firewall was changed", "Someone removed the inbound lockdown. It was put back.")
        with lock:
            d60 = [x for x in drops if now - x[0] <= SCAN_WIN]
            a5 = [x for x in auth if now - x[0] <= AUTH_WIN]
            at = auth_total
            ports = {}
            for _, src, port in d60:
                ports.setdefault(src, set()).add(port)
            for src, ps in ports.items():
                if len(ps) >= SCAN_PORTS:
                    alert("scan:" + src, "amber", "Port scan blocked",
                          "%s tried %d ports in the last minute. All were dropped." % (src, len(ps)))
            if len(d60) >= BURST_N:
                alert("burst", "amber", "Many connection attempts",
                      "%d inbound attempts in the last minute. All were dropped." % len(d60))
            if len(a5) >= AUTH_N:
                c = Counter(s for _, s in a5).most_common(1)[0][0]
                alert("auth", "amber", "Repeated failed sign-ins",
                      "%d wrong passwords in 5 minutes, via %s." % (len(a5), c))
            top = Counter(s for t, s, p in drops if now - t <= 3600).most_common(3)
            recent = [{"t": int(t), "src": s, "port": p} for t, s, p in list(drops)[-5:]]
            if upd["security_pending"] and upd["pending_since"]:
                late = now - upd["pending_since"] >= UPD_RED
                alert("upd:" + ("red" if late else "amber"), "red" if late else "amber",
                      "Security fixes not installed" if late else "Security fixes waiting",
                      "%d package(s) with a security fix: %s." % (upd["security_pending"], ", ".join(upd["packages"][:4])))
            if upd["reboot_required"]:
                alert("reboot", "amber", "Restart to finish security fixes",
                      "A fix (for example to the kernel) takes effect only after a restart. Save your work and restart.")
            try:                                          # outside vulnerability information (zenos-vulnwatch)
                vs = json.load(open("/run/zenos/vuln.json")).get("summary") or {}
            except Exception:
                vs = {}
            if vs.get("kev_affected"):
                alert("vuln:kev", "red", "Exploited vulnerability on this PC",
                      "%d part(s) affected by vulnerabilities known to be exploited (CISA KEV). Details: "
                      "zenos_vulnwatch.py show." % int(vs["kev_affected"]))
            elif vs.get("affected"):
                alert("vuln", "amber", "Vulnerabilities waiting for a fix",
                      "%d part(s) affected; none is known to be exploited yet." % int(vs["affected"]))
            ust = dict(upd)
            al = list(alerts)
        hist_in.append(0 if prev_in is None else max(0, blocked - prev_in)); prev_in = blocked
        hist_auth.append(max(0, at - prev_auth)); prev_auth = at
        state = {"t": int(now), "since": int(start), "firewall": fw_ok,
                 "remote": [{"what": w, "peer": p} for w, p in remote],
                 "inbound_blocked": blocked, "outbound_contained": max(0, tout - base_out) + contained_total,
                 "auth_failed": at, "h_in": list(hist_in), "h_auth": list(hist_auth),
                 "top_sources": [{"src": s, "n": n} for s, n in top], "recent": recent, "alerts": al, "updates": ust,
                 "trust": trust_summary(trust), "vuln": vs}
        tmp = OUT + ".tmp"
        with open(tmp, "w") as f:
            json.dump(state, f)
        os.chmod(tmp, 0o644)
        os.replace(tmp, OUT)
        time.sleep(2)


if __name__ == "__main__":
    main()
