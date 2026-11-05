#!/usr/bin/env python3
"""ZENOS audit shipping (root): sends this PC's tamper-evident ledgers to the audit nodes, as they grow, every 10 seconds, with a
signed status of the PC (kernel running and installed, protecting services running).

Once a record has reached a node, rewriting it on this PC is detected there (the node refuses the changed history
and raises an alert). Batches are signed with this PC's audit key (/etc/zenos/audit-device.key, root only); the
node's signed receipts are kept in /var/lib/zenos/audit-receipts.jsonl.

Configuration: /etc/zenos/audit.json
  {"machine": "pc-0042",                         (optional; default: from /etc/machine-id)
   "nodes": [{"name": "Ministry audit", "url": "https://audit.example.go.jp:8443", "pub": "<node key>"}],
   "ledgers": {"guard": "/var/log/zenos/access-ledger.jsonl",
               "user-*": "/home/*/.local/share/zenos/ledger.jsonl"}}      ("*" = the user name)
  zenos_auditship.py --show-key     the line to enroll this PC on a node
  zenos_auditship.py --once         ship once and exit
"""
import base64, glob, hashlib, json, os, re, ssl, subprocess, sys, time, urllib.request, urllib.error
from pathlib import Path
from urllib.parse import urlparse
sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "lib", "zenos"))
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "lib"))
import zident                                                    # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

CONF = Path(os.environ.get("ZENOS_AUDIT_CONF", "/etc/zenos/audit.json"))
KEY = Path(os.environ.get("ZENOS_AUDIT_KEY", "/etc/zenos/audit-device.key"))
STATE = Path(os.environ.get("ZENOS_AUDIT_STATE", "/var/lib/zenos/audit-ship.json"))
RECEIPTS = STATE.with_name("audit-receipts.jsonl")
LOG = Path(os.environ.get("ZENOS_AUDIT_LOG", "/var/log/zenos/guard.jsonl"))
HALT = Path(os.environ.get("ZENOS_HALT", "/var/lib/zenos/halt.json"))      # written by zenos-guardd
DEFAULT_LEDGERS = {"guard": "/var/log/zenos/access-ledger.jsonl", "user-*": "/home/*/.local/share/zenos/ledger.jsonl"}
BATCH = 500
EVERY = float(os.environ.get("ZENOS_AUDIT_EVERY", "10"))   # seconds between shipments; the guard chain always sends
WATCHED = ("zenos-keyd", "zenos-guardd", "zenos-aiguard", "zenos-netsentinel", "zenos-firewall")
SIGNED = ("machine", "chain", "from", "records")


def _vkey(s):
    return [int(x) if x.isdigit() else x for x in re.split(r"(\d+)", s)]


def status():
    """what the audit nodes should see about this PC besides its ledger: the kernel running and the newest one
    installed (a fix works only after a restart), and whether the protecting services are running"""
    ks = [os.path.basename(p)[len("vmlinuz-"):] for p in glob.glob("/boot/vmlinuz-*")]
    try:
        r = subprocess.run(["systemctl", "is-active"] + [u + ".service" for u in WATCHED],
                           capture_output=True, text=True, timeout=10).stdout.split()
    except Exception:
        r = []
    r += ["unknown"] * (len(WATCHED) - len(r))
    try:
        halted = json.loads(HALT.read_text()).get("status") == "halted"
    except FileNotFoundError:
        halted = False
    except Exception:
        halted = True                                   # unreadable stop file: reported as stopped, as keyd treats it
    try:                                                # counts only (zenos-vulnwatch): affected, KEV, fixed
        vuln = {k: int(v) for k, v in (json.load(open("/run/zenos/vuln.json")).get("summary") or {}).items()}
    except Exception:
        vuln = None
    return {"t": int(time.time()), "vuln": vuln, "kernel": os.uname().release, "kernel_newest": max(ks, key=_vkey) if ks else None,
            "reboot_required": os.path.exists("/run/reboot-required"), "services": dict(zip(WATCHED, r[:len(WATCHED)])),
            "halted": halted}


def sign(key, b):
    """the batch signature covers what every audit node checks; the status has its own signature, so a node that
    does not know about it yet still accepts the batch"""
    b["sig"] = base64.b64encode(key.sign(hashlib.sha256(canon({k: b[k] for k in SIGNED})).digest())).decode()
    if "status" in b:
        b["status_sig"] = base64.b64encode(key.sign(hashlib.sha256(canon({"machine": b["machine"], "status": b["status"]})).digest())).decode()
    return b


def canon(o):
    return json.dumps(o, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def log(**kw):
    kw = {"t": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **kw}
    try:
        LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(LOG, "a") as f:
            f.write(json.dumps(kw, ensure_ascii=False) + "\n")
    except OSError:
        pass
    print(json.dumps(kw, ensure_ascii=False), flush=True)


_said = {}


def once(key, every, **kw):
    """log a recurring problem when it starts, then at most once per `every` seconds"""
    if time.time() - _said.get(key, 0) > every:
        _said[key] = time.time()
        log(**kw)


def device_key():
    """the PC's identity (zident): the TPM key when /etc/zenos/identity.json says so, otherwise the key file"""
    if zident.CONF.exists():
        return zident.load()
    return zident.FileIdentity(KEY)


def conf():
    try:
        c = json.loads(CONF.read_text())
    except (OSError, ValueError):
        c = {}
    if not c.get("machine"):
        try:
            c["machine"] = "pc-" + Path("/etc/machine-id").read_text().strip()[:12]
        except OSError:
            c["machine"] = "pc-unknown"
    c.setdefault("nodes", [])
    c.setdefault("ledgers", DEFAULT_LEDGERS)
    return c


def ledgers(c):
    """chain name -> file"""
    out = {}
    for name, pat in c["ledgers"].items():
        if "*" in name:
            for p in glob.glob(pat):
                user = Path(p).relative_to(Path(pat.split("*")[0])).parts[0]
                out[name.replace("*", user)] = p
        elif os.path.exists(pat):
            out[name] = pat
    return out


def read_records(p):
    with open(p, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


def post(url, body):
    u = urlparse(url)
    if u.scheme != "https" and u.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("audit nodes must be reached over https")
    req = urllib.request.Request(url.rstrip("/") + "/v1/batch", data=json.dumps(body, ensure_ascii=False).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20, context=ssl.create_default_context() if u.scheme == "https" else None) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def ship_once(c, key, state):
    now = status()
    for node in c["nodes"]:
        try:
            npub = Ed25519PublicKey.from_public_bytes(base64.b64decode(node["pub"]))
        except Exception:
            log(event="audit-node-misconfigured", node=node.get("name"))
            continue
        st = state.setdefault(node["url"], {})
        for chain, path in ledgers(c).items():
            try:
                recs = read_records(path)
            except (OSError, ValueError):
                continue
            for attempt in range(50):                             # until this node has everything
                frm = min(st.get(chain, 0), len(recs))
                if frm >= len(recs) and (attempt or chain != "guard"):
                    break                                         # (the guard chain always sends: a heartbeat)
                b = {"machine": c["machine"], "chain": chain, "from": frm, "records": recs[frm:frm + BATCH]}
                if chain == "guard":
                    b["status"] = now
                sign(key, b)
                try:
                    code, ans = post(node["url"], b)
                except Exception as e:
                    once(("down", node["url"]), 3600, event="audit-node-unreachable", node=node.get("name"), error=str(e)[:120])
                    return
                if _said.pop(("down", node["url"]), None):
                    log(event="audit-node-reachable", node=node.get("name"))
                if code == 200 and ans.get("ok"):
                    try:
                        npub.verify(base64.b64decode(ans["sig"]), canon(ans["receipt"]))
                    except Exception:
                        log(event="audit-receipt-invalid", node=node.get("name"), chain=chain)
                        return
                    st[chain] = ans["receipt"]["count"]
                    if ans.get("added"):
                        with open(RECEIPTS, "a") as f:
                            f.write(json.dumps({"node": node.get("name"), **ans}, ensure_ascii=False) + "\n")
                    if frm >= len(recs):
                        break
                elif code == 409 and "need" in ans:                 # the node holds less (or a restart): resend from there
                    st[chain] = int(ans["need"])
                else:
                    once(("refused", node["url"], chain, ans.get("error")), 3600, event="audit-node-refused", node=node.get("name"),
                         chain=chain, code=code, error=str(ans.get("error"))[:120], index=ans.get("index"))
                    break
    STATE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE.with_name(STATE.name + ".tmp")
    tmp.write_text(json.dumps(state))
    os.replace(tmp, STATE)


def main():
    key = device_key()
    c = conf()
    if "--show-key" in sys.argv:
        pub = base64.b64encode(key.pub()).decode()
        return print(f"zenos_auditnode.py --store <dir> --enroll {c['machine']} {pub}")
    try:
        state = json.loads(STATE.read_text())
    except (OSError, ValueError):
        state = {}
    while True:
        ship_once(conf(), key, state)
        if "--once" in sys.argv:
            return
        time.sleep(EVERY)


if __name__ == "__main__":
    main()
