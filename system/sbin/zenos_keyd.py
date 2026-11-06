#!/usr/bin/env python3
"""ZENOS key agent (root): holds the level keys and does every seal and unseal for the desktop users.

Without it the level keys sit in each user's home, so anyone could decrypt any level with a few lines of Python.
Here the keys belong to root (/var/lib/zenos/keys). A user gets plaintext only for files at or below their clearance
(set by the administrator in /etc/zenos/clearance), or for one exact file with a grant their officers signed
(verified here against the enrolled keys in /etc/zenos/approvers). Nothing is opened while the PC is stopped.
The decision itself is taken by the proven program zenos-decide (zdecide, formal/); this agent checks the signatures
and digests it relies on. Every unseal is written to the root ledger, which zenos-auditship sends off the machine.

  zenos_keyd.py                      run the agent (systemd: zenos-keyd.service)
  zenos_keyd.py --clearance USER N   set a user's clearance (1-5)
  zenos_keyd.py --reseal-dry DIR...  list the sealed files whose key is still on this PC
  zenos_keyd.py --reseal DIR...      seal them again through the key service, in place
  zenos_keyd.py --drop-local-keys --yes   destroy the keys kept on this PC (after --reseal)
Protocol: one JSON line per connection on /run/zenos/keyd.sock; the caller is identified by SO_PEERCRED.
"""
import base64, hashlib, json, os, pwd, re, socket, struct, subprocess, sys, threading, time
from pathlib import Path

# the ZENOS library is ../lib/zenos beside this program (/usr/lib/zenos, root-owned)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "lib", "zenos"))
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
try:
    import zledger
except Exception:
    zledger = None
try:
    import zfrag
except Exception:
    zfrag = None
import zdecide
import zkeysvc

KEYS = Path(os.environ.get("ZENOS_KEYD_KEYS", "/var/lib/zenos/keys"))
CLEARANCE = Path(os.environ.get("ZENOS_CLEARANCE", "/etc/zenos/clearance"))
APPROVERS = Path(os.environ.get("ZENOS_APPROVERS", "/etc/zenos/approvers"))
SOCK = os.environ.get("ZENOS_KEYD_SOCK", "/run/zenos/keyd.sock")
LOG = Path(os.environ.get("ZENOS_KEYD_LOG", "/var/log/zenos/keyd.jsonl"))
LEDGER = os.environ.get("ZENOS_KEYD_LEDGER", "/var/log/zenos/access-ledger.jsonl")
HALT = Path(os.environ.get("ZENOS_HALT", "/var/lib/zenos/halt.json"))      # written by zenos-guardd
EXPOSED = Path(os.environ.get("ZENOS_EXPOSED", "/run/zenos/exposed.json"))  # read by zenos-aiguard
AIGUARD_SOCK = os.environ.get("ZENOS_AIGUARD_SOCK", "/run/zenos/aiguard.sock")
# the AI guard counts as installed when its service unit is; then a missing socket means it is not running, and L3+
# files stay closed (only a development layout without the unit opens them without it)
AIGUARD_UNITS = [u for u in os.environ.get("ZENOS_AIGUARD_UNIT", "/lib/systemd/system/zenos-aiguard.service:"
                                           "/usr/lib/systemd/system/zenos-aiguard.service:"
                                           "/etc/systemd/system/zenos-aiguard.service").split(":") if u]
# who holds L4+ plaintext: the process that asked for it (pid and start time, from the socket), read by the network
# sentinel, which keeps the network cut while that process or anything it started is alive
HOLDERS = Path(os.environ.get("ZENOS_OPEN_HOLDERS", "/run/zenos/open-holders.json"))
MAGIC = b"ZENOS1\n"
LABEL = {1: "Public", 2: "Confidentiality 2", 3: "Confidentiality 3",
         4: "Important Economic Security Information", 5: "Specially Designated Secret"}
MAX = 64 * 1024 * 1024


def log(**kw):
    kw = {"t": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **kw}
    try:
        LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(LOG, "a") as f:
            f.write(json.dumps(kw, ensure_ascii=False) + "\n")
    except OSError:
        pass
    if zledger is not None:
        try:
            zledger.append(LEDGER, kw.get("event", "keyd"), kw.get("user", "keyd"), "keyd",
                           **{k: v for k, v in kw.items() if k not in ("t", "event", "user")})
        except Exception:
            pass


def keysvc_in_use():
    try:
        return zkeysvc.conf() is not None
    except zkeysvc.Unavailable:
        return True                      # configured but unusable: still never make keys on the PC


def ensure_keys():
    KEYS.mkdir(parents=True, exist_ok=True)
    os.chmod(KEYS, 0o700)
    # with a key service, no level key is made on the PC (old ones stay until --drop-local-keys)
    for n in ([] if keysvc_in_use() else range(1, 6)):
        p = KEYS / f"L{n}.key"
        if not p.exists():
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(AESGCM.generate_key(bit_length=256))
    sk = KEYS / "device_ed25519"
    if not sk.exists():
        k = Ed25519PrivateKey.generate()
        fd = os.open(sk, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))
        (KEYS / "device_ed25519.pub").write_bytes(k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    (KEYS / "frag").mkdir(exist_ok=True)
    os.chmod(KEYS / "frag", 0o700)


def clearance(user):
    try:
        for line in CLEARANCE.read_text().splitlines():
            k, _, v = line.partition("=")
            if k.strip() == user:
                return max(1, min(5, int(v.strip())))
    except (OSError, ValueError):
        pass
    return 1                                    # not cleared: public files only, the rest goes through approval


def set_clearance(user, n):
    pwd.getpwnam(user)
    n = int(n)
    if not 1 <= n <= 5:
        sys.exit("The clearance is a level from 1 to 5.")
    lines = []
    try:
        lines = [l for l in CLEARANCE.read_text().splitlines() if l.partition("=")[0].strip() != user]
    except OSError:
        pass
    lines.append(f"{user} = {n}")
    CLEARANCE.parent.mkdir(parents=True, exist_ok=True)
    tmp = CLEARANCE.with_name(".clearance.tmp")
    tmp.write_text("\n".join(lines) + "\n")
    os.chmod(tmp, 0o644)
    os.replace(tmp, CLEARANCE)
    log(event="clearance-set", user=user, level=n, by="root")
    print(f"{user}: clearance L{n}")


def device_pub():
    return (KEYS / "device_ed25519.pub").read_bytes()


def seal(data, level, name, author):
    base = {"zenos": 1, "level": level, "label": LABEL[level], "name": name,
            "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "author": author}
    ks = zkeysvc.conf()
    if ks:
        # the key service holds the key: the PC keeps none (raises zkeysvc.Unavailable / Refused: nothing is sealed)
        fid, dek = zkeysvc.new_file_key(author, level, name, ks)
        header = {**base, "alg": "AES-256-GCM", "fmt": zkeysvc.FMT, "fid": fid,
                  "ks": zkeysvc.fingerprint(zkeysvc.unb64(ks["pub"])), "nonce": base64.b64encode(os.urandom(12)).decode()}
        hb = json.dumps(header, ensure_ascii=False, sort_keys=True).encode()
        ct = AESGCM(dek).encrypt(base64.b64decode(header["nonce"]), data, hb)
        del dek
    elif zfrag is not None:
        header = {**base, "alg": "AES-256-GCM-fragmented", "fmt": "zfrag2"}
        hb = json.dumps(header, ensure_ascii=False, sort_keys=True).encode()
        ct = zfrag.seal(data, level, name, str(KEYS / "frag"))
    else:
        header = {**base, "alg": "AES-256-GCM", "nonce": base64.b64encode(os.urandom(12)).decode()}
        hb = json.dumps(header, ensure_ascii=False, sort_keys=True).encode()
        ct = AESGCM((KEYS / f"L{level}.key").read_bytes()).encrypt(base64.b64decode(header["nonce"]), data, hb)
    sk = Ed25519PrivateKey.from_private_bytes((KEYS / "device_ed25519").read_bytes())
    sig = sk.sign(hb + hashlib.sha256(ct).digest())
    blob = MAGIC + hb + b"\n" + base64.b64encode(sig) + b"\n" + ct
    if ks:
        try:
            zkeysvc.sealed(fid, hashlib.sha256(blob).hexdigest(), ks)   # grants name the file by this digest
        except Exception:
            log(event="keysvc-sealed-unrecorded", user=author, fid=fid)
    return blob


def parse_verify(blob):
    if not blob.startswith(MAGIC):
        raise ValueError("not a ZENOS file")
    hb, rest = blob[len(MAGIC):].split(b"\n", 1)
    sig, ct = rest.split(b"\n", 1)
    Ed25519PublicKey.from_public_bytes(device_pub()).verify(base64.b64decode(sig), hb + hashlib.sha256(ct).digest())
    return json.loads(hb), hb, ct


def unseal(h, hb, ct, dek=None):
    if h.get("fmt") == zkeysvc.FMT:
        return AESGCM(dek).decrypt(base64.b64decode(h["nonce"]), ct, hb)
    if h.get("fmt") == "zfrag2":
        return zfrag.open_full(ct, str(KEYS / "frag"))
    return AESGCM((KEYS / f"L{h['level']}.key").read_bytes()).decrypt(base64.b64decode(h["nonce"]), ct, hb)


def roster():
    """the officers enrolled by the administrator"""
    return sorted(p.stem for p in APPROVERS.glob("*.pub")) if APPROVERS.is_dir() else []


def halted():
    try:
        return json.loads(HALT.read_text()).get("status") == "halted"
    except FileNotFoundError:
        return False
    except Exception:
        return True                                 # a stop file that cannot be read: treat the PC as stopped


def grant_facts(g):
    """what the decision needs from a grant, with its digest and every signature checked here"""
    if not isinstance(g, dict) or not isinstance(g.get("core"), dict):
        return None
    try:
        core = g["core"]
        digest = hashlib.sha256(json.dumps(core, sort_keys=True, ensure_ascii=False).encode()).digest()
        approvals = []
        for a in g.get("approvals", []):
            name = os.path.basename(str(a.get("approver", "")))
            try:
                Ed25519PublicKey.from_public_bytes((APPROVERS / f"{name}.pub").read_bytes()).verify(
                    base64.b64decode(a["sig"]), digest)
                ok = True
            except Exception:
                ok = False
            approvals.append({"approver": name, "sig_ok": ok})
        return {"requester": str(core.get("requester", "")), "holder": str(g.get("requester", "")),
                "file_hash": str(core.get("file_hash", "")), "level": int(core.get("level", 0)),
                "kind": core.get("kind"), "expires": zkeysvc.grant_expiry(g),
                "digest_ok": base64.b64decode(g.get("digest", "")) == digest, "approvals": approvals}
    except Exception:
        return None


EXPOSE_LOCK = threading.Lock()


def expose(level):
    """Record that content of `level` is now in plaintext on this PC (the highest level since boot), and, when that
    takes an AI out of reach (L3 and above), wait for zenos-aiguard to confirm its packet-filter rules first.
    False: the guard is installed but did not confirm, so the file must stay closed."""
    with EXPOSE_LOCK:
        try:
            cur = int(json.loads(EXPOSED.read_text())["level"])
        except FileNotFoundError:
            cur = 0
        except Exception:
            cur = 5
        if level > cur:
            try:
                EXPOSED.parent.mkdir(parents=True, exist_ok=True)
                tmp = EXPOSED.with_name(EXPOSED.name + ".tmp")
                tmp.write_text(json.dumps({"level": level, "t": time.time()}))
                os.chmod(tmp, 0o644)
                os.replace(tmp, EXPOSED)
            except OSError:
                return level < 3             # unrecorded: from L3 the file stays closed
        if level < 3:
            return True
        if not os.path.exists(AIGUARD_SOCK):
            return not any(os.path.exists(u) for u in AIGUARD_UNITS)   # installed but not running: closed
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect(AIGUARD_SOCK)
            s.sendall(b'{"op": "sync"}\n')
            buf = b""
            while not buf.endswith(b"\n"):
                c = s.recv(4096)
                if not c:
                    break
                buf += c
            s.close()
            a = json.loads(buf or b"{}")
            return a.get("ok") is True and int(a.get("level", 0)) >= level
        except Exception:
            return False


def _start_time(pid):
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
    except (OSError, IndexError):
        return None


def socket_holders(ino, uid):
    """every process that holds the client end of our connection `ino` (the connector may have handed the socket to
    another process, or exited): from the kernel's socket table (ss -xp). Without that table, every process of the
    uid counts (stricter, never looser)."""
    pids = set()
    try:
        out = subprocess.run(["ss", "-xpnH"], capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            f = line.split()
            # Netid State Recv-Q Send-Q Local Port Peer Port Process
            if len(f) >= 8 and f[7] == str(ino):
                pids.update(int(x) for x in re.findall(r"pid=(\d+)", line))
        if pids:
            return pids
    except (OSError, subprocess.SubprocessError):
        pass
    for d in os.listdir("/proc"):
        if d.isdigit():
            try:
                if os.stat(f"/proc/{d}").st_uid == uid:
                    pids.add(int(d))
            except OSError:
                pass
    return pids


def hold(pid, uid, level, ino=None):
    """note the processes that now hold plaintext of `level` (the sentinel cuts the network from L4 while any of
    them, or anything they start, lives): every process holding our connection's client end, and the connector.
    False when none is alive to hold it (the plaintext is then not given). This file is written only here."""
    if level < 4:
        return True
    pids = (socket_holders(ino, uid) if ino else set()) | ({pid} if pid else set())
    recs = [{"pid": p, "uid": uid, "start": _start_time(p), "level": level, "t": time.time()} for p in sorted(pids)]
    recs = [r for r in recs if r["start"]]
    if not recs:
        return False
    with EXPOSE_LOCK:
        try:
            cur = json.loads(HOLDERS.read_text())
        except Exception:
            cur = []
        cur = [h for h in cur if isinstance(h, dict) and _start_time(h.get("pid", 0)) == h.get("start")] + recs
        try:
            HOLDERS.parent.mkdir(parents=True, exist_ok=True)
            tmp = HOLDERS.with_name(HOLDERS.name + ".tmp")
            tmp.write_text(json.dumps(cur))
            os.chmod(tmp, 0o644)
            os.replace(tmp, HOLDERS)
        except OSError:
            return False
    return True


def handle(msg, uid, pid=0, ino=None):
    user = pwd.getpwuid(uid).pw_name
    op = msg.get("op")
    if op == "whoami":
        return {"ok": True, "user": user, "clearance": clearance(user), "device": base64.b64encode(device_pub()).decode()}
    if op == "seal":
        level = int(msg.get("level", 0))
        if level not in LABEL:
            return {"ok": False, "error": "bad level"}
        if level > clearance(user):   # the device signature vouches for the label: only someone cleared for it may set it
            log(event="seal-refused", user=user, level=level, clearance=clearance(user))
            return {"ok": False, "error": "clearance",
                    "message": "You are not cleared for L%d, so you cannot seal a file at that level." % level}
        data = base64.b64decode(msg.get("data", ""))
        name = re.sub(r'[/\\\n\r\t]', "", str(msg.get("name", "")))[:200] or "Untitled"
        try:
            blob = seal(data, level, name, user)
        except zkeysvc.Refused as e:
            log(event="seal-refused", user=user, level=level, reason="keysvc:" + e.error)
            return {"ok": False, "error": "keysvc", "message": KEYSVC_MSG.get(e.error, KEYSVC_MSG["other"])}
        except zkeysvc.Unavailable as e:
            log(event="seal-refused", user=user, level=level, reason="keysvc-unavailable", detail=str(e)[:120])
            return {"ok": False, "error": "keysvc", "message": KEYSVC_MSG["unavailable"]}
        log(event="seal", user=user, level=level, name=name, sha256=hashlib.sha256(blob).hexdigest()[:16],
            **({"fid": json.loads(blob[len(MAGIC):].split(b"\n", 1)[0]).get("fid")}
               if b'"fmt": "zks1"' in blob[:4096] else {}))
        return {"ok": True, "blob": base64.b64encode(blob).decode()}
    if op in ("verify", "open"):
        blob = base64.b64decode(msg.get("blob", ""))
        try:
            h, hb, ct = parse_verify(blob)
        except Exception:
            return {"ok": False, "error": "signature", "message": "This file failed the signature check."}
        if op == "verify":
            return {"ok": True, "header": h}
        level, cl = int(h["level"]), clearance(user)
        fh = hashlib.sha256(blob).hexdigest()
        stopped = halted()
        allowed, how, why = zdecide.open_file(user, cl, level, fh, stopped, roster(), grant_facts(msg.get("grant")))
        if not allowed:
            log(event="unseal-refused", user=user, level=level, clearance=cl, name=h.get("name"), sha256=fh[:16],
                reason=why)
            if why == "halted":
                return {"ok": False, "error": "halted",
                        "message": "This PC is stopped after an anomaly. Nothing can be opened until the release is approved."}
            return {"ok": False, "error": "level", "message": f"This file is L{level}; your clearance is L{cl}."}
        if not expose(level):
            log(event="unseal-refused", user=user, level=level, clearance=cl, name=h.get("name"), sha256=fh[:16],
                reason="aiguard")
            return {"ok": False, "error": "aiguard",
                    "message": "The AI guard did not confirm its network rules, so this file stays closed. Try again in a moment."}
        dek, fid = None, None
        if h.get("fmt") == zkeysvc.FMT:
            fid = str(h.get("fid", ""))
            try:     # the key service decides again with its own facts, and records the release on its side at once
                dek, ans = zkeysvc.open_key(user, fid, level, grant=msg.get("grant"), presence=msg.get("presence"))
                how = ans.get("by") or how
            except zkeysvc.Refused as e:
                log(event="unseal-refused", user=user, level=level, clearance=cl, name=h.get("name"), sha256=fh[:16],
                    fid=fid, reason="keysvc:" + e.error)
                out = {"ok": False, "error": "keysvc-" + e.error, "message": KEYSVC_MSG.get(e.error, KEYSVC_MSG["other"])}
                if e.error == "presence":
                    try:
                        c = zkeysvc.challenge(user, fid, level)
                        # the key service sent the person's phone a link to its own page, which shows the file as
                        # the service knows it; once confirmed there, open again with presence {"challenge": ...}
                        out.update(challenge=c["challenge"], confirm_sent=bool(c.get("sent")), fid=fid)
                        if not c.get("sent"):
                            out["message"] = KEYSVC_MSG["presence-unsent"]
                    except Exception:
                        pass
                return out
            except zkeysvc.Unavailable as e:
                log(event="unseal-refused", user=user, level=level, clearance=cl, name=h.get("name"), sha256=fh[:16],
                    fid=fid, reason="keysvc-unavailable", detail=str(e)[:120])
                return {"ok": False, "error": "keysvc-unavailable", "message": KEYSVC_MSG["unavailable"]}
        try:
            data = unseal(h, hb, ct, dek)
        except Exception:
            log(event="unseal-refused", user=user, level=level, name=h.get("name"), sha256=fh[:16], fid=fid,
                reason="key-mismatch")
            return {"ok": False, "error": "key", "message": "The key for this file did not fit: its level or id was changed."}
        dek = None
        if not hold(pid, uid, level, ino):
            log(event="unseal-refused", user=user, level=level, name=h.get("name"), sha256=fh[:16], reason="no-holder")
            return {"ok": False, "error": "holder", "message": "The program that asked is gone; the file stays closed."}
        log(event="unseal", user=user, level=level, by=how, name=h.get("name"), sha256=fh[:16],
            **({"fid": fid} if fid else {}))
        return {"ok": True, "header": h, "data": base64.b64encode(data).decode()}
    if op == "clip-put":       # copy inside sealed L3+ windows: held here in RAM, never on the X11 clipboard
        level = int(msg.get("level", 0))
        text = str(msg.get("text", ""))
        if level not in LABEL or len(text) > CLIP_MAX:
            return {"ok": False, "error": "bad clip"}
        with CLIP_LOCK:
            CLIPS[uid] = {"level": level, "text": text, "t": time.time()}
        log(event="clip-put", user=user, level=level, chars=len(text))
        return {"ok": True}
    if op == "clip-get":       # paste: only into a window of the same level or higher, for a while
        level = int(msg.get("level", 0))
        with CLIP_LOCK:
            c = CLIPS.get(uid)
            if c and time.time() - c["t"] > CLIP_TTL:
                CLIPS.pop(uid, None)
                c = None
        if not c or not zdecide.flow(c["level"], "window", level):
            return {"ok": True, "text": None}
        return {"ok": True, "text": c["text"], "level": c["level"], "t": c["t"]}
    return {"ok": False, "error": "unknown op"}


KEYSVC_MSG = {
    "unavailable": "The key service cannot be reached, so this file stays closed. The keys of sealed files are not kept on this PC.",
    "silent": "The key service has not heard from this PC's audit shipping recently, so it gives out no keys.",
    "unhealthy": "One of this PC's protecting services is not running, so the key service gives out no keys.",
    "halted": "This PC is stopped after an anomaly. Nothing can be opened until the release is approved.",
    "rate": "Too many files were opened from this PC in a short time. Wait a minute and try again.",
    "presence": "The key service sent a confirmation to your phone in ZENOS Messages. Check the file name there, confirm, then open the file again.",
    "presence-unsent": "This file needs a confirmation on your phone, but the key service has no Messages account for you. Ask your administrator.",
    "clearance": "Your clearance, as the key service holds it, does not cover this level.",
    "unknown-file": "The key service does not know this file, or it was sealed on another PC.",
    "not-assigned": "The key service does not list you as a user of this PC.",
    "other": "The key service refused this request.",
}

CLIPS, CLIP_LOCK = {}, threading.Lock()
CLIP_MAX = 2_000_000
CLIP_TTL = 30 * 60


def client(c):
    try:
        cred = c.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        pid, uid, gid = struct.unpack("3i", cred)
        c.settimeout(30)
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = c.recv(1 << 20)
            if not chunk:
                break
            buf += chunk
            if len(buf) > MAX * 4 // 3 + 4096:
                raise ValueError("too large")
        out = handle(json.loads(buf or b"{}"), uid, pid, os.fstat(c.fileno()).st_ino)
    except Exception:
        out = {"ok": False, "error": "bad request"}
    try:
        c.sendall((json.dumps(out) + "\n").encode())
    except OSError:
        pass
    c.close()


RESEAL_STATE = Path(os.environ.get("ZENOS_RESEAL_STATE", "/var/lib/zenos/reseal.json"))


def _open_dir_nofollow(path):
    """a descriptor for `path`, opened one component at a time without following any symbolic link, so a user who
    swaps a folder for a link while this runs cannot point the root-owned writes elsewhere"""
    parts = [x for x in os.path.abspath(path).split("/") if x]
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for x in parts:
            nfd = os.open(x, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nfd
        return fd
    except BaseException:
        os.close(fd)
        raise


def sealed_files(paths):
    for top in paths:
        walk = os.walk(top, followlinks=False) if os.path.isdir(top) else [(os.path.dirname(top) or ".", [], [os.path.basename(top)])]
        for root, dirs, files in walk:
            for f in files:
                p = os.path.join(root, f)
                try:
                    if os.path.islink(p) or not os.path.isfile(p):
                        continue
                    with open(p, "rb") as fh:
                        if fh.read(len(MAGIC)) == MAGIC:
                            yield p
                except OSError:
                    continue


def _reseal_one(p):
    """returns "sealed", "already" or raises"""
    dfd = _open_dir_nofollow(os.path.dirname(p) or ".")
    name = os.path.basename(p)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dfd)
        with os.fdopen(fd, "rb") as fh:
            st = os.fstat(fh.fileno())
            if not __import__("stat").S_ISREG(st.st_mode):
                raise ValueError("not a regular file")
            blob = fh.read()
        h, hb, ct = parse_verify(blob)
        if h.get("fmt") == zkeysvc.FMT:
            return "already", h, blob, blob
        data = unseal(h, hb, ct)
        new = seal(data, int(h["level"]), h.get("name") or name, str(h.get("author") or "root"))
        tmp = ".%s.zenos-reseal-%s" % (name, os.urandom(6).hex())
        wfd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, st.st_mode & 0o7777, dir_fd=dfd)
        try:
            with os.fdopen(wfd, "wb") as f:
                f.write(new)
                f.flush()
                os.fchown(f.fileno(), st.st_uid, st.st_gid)
                os.fchmod(f.fileno(), st.st_mode & 0o7777)
                os.fsync(f.fileno())
            cur = os.stat(name, dir_fd=dfd, follow_symlinks=False)
            if (cur.st_ino, cur.st_dev) != (st.st_ino, st.st_dev):
                raise ValueError("the file changed while it was being sealed again")
            os.replace(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
            os.fsync(dfd)
        except BaseException:
            try:
                os.unlink(tmp, dir_fd=dfd)
            except OSError:
                pass
            raise
        return "sealed", h, blob, new
    finally:
        os.close(dfd)


def reseal(paths, dry=False):
    """Seal again, through the key service, every sealed file under `paths` whose key is still on this PC.
    The new file replaces the old one in place (same name, owner and mode); the author and level are kept.
    Returns how many are left with a key on this PC (files that could not be read or sealed count as left)."""
    if not zkeysvc.conf():
        sys.exit("No key service is configured (/etc/zenos/keysvc.json).")
    done = left = 0
    for p in sealed_files(paths):
        try:
            if dry:
                h, _, _ = parse_verify(Path(p).read_bytes())
                if h.get("fmt") != zkeysvc.FMT:
                    print(f"would  {p}  L{h['level']}  {h.get('author')}")
                    left += 1
                continue
            r, h, old, new = _reseal_one(p)
        except Exception as e:
            print(f"left   {p}: {type(e).__name__}: {e}")
            left += 1
            continue
        if r == "already":
            continue
        log(event="reseal", user=str(h.get("author")), level=int(h["level"]), name=h.get("name"),
            old=hashlib.sha256(old).hexdigest()[:16], new=hashlib.sha256(new).hexdigest()[:16],
            fid=json.loads(new[len(MAGIC):].split(b"\n", 1)[0]).get("fid"))
        print(f"sealed {p}  L{h['level']}")
        done += 1
    print(f"{done} file(s) sealed through the key service, {left} left with a key on this PC.")
    if not dry:
        RESEAL_STATE.parent.mkdir(parents=True, exist_ok=True)
        RESEAL_STATE.write_text(json.dumps({"t": time.time(), "paths": [os.path.abspath(x) for x in paths], "left": left}))
    return left


def drop_local_keys():
    """Destroy the level and fragment keys kept on this PC. Files still sealed with them can no longer be opened."""
    if not zkeysvc.conf():
        sys.exit("No key service is configured: the keys on this PC are the only ones.")
    try:
        st = json.loads(RESEAL_STATE.read_text())
    except (OSError, ValueError):
        st = None
    if not st or st.get("left") != 0:
        sys.exit("Run --reseal first, until it reports 0 files left. Files on USB sticks, backups and other PCs that "
                 "were not sealed again cannot be opened after this.")
    print("Sealed again under: " + ", ".join(st.get("paths", [])))
    gone = 0
    for p in list(KEYS.glob("L*.key")) + [q for q in (KEYS / "frag").rglob("*") if q.is_file()]:
        n = p.stat().st_size
        with open(p, "r+b") as f:
            f.write(os.urandom(n))
            f.flush()
            os.fsync(f.fileno())
        p.unlink()
        gone += 1
    log(event="local-keys-dropped", user="root", count=gone)
    print(f"{gone} key file(s) destroyed. New files are sealed only through the key service.")


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "--clearance":
        return set_clearance(sys.argv[2], sys.argv[3])
    if len(sys.argv) >= 3 and sys.argv[1] in ("--reseal", "--reseal-dry"):
        sys.exit(1 if reseal(sys.argv[2:], dry=sys.argv[1] == "--reseal-dry") else 0)
    if sys.argv[1:] == ["--drop-local-keys", "--yes"]:
        return drop_local_keys()
    if sys.argv[1:2] == ["--drop-local-keys"]:
        sys.exit("This destroys the keys on this PC; files not yet sealed again cannot be opened afterwards.\n"
                 "Run --reseal-dry first, then: zenos_keyd.py --drop-local-keys --yes")
    ensure_keys()
    os.makedirs(os.path.dirname(SOCK), exist_ok=True)
    os.chmod(os.path.dirname(SOCK), 0o755)   # with the unit's UMask=0077 it would be 0700: no user could reach the socket
    try:
        os.unlink(SOCK)
    except OSError:
        pass
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(SOCK)
    os.chmod(SOCK, 0o666)                 # anyone may ask; the answer depends on who asks (SO_PEERCRED)
    s.listen(16)
    log(event="keyd-start", keys=str(KEYS))
    while True:
        c, _ = s.accept()
        threading.Thread(target=client, args=(c,), daemon=True).start()


if __name__ == "__main__":
    main()
