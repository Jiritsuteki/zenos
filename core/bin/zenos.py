#!/usr/bin/env python3
"""ZENOS PoC core: level-labelled, signed, encrypted files (.zen).

File layout:  b"ZENOS1\n" + header(JSON, one line) + b"\n" + signature(base64) + b"\n" + ciphertext
- header carries the level; it is bound to the ciphertext as AES-GCM associated data
- the device key signs header + sha256(ciphertext): changing the level breaks the signature
- each level has its own key; a session holds keys only up to its level
PoC keys live on disk under ~/.local/share/zenos/keys. Production keys live on the FIDO2 device.
"""
import base64, hashlib, json, os, subprocess, sys, time
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

for _lib in ("/usr/lib/zenos", "/usr/local/lib/zenos"):   # the ZENOS library: installed, else development layout
    if os.path.isdir(_lib) and _lib not in sys.path:
        sys.path.append(_lib)
from zformat import MAGIC, FOLDERS, LABEL, REQUIRED, request_core, request_digest  # noqa: E402

H = Path.home()
Z = H / ".local/share/zenos"                     # per-user data
ROOT = Path(__file__).resolve().parent.parent      # program files (icons, apps, launchers)
K = Z / "keys"
CFG = H / ".config/zenos"
DESK = H / "Desktop"
AUDIT = Z / "audit.log"
FOLDER_ICON = {"Basic · L1": "basic", "Green · L2-L3": "green", "Red · L4": "red", "Black · L5": "black"}
REQ = Z / "requests"
GRANTS = Z / "grants"
APPROVER_KEYS = Z / "approvers"
# approvers needed per level (design: more approvers as the level rises)
# PoC roster. In production each officer signs with their own FIDO2 device.
ROSTER = {"sato": "Sato Kenji · Section Chief", "tanaka": "Tanaka Yuko · Director",
          "suzuki": "Suzuki Akira · Security Officer"}
GRANT_MINUTES = 30
# anomaly detection: the halt state, pre-filed operations, quarantined evidence
HALT = CFG / "halt.json"
# Installed system: the stop, release requests and quarantine belong to root (zenos-guardd); the officers' public
# keys are installed by the administrator. The user can read them but cannot change them.
SYSD = Path("/var/lib/zenos")
GUARDD = (SYSD / "requests").is_dir()
GUARDD_SOCK = "/run/zenos/guardd.sock"
if GUARDD:
    HALT = SYSD / "halt.json"
RELEASE_REQ = SYSD / "requests" if GUARDD else None
APPROVER_PUB = Path("/etc/zenos/approvers")
PLANS = Z / "plans"
QUAR = Z / "quarantine"
USB = DESK / "USB Drive"   # PoC stand-in for removable media / external transfer
PLAN_RULES = {"usb-export": "Copy files to the USB Drive", "bulk-read": "Open many protected files at once"}

try:
    import zledger as _zledger
except Exception:
    _zledger = None
LEDGER = Z / "ledger.jsonl"
try:
    import zfrag as _zfrag
except Exception:
    _zfrag = None
KSTORE = K / "frag"

# Installed system: the level keys belong to root (zenos-keyd); every seal and unseal goes through it, and it
# decides by the caller's clearance (or an officer-signed grant). The development layout keeps keys in the home.
KEYD_SOCK = os.environ.get("ZENOS_KEYD_SOCK", "/run/zenos/keyd.sock")


def use_keyd():
    return os.path.exists(KEYD_SOCK)


def keyd(msg):
    import socket
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(60)
    s.connect(KEYD_SOCK)
    s.sendall((json.dumps(msg) + "\n").encode())
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = s.recv(1 << 20)
        if not chunk:
            break
        buf += chunk
    s.close()
    return json.loads(buf or b"{}")


def _device_id():
    try:
        import hashlib as _h
        if use_keyd():
            return _h.sha256(base64.b64decode(keyd({"op": "whoami"})["device"])).hexdigest()[:16]
        return _h.sha256((K / "device_ed25519.pub").read_bytes()).hexdigest()[:16]
    except Exception:
        return "unknown"

def net_guard(level, on):
    """Signal the root sensor to cut/restore egress while an L4+ file is open (open.flag)."""
    try:
        (Z / "open.flag").write_text(str(level) if on else "0")
    except Exception:
        pass


def audit(event, **kw):
    """Every operation is recorded (metadata only, never the content)."""
    Z.mkdir(parents=True, exist_ok=True)
    rec = {"t": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "user": os.environ.get("USER", "zenos"),
           "session_level": session_level(), "event": event, **kw}
    with open(AUDIT, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    if _zledger is not None:
        try:
            _zledger.append(str(LEDGER), event, os.environ.get("USER", "zenos"), _device_id(), **kw)
        except Exception:
            pass


def ensure_keys():
    if use_keyd():
        return                                       # the keys live with the root key agent
    K.mkdir(parents=True, exist_ok=True)
    os.chmod(K, 0o700)
    for n in range(1, 6):
        p = K / f"L{n}.key"
        if not p.exists():
            p.write_bytes(AESGCM.generate_key(bit_length=256))
            os.chmod(p, 0o600)
    sk = K / "device_ed25519"
    if not sk.exists():
        k = Ed25519PrivateKey.generate()
        sk.write_bytes(k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                       serialization.NoEncryption()))
        os.chmod(sk, 0o600)
        (K / "device_ed25519.pub").write_bytes(
            k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


def session_level():
    try:
        s = max(1, min(5, int((CFG / "level").read_text().strip())))
    except Exception:
        s = 1
    if use_keyd():                                   # never above the clearance the administrator set
        try:
            s = min(s, int(keyd({"op": "whoami"})["clearance"]))
        except Exception:
            s = 1
    return s


def folder_for(level):
    for name, (lo, hi) in FOLDERS.items():
        if lo <= level <= hi:
            d = DESK / name
            if not d.exists():
                d.mkdir(parents=True)
                (d / ".directory").write_text(
                    f"[Desktop Entry]\nIcon={ROOT}/icons/zenos-folder-{FOLDER_ICON[name]}.svg\n")
            return d


def folder_range(path):
    p = Path(path).parent
    if p.parent == DESK and p.name in FOLDERS:
        return FOLDERS[p.name]
    return None


def seal(data: bytes, level: int, name: str) -> bytes:
    if use_keyd():
        r = keyd({"op": "seal", "level": level, "name": name, "data": base64.b64encode(data).decode()})
        if not r.get("ok"):
            raise RuntimeError(r.get("message") or "The key agent refused to seal: " + str(r.get("error")))
        return base64.b64decode(r["blob"])
    ensure_keys()
    base = {"zenos": 1, "level": level, "label": LABEL[level], "name": name,
            "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "author": os.environ.get("USER", "zenos")}
    if _zfrag is not None:
        header = {**base, "alg": "AES-256-GCM-fragmented", "fmt": "zfrag2"}
        hb = json.dumps(header, ensure_ascii=False, sort_keys=True).encode()
        ct = _zfrag.seal(data, level, name, str(KSTORE))
    else:
        header = {**base, "alg": "AES-256-GCM", "nonce": base64.b64encode(os.urandom(12)).decode()}
        hb = json.dumps(header, ensure_ascii=False, sort_keys=True).encode()
        ct = AESGCM((K / f"L{level}.key").read_bytes()).encrypt(base64.b64decode(header["nonce"]), data, hb)
    sk = Ed25519PrivateKey.from_private_bytes((K / "device_ed25519").read_bytes())
    sig = sk.sign(hb + hashlib.sha256(ct).digest())
    return MAGIC + hb + b"\n" + base64.b64encode(sig) + b"\n" + ct

def decrypt_ct(h, hb, ct, sig=None, grant=None):
    """Single decrypt path: fragmented (per-fragment keys) or legacy (per-level key). With the key agent the whole
    signed file goes to it, with the officers' grant when the file is above the caller's clearance."""
    if use_keyd():
        if sig is None:
            raise RuntimeError("the key agent needs the signed file")
        r = keyd({"op": "open", "blob": base64.b64encode(MAGIC + hb + b"\n" + base64.b64encode(sig) + b"\n" + ct).decode(),
                  "grant": grant})
        if not r.get("ok"):
            raise PermissionError(r.get("message") or r.get("error") or "refused")
        return base64.b64decode(r["data"])
    if h.get("fmt") == "zfrag2":
        return _zfrag.open_full(ct, str(KSTORE))
    return AESGCM((K / f"L{h['level']}.key").read_bytes()).decrypt(base64.b64decode(h["nonce"]), ct, hb)


def parse(blob: bytes):
    if not blob.startswith(MAGIC):
        raise ValueError("not a ZENOS file")
    hb, rest = blob[len(MAGIC):].split(b"\n", 1)
    sig, ct = rest.split(b"\n", 1)
    return json.loads(hb), hb, base64.b64decode(sig), ct


def verify(hb, sig, ct):
    if use_keyd():
        r = keyd({"op": "verify", "blob": base64.b64encode(MAGIC + hb + b"\n" + base64.b64encode(sig) + b"\n" + ct).decode()})
        if not r.get("ok"):
            raise ValueError("signature check failed")
        return
    pk = Ed25519PublicKey.from_public_bytes((K / "device_ed25519.pub").read_bytes())
    pk.verify(sig, hb + hashlib.sha256(ct).digest())  # raises InvalidSignature


def safe_name(s):
    s = "".join(c for c in s if c not in '/\\:*?"<>|\n\r\t').strip()
    return s or "Untitled"


UI_ENV = {**os.environ, "LANGUAGE": "en_US:en"}   # the UI is English-first (buttons too)


def kd(*args, level=0):
    # level: the sealed level shown in this window (the guard refuses screenshot tools while L3+ is on screen)
    env = dict(UI_ENV, ZENOS_SEALED_LEVEL=str(level)) if level else UI_ENV
    r = subprocess.run(["kdialog", *args], capture_output=True, text=True, env=env)
    return r.returncode, r.stdout.rstrip("\n")


def notify(title, text):
    subprocess.Popen(["kdialog", "--title", title, "--passivepopup", text, "6"], env=UI_ENV)


# ---------------- requests and approvals ----------------

def file_hash(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def approver_key(name):
    """PoC: each officer's signing key. Production: the key never leaves the officer's FIDO2 device."""
    APPROVER_KEYS.mkdir(parents=True, exist_ok=True)
    os.chmod(APPROVER_KEYS, 0o700)
    sk = APPROVER_KEYS / f"{name}.key"
    if not sk.exists():
        k = Ed25519PrivateKey.generate()
        sk.write_bytes(k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                       serialization.NoEncryption()))
        os.chmod(sk, 0o600)
        (APPROVER_KEYS / f"{name}.pub").write_bytes(
            k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    return Ed25519PrivateKey.from_private_bytes(sk.read_bytes())


def admin_enrolled():
    """True once the administrator has enrolled officer keys (installed system). From then on only those count."""
    try:
        return any(APPROVER_PUB.glob("*.pub"))
    except OSError:
        return False


def approver_pub(name):
    """an officer's public key. Installed system: only the administrator-installed copy (root-owned) — never a key
    from the user's own store, which the user could make up. Development preview: the PoC key store."""
    name = os.path.basename(name)
    p = APPROVER_PUB / f"{name}.pub"
    return p if (p.exists() or admin_enrolled()) else APPROVER_KEYS / f"{name}.pub"


def request_path(rid):
    rid = os.path.basename(rid)
    for d in ([RELEASE_REQ] if RELEASE_REQ else []) + [REQ]:
        if (d / f"{rid}.json").exists():
            return d / f"{rid}.json"
    return REQ / f"{rid}.json"


def guardd_call(msg):
    """talk to the root guard (release approvals and declines)"""
    import socket
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect(GUARDD_SOCK)
    s.sendall((json.dumps(msg) + "\n").encode())
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = s.recv(65536)
        if not chunk:
            break
        buf += chunk
    s.close()
    return json.loads(buf or b"{}")


def verified_approvers(core, digest_b64, approvals):
    """Recompute the digest from the request core and count approvals whose signatures verify."""
    digest = hashlib.sha256(json.dumps(core, sort_keys=True, ensure_ascii=False).encode()).digest()
    if base64.b64decode(digest_b64) != digest:
        return set()
    ok = set()
    import zapprove
    for a in approvals:
        name = os.path.basename(str(a.get("approver", "")))
        if zapprove.enrolled(APPROVER_PUB, name):
            # an administrator-enrolled key: a browser key or a passkey in the phone's secure chip
            if zapprove.check(APPROVER_PUB, name, a.get("sig", ""), digest, core.get("level", 0))[0]:
                ok.add(name)
            continue
        try:
            pk = Ed25519PublicKey.from_public_bytes(approver_pub(name).read_bytes())
            pk.verify(base64.b64decode(a["sig"]), digest)
            ok.add(name)
        except Exception:
            pass
    return ok


def new_request(kind, level, required, reason, **extra):
    REQ.mkdir(parents=True, exist_ok=True)
    rid = time.strftime("%Y%m%d-%H%M%S") + "-" + os.urandom(2).hex()
    code = f"{int.from_bytes(os.urandom(2), 'big') % 10000:04d}"
    r = {"id": rid, "kind": kind, "requester": os.environ.get("USER", "zenos"), "level": level,
         "label": LABEL[level], "reason": reason, "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
         "required": required, "code": code, "status": "pending", "approvals": [], **extra}
    (REQ / f"{rid}.json").write_text(json.dumps(r, ensure_ascii=False, indent=1))
    return r


# ---------------- halt state (anomaly stop) ----------------

def halted():
    try:
        h = json.loads(HALT.read_text())
        return h if h.get("status") == "halted" else None
    except Exception:
        return None


def release_required(level):
    # releasing a stop needs more officers than opening the file did
    return min(len(ROSTER), max(2, REQUIRED[level] + 1))


def refuse_if_halted(what):
    h = halted()
    if h:
        audit("refused-halted", action=what, halt=h["id"])
        kd("--title", "ZENOS · Stopped", "--sorry",
           f"This PC is stopped after an anomaly ({h['rule_text']}).\n"
           f"Nothing can be opened or created until the emergency release is approved.")
        return True
    return False


def active_plan(rule, level):
    """A pre-filed operation approved by the officers: same user, same rule, level covered, not expired, quota left."""
    PLANS.mkdir(parents=True, exist_ok=True)
    for p in sorted(PLANS.glob("*.json")):
        try:
            g = json.loads(p.read_text())
        except Exception:
            continue
        core, sc = g.get("core", {}), g.get("core", {}).get("scope", {})
        if (sc.get("rule") != rule or core.get("requester") != os.environ.get("USER", "zenos")
                or level > core.get("level", 0) or time.time() > g["expires"] or g["used"] >= sc.get("max_files", 0)):
            continue
        if len(verified_approvers(core, g["digest"], g["approvals"])) >= REQUIRED[core["level"]]:
            return p, g
    return None, None


def use_plan(p, g, n=1):
    g["used"] += n
    p.write_text(json.dumps(g, ensure_ascii=False, indent=1))


def request_access(p, h):
    rc, reason = kd("--title", f"ZENOS · Access request · L{h['level']}", "--inputbox",
                    f"Why do you need \"{h['name']}\"?\nThe reason is shown to the approvers. The content is not.")
    if rc != 0:
        return
    REQ.mkdir(parents=True, exist_ok=True)
    rid = time.strftime("%Y%m%d-%H%M%S") + "-" + os.urandom(2).hex()
    code = f"{int.from_bytes(os.urandom(2), 'big') % 10000:04d}"
    r = {"id": rid, "requester": os.environ.get("USER", "zenos"), "file": str(p), "name": h["name"],
         "file_hash": file_hash(p), "level": h["level"], "label": h["label"], "reason": reason,
         "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "required": REQUIRED[h["level"]],
         "code": code, "status": "pending", "approvals": []}
    (REQ / f"{rid}.json").write_text(json.dumps(r, ensure_ascii=False, indent=1))
    audit("request", request=rid, file=p.name, level=h["level"], required=r["required"])
    kd("--title", "ZENOS · Request sent", "--msgbox",
       f"Your access request for \"{h['name']}\" (L{h['level']}) was sent.\n\n"
       f"Match code:   {code}\n\nApprovers will be asked to confirm this code.\n"
       f"Needs {r['required']} approval(s). You will be notified when it is decided.")


MAX_CODE_TRIES = 5


def approve(rid, approver, code):
    """Returns (ok, message). Signs the request with the approver's key; issues a grant when enough approvals."""
    p = request_path(rid)
    r = json.loads(p.read_text())
    if RELEASE_REQ and p.parent == RELEASE_REQ:
        # an emergency release: the approver signs, the root guard verifies and decides
        if approver not in ROSTER:
            return False, "Unknown approver."
        sig = approver_key(approver).sign(request_digest(r))
        try:
            out = guardd_call({"op": "approve", "request": r["id"], "approver": approver, "code": code.strip(),
                               "sig": base64.b64encode(sig).decode()})
        except OSError:
            return False, "The ZENOS guard is not reachable."
        return bool(out.get("ok")), out.get("message", "")
    if r["status"] != "pending":
        return False, "This request is already decided."
    if approver not in ROSTER:
        return False, "Unknown approver."
    if int(r.get("code_tries", 0) or 0) >= MAX_CODE_TRIES:
        audit("approve-refused", request=rid, approver=approver, reason="code-tries")
        return False, "Too many wrong match codes for this request. Nothing was approved; ask for a new request."
    if code.strip() != r["code"]:
        r["code_tries"] = int(r.get("code_tries", 0) or 0) + 1              # a 4-digit code cannot be tried through
        p.write_text(json.dumps(r, ensure_ascii=False, indent=1))
        audit("approve-refused", request=rid, approver=approver, reason="match-code")
        return False, "The match code does not match the requester's screen. Nothing was approved."
    if approver == r.get("requester"):
        return False, "You cannot approve your own request. Another officer must approve."
    if any(a["approver"] == approver for a in r["approvals"]):
        return False, "You have already approved this request. Another officer must approve."
    sig = approver_key(approver).sign(request_digest(r))
    return _apply_approval(p, r, approver, base64.b64encode(sig).decode())


def signed_answer(rid, approver, op, sig_b64, code=""):
    """An officer's answer signed on their own device (carried here by ZENOS Messages). The signature must verify
    against the administrator-enrolled key for that officer; nothing else is trusted. Returns (ok, message)."""
    p = REQ / f"{os.path.basename(rid)}.json"
    if not p.exists():
        return False, "Unknown request."
    r = json.loads(p.read_text())
    if r["status"] != "pending":
        return False, "This request is already decided."
    approver = os.path.basename(approver)
    import zapprove
    if not zapprove.enrolled(APPROVER_PUB, approver):
        audit("approve-refused", request=r["id"], approver=approver, reason="not-enrolled")
        return False, "This officer is not enrolled on this PC."
    digest = request_digest(r)
    ok, why, facts = zapprove.check(APPROVER_PUB, approver, sig_b64, digest if op == "approve" else b"decline:" + digest,
                                    r.get("level", 0), state=Z / "approver-counters.json")
    if not ok:
        audit("approve-refused", request=r["id"], approver=approver, reason=why)
        if why == "phone-not-near":
            return False, (f"An L{r.get('level')} request must be approved on this PC's screen, with your phone near it "
                           "(scan the QR code it shows). Nothing was recorded.")
        return False, "The signature does not verify. Nothing was recorded."
    if facts.get("exception"):
        audit("approval-exception", request=r["id"], approver=approver, level=r.get("level"), kind="remote")
    if op == "decline":
        r["status"], r["declined_by"] = "declined", approver
        r["decline_sig"] = sig_b64
        p.write_text(json.dumps(r, ensure_ascii=False, indent=1))
        audit("decline", request=r["id"], approver=approver, signed=True, **zapprove.ledger_fields(facts))
        what = {"release": "the emergency release", "plan": "the pre-filed operation"}.get(r.get("kind"), f"\"{r.get('name')}\"")
        notify("ZENOS · Request declined", f"Your request for {what} (L{r['level']}) was declined.")
        return True, "Declined."
    if int(r.get("code_tries", 0) or 0) >= MAX_CODE_TRIES:
        audit("approve-refused", request=r["id"], approver=approver, reason="code-tries")
        return False, "Too many wrong match codes for this request. Nothing was approved; ask for a new request."
    if str(code).strip() != r["code"]:
        r["code_tries"] = int(r.get("code_tries", 0) or 0) + 1
        p.write_text(json.dumps(r, ensure_ascii=False, indent=1))
        audit("approve-refused", request=r["id"], approver=approver, reason="match-code")
        return False, "The match code does not match the requester's screen. Nothing was approved."
    if any(a["approver"] == approver for a in r["approvals"]):
        return False, "You have already approved this request. Another officer must approve."
    return _apply_approval(p, r, approver, sig_b64, facts)


def _apply_approval(p, r, approver, sig_b64, facts=None):
    """record one verified approval; with enough of them, the request takes effect (grant, plan or release)"""
    rid = r["id"]
    r["approvals"].append({"approver": approver, "t": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "sig": sig_b64})
    import zapprove
    audit("approve", request=rid, approver=approver, count=len(r["approvals"]), required=r["required"],
          **zapprove.ledger_fields(facts or {}))
    msg = f"Approved by {ROSTER.get(approver, approver)} ({len(r['approvals'])}/{r['required']})."
    if len(r["approvals"]) >= r["required"] and r.get("kind") == "release":
        r["status"] = "approved"
        h = json.loads(HALT.read_text())
        h.update(status="released", released=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                 released_by=[a["approver"] for a in r["approvals"]])
        HALT.write_text(json.dumps(h, ensure_ascii=False, indent=1))
        for pid in h.get("pids", []):   # the stopped operation is cancelled, not resumed; quarantine stays
            try:
                os.kill(pid["pid"], 9)   # SIGKILL works on a stopped process
            except Exception:
                pass
        audit("release", halt=h["id"], request=rid, approvers=h["released_by"])
        msg += " The stop is released."
    elif len(r["approvals"]) >= r["required"] and r.get("kind") == "plan":
        r["status"] = "approved"
        PLANS.mkdir(parents=True, exist_ok=True)
        sc = r["scope"]
        g = {"request": rid, "expires": time.time() + sc["minutes"] * 60, "used": 0,
             "digest": base64.b64encode(request_digest(r)).decode(), "approvals": r["approvals"],
             "core": request_core(r)}
        (PLANS / f"{rid}.json").write_text(json.dumps(g, ensure_ascii=False, indent=1))
        audit("plan-active", request=rid, rule=sc["rule"], level=r["level"], max_files=sc["max_files"],
              minutes=sc["minutes"])
        notify("ZENOS · Pre-filed operation approved",
               f"{PLAN_RULES[sc['rule']]} · up to {sc['max_files']} file(s) · L{r['level']} · {sc['minutes']} min.\n"
               f"ZENOS will not stop this operation.")
        msg += f" The operation is pre-approved for {sc['minutes']} minutes."
    elif len(r["approvals"]) >= r["required"]:
        r["status"] = "approved"
        GRANTS.mkdir(parents=True, exist_ok=True)
        g = {"request": rid, "requester": r["requester"], "file_hash": r["file_hash"], "level": r["level"],
             "expires": time.time() + GRANT_MINUTES * 60, "digest": base64.b64encode(request_digest(r)).decode(),
             "approvals": r["approvals"],
             "core": {k: r[k] for k in ("id", "requester", "file", "file_hash", "level", "reason", "created")}}
        (GRANTS / f"{r['file_hash']}.json").write_text(json.dumps(g, ensure_ascii=False, indent=1))
        audit("grant", request=rid, level=r["level"], minutes=GRANT_MINUTES)
        notify("ZENOS · Access approved",
               f"\"{r['name']}\" (L{r['level']}) can be opened for {GRANT_MINUTES} minutes.")
        msg += f" Access granted for {GRANT_MINUTES} minutes."
    p.write_text(json.dumps(r, ensure_ascii=False, indent=1))
    return True, msg


def decline(rid, approver):
    p = request_path(rid)
    r = json.loads(p.read_text())
    if RELEASE_REQ and p.parent == RELEASE_REQ:
        if approver not in ROSTER:
            return False, "Unknown approver."
        sig = approver_key(approver).sign(b"decline:" + request_digest(r))
        try:
            out = guardd_call({"op": "decline", "request": r["id"], "approver": approver,
                               "sig": base64.b64encode(sig).decode()})
        except OSError:
            return False, "The ZENOS guard is not reachable."
        return bool(out.get("ok")), out.get("message", "")
    if r["status"] != "pending":
        return False, "This request is already decided."
    r["status"] = "declined"
    r["declined_by"] = approver
    p.write_text(json.dumps(r, ensure_ascii=False, indent=1))
    audit("decline", request=rid, approver=approver)
    what = {"release": "the emergency release", "plan": "the pre-filed operation"}.get(r.get("kind"), f"\"{r.get('name')}\"")
    notify("ZENOS · Request declined", f"Your request for {what} (L{r['level']}) was declined.")
    return True, "Declined."


def valid_grant(p):
    """A grant is valid only for this exact file, this user, before expiry, with enough verified signatures."""
    gp = GRANTS / f"{file_hash(p)}.json"
    if not gp.exists():
        return None
    g = json.loads(gp.read_text())
    if g["requester"] != os.environ.get("USER", "zenos") or time.time() > g["expires"]:
        return None
    # the signed digest must match the request it claims to approve (no editing the grant file)
    core = g.get("core", {})
    digest = hashlib.sha256(json.dumps(core, sort_keys=True, ensure_ascii=False).encode()).digest()
    if (base64.b64decode(g["digest"]) != digest or core.get("file_hash") != file_hash(p)
            or core.get("requester") != g["requester"] or core.get("level") != g["level"]):
        return None
    ok = set()
    for a in g["approvals"]:
        try:
            pk = Ed25519PublicKey.from_public_bytes(approver_pub(a["approver"]).read_bytes())
            pk.verify(base64.b64decode(a["sig"]), digest)
            ok.add(a["approver"])
        except Exception:
            pass
    ok.discard(g["requester"])                  # the requester's own approval never counts (as in zenos-decide)
    return g if len(ok) >= REQUIRED[g["level"]] else None


# ---------------- commands ----------------

def cmd_plan():
    """File an operation in advance so the anomaly monitor does not stop it."""
    if refuse_if_halted("plan"):
        return
    rc, rule = kd("--title", "ZENOS · Pre-file an operation", "--radiolist",
                  "Which operation will you do?\nIf it is approved in advance, ZENOS will not stop it.",
                  "usb-export", PLAN_RULES["usb-export"], "on", "bulk-read", PLAN_RULES["bulk-read"], "off")
    if rc != 0:
        return
    rc, lv = kd("--title", "ZENOS · Pre-file an operation", "--radiolist", "Highest level of the files involved",
                *sum(([str(n), f"L{n} · {LABEL[n]}", "on" if n == 4 else "off"] for n in range(1, 6)), []))
    if rc != 0:
        return
    rc, n = kd("--title", "ZENOS · Pre-file an operation", "--inputbox", "How many files at most?", "5")
    if rc != 0 or not n.strip().isdigit():
        return
    rc, reason = kd("--title", "ZENOS · Pre-file an operation", "--inputbox",
                    "Why? The reason is shown to the approvers.")
    if rc != 0:
        return
    lvl = int(lv)
    r = new_request("plan", lvl, max(1, REQUIRED[lvl]), reason,
                    scope={"rule": rule, "max_files": int(n), "minutes": GRANT_MINUTES})
    audit("plan-request", request=r["id"], rule=rule, level=lvl, max_files=int(n))
    kd("--title", "ZENOS · Request sent", "--msgbox",
       f"Pre-filed operation: {PLAN_RULES[rule]}\nUp to {n} file(s) · L{lvl} · {GRANT_MINUTES} minutes\n\n"
       f"Match code:   {r['code']}\n\nNeeds {r['required']} approval(s).")


def cmd_new():
    if refuse_if_halted("create"):
        return
    s = session_level()
    rc, title = kd("--title", f"ZENOS Documents · L{s}", "--inputbox", f"Title of the new document (saved as L{s} · {LABEL[s]})")
    if rc != 0:
        return
    rc, body = kd("--title", f"ZENOS Documents · L{s} · {title}", "--textinputbox",
                  f"Write the document. It is encrypted with the L{s} key when you press OK.", "", "760", "480")
    if rc != 0:
        return
    dest = folder_for(s) / (safe_name(title) + ".zen")
    dest.write_bytes(seal(body.encode("utf-8"), s, title))
    audit("create", file=dest.name, level=s, folder=dest.parent.name)
    notify("ZENOS", f"Saved as L{s} in {dest.parent.name}.\nEncrypted and signed.")


def cmd_open(path):
    p = Path(path)
    ensure_keys()
    if refuse_if_halted("open"):
        return
    try:
        h, hb, sig, ct = parse(p.read_bytes())
        verify(hb, sig, ct)
    except Exception:
        audit("open-refused", file=p.name, reason="signature")
        kd("--title", "ZENOS", "--sorry", f"{p.name}\n\nThis file failed the signature check.\n"
           "It may have been altered (for example, its level was rewritten), so ZENOS will not open it.")
        return
    lvl, s = h["level"], session_level()
    granted = None
    if s < lvl:
        granted = valid_grant(p)
        if not granted:
            audit("open-refused", file=p.name, level=lvl, reason="key-level")
            rc, _ = kd("--title", f"ZENOS · L{lvl}", "--yes-label", "Send access request", "--no-label", "Close",
                       "--warningyesno",
                       f"\"{h['name']}\" is L{lvl} ({h['label']}).\nYour key is L{s}, so the content stays encrypted.\n\n"
                       f"To open it, send an access request for L{lvl}.\n"
                       f"{REQUIRED[lvl]} responsible officer(s) must approve it with their devices.")
            if rc == 0:
                request_access(p, h)
            return
    try:
        data = decrypt_ct(h, hb, ct, sig=sig, grant=granted)
    except PermissionError as e:                      # the key agent's own check (clearance / grant)
        audit("open-refused", file=p.name, level=lvl, reason="key-agent")
        kd("--title", f"ZENOS · L{lvl}", "--sorry", f"\"{h['name']}\" stays encrypted.\n\n{e}")
        return
    audit("open-granted" if granted else "open", file=p.name, level=lvl,
          **({"request": granted["request"], "approvers": [a["approver"] for a in granted["approvals"]]} if granted else {}))
    _ng = lvl >= 4
    if _ng:
        net_guard(lvl, True)
    try:
        if Path(h["name"]).suffix.lower() in OFFICE_EXT:
            return office_edit(p, h["name"], data, lvl)
        if Path(h["name"]).suffix.lower() in MEDIA_APPS:
            return media_view(p, h["name"], data, lvl)
        # the plaintext exists only in RAM (/dev/shm) while it is on screen, then it is deleted
        d = Path("/dev/shm") / f"zenos-{os.getuid()}"
        d.mkdir(mode=0o700, exist_ok=True)
        t = d / (p.stem + ".txt")
        t.write_bytes(data)
        try:
            ttl = f"ZENOS · L{lvl} · {h['name']} · {h['created'][:10]}"
            if lvl >= 3:                              # L3+: a viewer that cannot copy, select or drag
                subprocess.run([sys.executable, "-I", str(Path(__file__).parent / "zenos_textview.py"), ttl, str(t)],
                               env=dict(UI_ENV, ZENOS_SEALED_LEVEL=str(lvl)))
            else:
                kd("--title", ttl, "--textbox", str(t), "760", "480", level=lvl)
        finally:
            t.unlink(missing_ok=True)
    finally:
        if _ng:
            net_guard(lvl, False)


# ---------------- sealed pictures, videos and PDFs ----------------
MEDIA_APPS = {**{e: "zenos-images.sh" for e in (".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp", ".svg", ".avif", ".tif", ".tiff")},
              **{e: "zenos-video.sh" for e in (".mp4", ".m4v", ".mov", ".mkv", ".webm", ".avi", ".ogv", ".mpg", ".mpeg", ".ts")},
              ".pdf": "zenos-pdf.sh"}


def media_view(p, name, data, lvl):
    """Show a sealed picture/video/PDF in its ZENOS app. The plaintext lives only in RAM (/dev/shm) while the
    app is open; the app is told the level, so copies can only be saved into a folder of the same level or higher."""
    import subprocess
    d = Path("/dev/shm") / f"zenos-{os.getuid()}" / f"media-{os.getpid()}"
    d.mkdir(parents=True, mode=0o700, exist_ok=True)
    t = d / safe_name(name)
    t.write_bytes(data)
    audit("media-open", file=p.name, level=lvl, app=MEDIA_APPS[Path(name).suffix.lower()])
    try:
        env = dict(os.environ, ZENOS_SEALED_LEVEL=str(lvl))
        subprocess.run([str(Path(__file__).parent / MEDIA_APPS[Path(name).suffix.lower()]), str(t)], env=env)
    finally:
        t.unlink(missing_ok=True)
        try:
            d.rmdir()
        except OSError:
            pass


# ---------------- office files (Documents / Sheets / Slides) ----------------
OFFICE_EXT = {".docx": "Documents", ".xlsx": "Sheets", ".pptx": "Slides",
              ".odt": "Documents", ".ods": "Sheets", ".odp": "Slides",
              ".doc": "Documents", ".xls": "Sheets", ".ppt": "Slides",
              ".docm": "Documents", ".xlsm": "Sheets", ".pptm": "Slides"}
OFFICE_WINDOW = "/usr/bin/zenos-office"     # the LibreOffice engine in a ZENOS window (docs/OFFICE_ENGINE.md)
OFFICE_APPS = {".docx": "zenos-docs.sh", ".xlsx": "zenos-sheets.sh", ".pptx": "zenos-slides.sh"}


def office_edit(p, name, data, lvl):
    """Edit an office file with the ZENOS office engine. The plaintext and the engine's own working data
    (profile, autosave, backups) live only in RAM, and the file is sealed again at the same level on close."""
    d = Path("/dev/shm") / f"zenos-{os.getuid()}" / f"office-{os.getpid()}"
    d.mkdir(parents=True, mode=0o700, exist_ok=True)
    t = d / safe_name(name)
    t.write_bytes(data)
    before = hashlib.sha256(data).hexdigest()
    app = OFFICE_EXT[Path(name).suffix.lower()]
    audit("office-open", file=p.name, level=lvl, app=app)
    try:
        launcher = Path(__file__).parent / OFFICE_APPS.get(Path(name).suffix.lower(), "")
        if os.path.exists(OFFICE_WINDOW):                # the engine keeps tables, pictures, layout; macros never run
            subprocess.run([OFFICE_WINDOW, str(t), "--level", str(lvl)],
                           env=dict(UI_ENV, ZENOS_SEALED_LEVEL=str(lvl)), capture_output=True)
        elif launcher.name and launcher.exists():        # the ZENOS app, in sealed mode (saves only to the RAM copy)
            subprocess.run([str(launcher), str(t)], env=dict(UI_ENV, ZENOS_SEALED_LEVEL=str(lvl)), capture_output=True)
        else:                                            # OpenDocument files: LibreOffice with its profile in RAM
            subprocess.run(["soffice", f"-env:UserInstallation=file://{d}/profile", "--norestore", "--nologo", str(t)],
                           env=UI_ENV, capture_output=True)
        new = t.read_bytes() if t.exists() else data
        if hashlib.sha256(new).hexdigest() != before:
            tmp = p.with_name("." + p.name + ".tmp")
            tmp.write_bytes(seal(new, lvl, name))
            tmp.replace(p)
            audit("office-save", file=p.name, level=lvl, app=app, bytes=len(new))
            notify("ZENOS", f"{name} was saved and sealed again as L{lvl}.")
    finally:
        import shutil
        shutil.rmtree(d, ignore_errors=True)


def cmd_office(kind):
    """New document / sheet / slides at the session level, saved straight into the matching security folder."""
    if refuse_if_halted("create"):
        return
    s = session_level()
    app = {"docx": "Documents", "xlsx": "Sheets", "pptx": "Slides"}[kind]
    rc, title = kd("--title", f"ZENOS {app} · L{s}", "--inputbox", f"Name of the new file (saved as L{s} · {LABEL[s]})")
    if rc != 0 or not title.strip():
        return
    name = safe_name(title) + "." + kind
    blank = (ROOT / "templates" / f"blank.{kind}").read_bytes()     # empty files shipped with ZENOS
    dest = folder_for(s) / (name + ".zen")
    dest.write_bytes(seal(blank, s, name))
    audit("create", file=dest.name, level=s, folder=dest.parent.name, app=app)
    office_edit(dest, name, blank, s)


def _cmd_check_before_vault(path):
    """Called by the guard on every file that lands in a security folder."""
    p = Path(path)
    rng = folder_range(p)
    if not rng or not p.is_file() or p.name.startswith("."):
        return
    lo, hi = rng
    if p.suffix == ".zen":
        try:
            h, *_ = parse(p.read_bytes())
        except Exception:
            return
        lvl = h["level"]
        if lvl > hi:
            back = folder_for(lvl) / p.name
            p.rename(back)
            audit("downgrade-blocked", file=p.name, level=lvl, into=p.parent.name)
            kd("--title", "ZENOS · Downgrade blocked", "--sorry",
               f"\"{h['name']}\" is L{lvl}. It cannot move into {p.parent.name}.\n\n"
               f"Moving a file to a lower level is a downgrade. It needs a downgrade request\n"
               f"approved by the responsible officers. The file was returned to {back.parent.name}.")
        return
    # a plain file dropped into a security folder is sealed at that folder's level
    if p.suffix in (".part", ".tmp", ".crdownload") or p.name == ".directory":
        return
    mine = session_level()
    if mine < lo:
        # not cleared for this folder: the file may not be sealed here (the key agent refuses a label above the
        # author's clearance), and a plain copy must not stay in it. It goes to the folder of the person's level.
        back = folder_for(mine) / p.name
        p.rename(back)
        audit("seal-refused", file=p.name, level=lo, clearance=mine, moved_to=back.parent.name)
        kd("--title", "ZENOS · Not cleared for this folder", "--sorry",
           f"\"{p.name}\" cannot be kept in {p.parent.name}: you are cleared up to L{mine}.\n\n"
           f"It was moved to {back.parent.name}. To work at a higher level, ask your administrator for clearance.")
        return
    lvl = max(lo, min(hi, mine))
    dest = p.with_suffix(p.suffix + ".zen") if p.suffix else p.with_name(p.name + ".zen")
    try:
        dest.write_bytes(seal(p.read_bytes(), lvl, p.name))
    except Exception as e:                      # never leave an unprotected copy in a security folder
        try:
            dest.unlink()
        except OSError:
            pass
        back = folder_for(1) / p.name
        p.rename(back)
        audit("seal-failed", file=p.name, level=lvl, error=str(e)[:80], moved_to=back.parent.name)
        kd("--title", "ZENOS · Could not seal", "--sorry",
           f"\"{p.name}\" could not be sealed as L{lvl} ({e}).\n\nIt was moved to {back.parent.name}.")
        return
    p.unlink()
    audit("seal", file=dest.name, level=lvl, folder=p.parent.name)
    notify("ZENOS", f"{p.name} was sealed as L{lvl}.\nThe unprotected copy was removed.")


def cmd_info(path):
    h, hb, sig, ct = parse(Path(path).read_bytes())
    try:
        verify(hb, sig, ct)
        ok = "valid"
    except Exception:
        ok = "INVALID"
    print(json.dumps({**h, "signature": ok, "ciphertext_bytes": len(ct)}, ensure_ascii=False, indent=1))


# --- ZENOS Vault hook ---
def vault_after_check(path):
    """A sealed file that settled in a security folder is also stored on the ministry grid (background)."""
    p = Path(path)
    try:
        rng = folder_range(p)
        if not rng or p.suffix != ".zen" or not p.is_file():
            return
        if not (Z / "p2p" / "enabled").exists():
            return
        h, *_ = parse(p.read_bytes())
        if h["level"] > rng[1]:
            return
        b = ROOT / "bin" / "zenos_p2p.py"
        if b.exists():
            subprocess.Popen([sys.executable, "-I", str(b), "backup", str(p), "--quiet", "1"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             stdin=subprocess.DEVNULL, start_new_session=True)
    except Exception as e:
        audit("vault-hook-error", file=p.name, error=str(e)[:200])


def cmd_check(path):
    _cmd_check_before_vault(path)
    vault_after_check(path)
# --- end of ZENOS Vault hook ---


if __name__ == "__main__":
    cmd, *args = sys.argv[1:] or ["help"]
    if cmd == "signed-answer":            # RID APPROVER approve|decline SIG [CODE]  (used by ZENOS Messages)
        try:
            ok, message = signed_answer(*args[:5])
        except Exception as e:
            ok, message = False, "The answer could not be recorded."
            audit("signed-answer-error", error=str(e)[:200])
        print(json.dumps({"ok": ok, "message": message}))
        sys.exit(0)
    {"new": cmd_new, "open": cmd_open, "plan": cmd_plan, "office": cmd_office, "check": cmd_check, "info": cmd_info,
     "keys": ensure_keys}.get(cmd, lambda *a: print("usage: zenos new|open FILE|check FILE|info FILE|keys"))(*args)
