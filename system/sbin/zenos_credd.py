#!/usr/bin/env python3
"""ZENOS vault service: passwords kept on the PC, unlocked only by the person's phone.

Each saved password is encrypted with a key that only the person's phone can produce: the phone's passkey derives it
(WebAuthn PRF) for that one entry, after the phone verifies the person by fingerprint, face or PIN. The PC never has
the key at rest, so a copied disk or a stolen PC yields no password.

  browser  --ask(origin, account)-->  credd  --pending-->  ZENOS Messages on the phone
  browser  <--password (that page only)--  credd  <--passkey signature over this request + the entry's key--  phone

* The ZENOS browser asks, giving the page's origin as it verified it (HTTPS, certificate chain checked, no distrusted
  authority) and shows a two-digit code. The phone shows the site, the account and three codes; the person picks the
  code the PC shows and approves with fingerprint or face.
* The passkey signs this request's digest (id, site, account, time, this service's one-time key, the entry's salt),
  so an approval counts for this request only. The entry's key travels encrypted to this service's one-time key.
* Whether the password is released is decided by `zenos-decide` (ZenosFormal/Cred.lean, `cred_sound`, `cred_once`):
  right origin, verified TLS, in time, registered phone, valid signature over this request, person verified,
  counter forward, right code; and every request is answered at most once.
* At most ASK_MAX prompts reach the phone per ASK_WINDOW (`ask_bounded`): a program cannot wear the person down with
  a stream of prompts.
* The password goes back only to the process that asked (same PID through SO_PEERCRED), and the browser fills it into
  that page only if it is still the same page.

Phones are registered with a one-time enrolment code from the administrator:  sudo zenos_credd.py --enroll USER
Protocol: one JSON line per connection on /run/zenos/credd.sock; the caller is identified by SO_PEERCRED.
Not protected: a PC already taken over while the person approves (the password is on the screen's page at that
moment); docs/SECURITY_ARCHITECTURE.md.
"""
import hashlib, hmac, json, os, pwd, re, secrets, socket, struct, sys, threading, time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "lib", "zenos"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "lib"))
import zdecide                                        # noqa: E402
import zwebauthn as W                                 # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization                    # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec                             # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM                       # noqa: E402
from cryptography.hazmat.primitives.kdf.hkdf import HKDF                             # noqa: E402

SOCK = os.environ.get("ZENOS_CREDD_SOCK", "/run/zenos/credd.sock")
DATA = os.environ.get("ZENOS_CRED_DIR", "/var/lib/zenos/cred")
TTL_MS = 120_000                   # a request is answerable for two minutes
ASK_WINDOW_MS, ASK_MAX = 60_000, 3 # prompts per person per minute
ENROLL_TTL = 15 * 60
ENROLL_TRIES, ENROLL_GAP = 20, 2.0     # wrong enrolment codes: 20 tries, 2 s apart (8 digits: no guessing, no lock-out)
MAX_LINE = 64 * 1024
# who may ask: the browser asks for passwords, ZENOS Messages carries the phone's answers. Each is a root-owned
# program run by the person; another program of the same person is refused (it could show a fake code on screen).
# The process must also be one zenos-launchd started (its record: pid, start time, uid, program). A program of the
# same person can rename itself, but it cannot get into that record, and it cannot attach to a process whose parent
# is root (kernel.yama.ptrace_scope = 1). A development layout without zenos-launchd keeps the name checks only.
LAUNCHED = os.environ.get("ZENOS_LAUNCHED", "/run/zenos/launched.json")
LAUNCH_UNITS = [u for u in os.environ.get("ZENOS_LAUNCH_UNIT", "/lib/systemd/system/zenos-launchd.service:"
                                          "/usr/lib/systemd/system/zenos-launchd.service").split(":") if u]
BROWSERS = os.environ.get("ZENOS_CREDD_BROWSER", "/usr/share/zenos/bin/zenos_webkit.py").split(":")
MESSENGERS = os.environ.get("ZENOS_CREDD_MESSENGER", "/usr/share/zenos/msg/client.js").split(":")
BROWSER_OPS = {"accounts", "ask", "wait", "cancel"}
PHONE_OPS = {"pending", "answer", "enroll-start", "enroll-finish"}
NODE_OPTIONS_OK = {"", "--require=/usr/lib/zenos/zdistrust.js"}
ORIGIN_RE = re.compile(r"^https://(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?::[1-9][0-9]{0,4})?$")

LOCK = threading.Lock()
REQ = {}                           # request id -> request (in memory only: a restart forgets every open request)
ASKS = {}                          # user -> times (ms) of the prompts sent
ENROLLING = {}                     # challenge (b64u) -> {user, origin, rp_id, expires}


def log(**kw):
    print(json.dumps(dict(kw, t=time.strftime("%Y-%m-%dT%H:%M:%S")), ensure_ascii=True), flush=True)


def now_ms():
    return int(time.time() * 1000)


# ---------- storage (root only)
def udir(user):
    d = os.path.join(DATA, user)
    os.makedirs(d, mode=0o700, exist_ok=True)
    return d


def load(user, name, default):
    try:
        with open(os.path.join(udir(user), name)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def save(user, name, obj):
    p = os.path.join(udir(user), name)
    tmp = p + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(obj, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, p)


def phones(user):
    return load(user, "phones.json", {})


def vault(user):
    return load(user, "vault.json", [])


def used(user):
    return load(user, "used.json", [])


def mark_used(user, rid):
    u = used(user)
    u.append(rid)
    save(user, "used.json", u[-5000:])


# ---------- the request and what the passkey signs
def core(r):
    return {"v": 1, "id": r["id"], "kind": r["kind"], "user": r["user"], "origin": r["origin"], "account": r["account"],
            "created": r["created"], "server_key": r["server_key"], "salt": r["salt"]}


def digest(r):
    return hashlib.sha256(json.dumps(core(r), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).digest()


def hkdf(key, salt, info):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(key)


def entry_key(prf, salt, origin, account):
    return hkdf(prf, salt, b"zenos-vault-entry\0" + origin.encode() + b"\0" + account.encode())


def entry_aad(origin, account):
    return origin.encode() + b"\0" + account.encode()


def good_origin(o):
    """https://host[:port], host in ASCII (international names in their xn-- form), no user part, no path"""
    return isinstance(o, str) and len(o) < 300 and ORIGIN_RE.match(o) is not None


def _proc(pid, name):
    with open("/proc/%d/%s" % (pid, name), "rb") as f:
        return f.read()


def launched(pid, uid, kind, path=None):
    """was `pid` started by zenos-launchd as `kind` for `uid`, and is it still that process (same start time)"""
    try:
        with open(path or LAUNCHED) as f:
            recs = json.load(f)
        st = _proc(pid, "stat").decode().rsplit(")", 1)[1].split()[19]
    except (OSError, ValueError, IndexError):
        return False
    return any(isinstance(h, dict) and h.get("pid") == pid and h.get("start") == st and h.get("uid") == uid
               and h.get("program") == kind for h in recs if isinstance(recs, list))


def caller(pid):
    """'browser', 'messenger' or None: which ZENOS program the connecting process runs. The program file must be one
    of the installed, root-owned ones, run by the plain interpreter: no code injected through the environment
    (PYTHONPATH, LD_PRELOAD, NODE_OPTIONS beyond the system's own), no interpreter options that run other code, and
    not being traced by a debugger."""
    try:
        exe = os.path.basename(os.path.realpath("/proc/%d/exe" % pid))
        argv = [a.decode() for a in _proc(pid, "cmdline").split(b"\0") if a]
        env = dict(e.decode(errors="replace").partition("=")[::2] for e in _proc(pid, "environ").split(b"\0") if e)
        status = _proc(pid, "status").decode()
        cwd = os.path.realpath("/proc/%d/cwd" % pid)
    except (OSError, ValueError):
        return None
    if re.search(r"^TracerPid:\s*[1-9]", status, re.M):
        return None
    if any(k in env for k in ("LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "PYTHONPATH", "PYTHONHOME",
                              "PYTHONSTARTUP", "PYTHONINSPECT", "PYTHONUSERBASE")):
        return None
    args = argv[1:]
    if re.fullmatch(r"python3(\.\d+)?", exe):
        while args and args[0] in ("-E", "-s", "-B", "-I", "-Es", "-sE"):
            args = args[1:]
        script, kinds = (args[0] if args else ""), (("browser", BROWSERS),)
    elif exe == "node":
        if env.get("NODE_OPTIONS", "") not in NODE_OPTIONS_OK:
            return None
        script, kinds = (args[0] if args else ""), (("messenger", MESSENGERS),)
    else:
        return None
    path = os.path.realpath(os.path.join(cwd, script)) if script and not script.startswith("-") else ""
    for kind, allowed in kinds:
        if path and path in [os.path.realpath(a) for a in allowed if a]:
            st = os.stat(path)
            if st.st_uid == 0 and not st.st_mode & 0o022:           # a file only root can change
                return kind
    return None


# ---------- browser side
def op_accounts(user, m):
    o = m.get("origin")
    return {"ok": True, "accounts": sorted({e["account"] for e in vault(user) if e["origin"] == o}),
            "phone": bool(phones(user))}


def op_ask(user, pid, m):
    kind, origin, account = m.get("kind"), m.get("origin"), m.get("account")
    if kind not in ("fill", "save") or not good_origin(origin):
        return {"ok": False, "error": "bad request"}
    ph = phones(user)
    if not ph:
        return {"ok": False, "error": "no-phone"}
    entries = [e for e in vault(user) if e["origin"] == origin]
    if kind == "fill":
        if account is None and len(entries) == 1:
            account = entries[0]["account"]
        entry = next((e for e in entries if e["account"] == account), None)
        if entry is None:
            return {"ok": False, "error": "nothing-saved"}
        allow, salt = [entry["phone"]], W.unb64u(entry["salt"])
    else:
        if not isinstance(account, str) or not account or len(account) > 200:
            return {"ok": False, "error": "bad request"}
        pw = m.get("password")
        if not isinstance(pw, str) or not pw or len(pw) > 4096:
            return {"ok": False, "error": "bad request"}
        entry, allow, salt = None, sorted(ph), secrets.token_bytes(32)
    t = now_ms()
    with LOCK:
        for old in [x for x in REQ.values() if t > x["created"] + TTL_MS + 60_000]:   # asked and never collected
            finish(old, {"ok": False, "error": "expired"})
            REQ.pop(old["id"], None)
        log_ = [x for x in ASKS.get(user, []) if t - x <= ASK_WINDOW_MS]
        if not zdecide.ask_ok(ASK_WINDOW_MS, ASK_MAX, t, log_):
            return {"ok": False, "error": "too-many-requests"}
        ASKS[user] = log_ + [t]
        eph = ec.generate_private_key(ec.SECP256R1())
        code = secrets.randbelow(90) + 10
        others = [c for c in range(10, 100) if c != code]
        codes = [code] + [others.pop(secrets.randbelow(len(others))) for _ in range(2)]
        codes = sorted(codes, key=lambda _: secrets.randbits(16))
        r = {"id": secrets.token_urlsafe(18), "kind": kind, "user": user, "pid": pid, "origin": origin,
             "account": account, "created": t, "tls_ok": m.get("tls_ok") is True, "code": code, "codes": codes,
             "eph": eph, "server_key": W.b64u(eph.public_key().public_bytes(serialization.Encoding.X962,
                                                                          serialization.PublicFormat.UncompressedPoint)),
             "salt": W.b64u(salt), "allow": allow, "entry": entry, "secret": m.get("password") if kind == "save" else None,
             "done": threading.Event(), "result": None}
        REQ[r["id"]] = r
    log(event="cred-ask", user=user, kind=kind, origin=origin, id=r["id"][:8])
    return {"ok": True, "id": r["id"], "code": code, "account": account, "expires": t + TTL_MS}


def op_wait(user, pid, m):
    r = REQ.get(m.get("id"))
    if not r or r["user"] != user or r["pid"] != pid:      # only the process that asked gets the answer
        return {"ok": False, "error": "unknown request"}
    left = r["created"] + TTL_MS - now_ms() + 2000
    r["done"].wait(max(0, min(left, TTL_MS + 5000)) / 1000)
    with LOCK:
        if not r["done"].is_set():
            finish(r, {"ok": False, "error": "expired"})
        REQ.pop(r["id"], None)
        return r["result"]


def op_cancel(user, pid, m):
    r = REQ.get(m.get("id"))
    if r and r["user"] == user and r["pid"] == pid:
        with LOCK:
            finish(r, {"ok": False, "error": "cancelled"})
    return {"ok": True}


def finish(r, result):
    """answer a request once (LOCK held): it is used up whatever the answer (cred_once)"""
    if r["done"].is_set():
        return
    mark_used(r["user"], r["id"])
    r["result"], r["secret"], r["eph"] = result, None, None
    r["done"].set()


# ---------- phone side (through ZENOS Messages, same person)
def op_pending(user, m):
    t = now_ms()
    out = []
    ph = phones(user)
    for r in list(REQ.values()):
        if r["user"] != user or r["done"].is_set() or t > r["created"] + TTL_MS:
            continue
        rp = ph[r["allow"][0]]["rp_id"] if r["allow"] and r["allow"][0] in ph else None
        out.append({"id": r["id"], "kind": r["kind"], "origin": r["origin"], "account": r["account"],
                    "created": r["created"], "expires": r["created"] + TTL_MS, "codes": r["codes"],
                    "tls_ok": r["tls_ok"], "core": core(r), "challenge": W.b64u(digest(r)), "salt": r["salt"],
                    "server_key": r["server_key"], "allow": r["allow"], "rp_id": rp})
    return {"ok": True, "pending": sorted(out, key=lambda x: x["created"])}


def op_answer(user, m):
    r = REQ.get(m.get("id"))
    if not r or r["user"] != user:
        return {"ok": False, "error": "unknown request"}
    with LOCK:
        if r["done"].is_set():
            return {"ok": False, "error": "already-answered"}
        if m.get("decline"):
            finish(r, {"ok": False, "error": "declined-on-phone"})
            log(event="cred-declined", user=user, id=r["id"][:8])
            return {"ok": True, "result": "declined"}
        ph = phones(user)
        cid = str(m.get("credential_id") or "")
        dig = digest(r)
        try:
            ad, cd, sig = (W.unb64u(m.get(k) or "") for k in ("authenticator_data", "client_data_json", "signature"))
        except (ValueError, TypeError):
            ad = cd = sig = b""
        facts = W.check_assertion(ph[cid], ad, cd, sig, dig) if cid in ph and cid in r["allow"] else \
            {"sig_ok": False, "challenge_ok": False, "origin_ok": False, "user_verified": False, "counter_ok": False}
        try:
            code = int(m.get("code"))
        except (TypeError, ValueError):
            code = -1
        allow, why = zdecide.cred(TTL_MS, used(user), [{"device": c, "user": user} for c in ph if c in r["allow"]],
                                  {"id": r["id"], "user": user, "origin": r["origin"],
                                   "entry_origin": r["entry"]["origin"] if r["entry"] else r["origin"],
                                   "tls_ok": r["tls_ok"], "code": r["code"], "created": r["created"]},
                                  {"device": cid, "code": code, **{k: facts[k] for k in
                                   ("sig_ok", "challenge_ok", "origin_ok", "user_verified", "counter_ok")}}, now_ms())
        if not allow:
            finish(r, {"ok": False, "error": why})
            log(event="cred-refused", user=user, id=r["id"][:8], reason=why)
            return {"ok": False, "error": why}
        ph[cid]["count"] = facts["count"]
        ph[cid]["used"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        save(user, "phones.json", ph)
        try:                                   # the entry's key, encrypted by the phone to this request's one-time key
            peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), W.unb64u(m.get("phone_key") or ""))
            k = hkdf(r["eph"].exchange(ec.ECDH(), peer), dig, b"zenos-cred-prf")
            prf = AESGCM(k).decrypt(W.unb64u(m.get("iv") or ""), W.unb64u(m.get("ct") or ""), dig)
            if len(prf) != 32:
                raise ValueError
        except Exception:
            finish(r, {"ok": False, "error": "bad-key-envelope"})
            return {"ok": False, "error": "bad-key-envelope"}
        salt = W.unb64u(r["salt"])
        key = entry_key(prf, salt, r["origin"], r["account"])
        if r["kind"] == "fill":
            e = r["entry"]
            try:
                pw = AESGCM(key).decrypt(W.unb64u(e["nonce"]), W.unb64u(e["ct"]), entry_aad(e["origin"], e["account"]))
            except Exception:
                finish(r, {"ok": False, "error": "wrong-phone-key"})
                return {"ok": False, "error": "wrong-phone-key"}
            finish(r, {"ok": True, "account": r["account"], "password": pw.decode()})
        else:
            nonce = secrets.token_bytes(12)
            ct = AESGCM(key).encrypt(nonce, r["secret"].encode(), entry_aad(r["origin"], r["account"]))
            v = [e for e in vault(user) if not (e["origin"] == r["origin"] and e["account"] == r["account"])]
            v.append({"origin": r["origin"], "account": r["account"], "phone": cid, "salt": r["salt"],
                      "nonce": W.b64u(nonce), "ct": W.b64u(ct), "saved": time.strftime("%Y-%m-%dT%H:%M:%S")})
            save(user, "vault.json", v)
            finish(r, {"ok": True, "account": r["account"]})
        log(event="cred-released" if r["kind"] == "fill" else "cred-saved", user=user, id=r["id"][:8],
            origin=r["origin"])
        return {"ok": True, "result": "approved"}


def op_enroll_start(user, m):
    """the phone page starts registering its passkey, with the administrator's one-time code"""
    origin, rp_id = m.get("origin"), m.get("rp_id")
    if not good_origin(origin) or origin != "https://" + str(rp_id):
        return {"ok": False, "error": "the phone page must be served over HTTPS from its own host"}
    with LOCK:
        en = load(user, "enroll.json", {})
        if en.get("tries", 0) >= ENROLL_TRIES or time.time() > en.get("expires", 0):
            return {"ok": False, "error": "no valid enrolment code: ask the administrator for a new one"}
        if time.time() - en.get("last", 0) < ENROLL_GAP:
            return {"ok": False, "error": "wait a moment before trying again"}
        en["tries"], en["last"] = en.get("tries", 0) + 1, time.time()
        save(user, "enroll.json", en)
        code = str(m.get("code") or "").strip()
        if not hmac.compare_digest(hashlib.sha256(code.encode()).hexdigest(), en.get("hash", "")):
            return {"ok": False, "error": "wrong enrolment code"}
        save(user, "enroll.json", {})           # one use
        ch = secrets.token_bytes(32)
        ENROLLING[W.b64u(ch)] = {"user": user, "origin": origin, "rp_id": rp_id, "expires": time.time() + 300}
    return {"ok": True, "challenge": W.b64u(ch), "rp_id": rp_id, "user": user,
            "user_handle": W.b64u(hashlib.sha256(b"zenos-cred-user\0" + user.encode()).digest())}


def op_enroll_finish(user, m):
    with LOCK:
        e = ENROLLING.pop(str(m.get("challenge") or ""), None)
    if not e or e["user"] != user or time.time() > e["expires"]:
        return {"ok": False, "error": "enrolment expired: start again"}
    if not (m.get("prf") is True):
        return {"ok": False, "error": "this phone's passkeys cannot derive keys (WebAuthn PRF): use a newer phone or browser"}
    try:
        p = W.register(W.unb64u(m.get("attestation_object") or ""), W.unb64u(m.get("client_data_json") or ""),
                       W.unb64u(m["challenge"]), e["origin"], e["rp_id"])
    except (W.Bad, ValueError, TypeError) as x:
        return {"ok": False, "error": str(x)}
    p["name"] = str(m.get("name") or "phone")[:80]
    p["created"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    with LOCK:
        ph = phones(user)
        ph[p["cred_id"]] = p
        save(user, "phones.json", ph)
    log(event="cred-phone-enrolled", user=user, phone=p["cred_id"][:12])
    return {"ok": True, "phone": p["cred_id"][:12]}


def handle(m, uid, pid):
    try:
        user = pwd.getpwuid(uid).pw_name
    except KeyError:
        return {"ok": False, "error": "unknown user"}
    kind = caller(pid)
    if kind and any(os.path.exists(u) for u in LAUNCH_UNITS) and not launched(pid, uid, kind):
        kind = None                                    # the right name, but not a process zenos-launchd started
    op = m.get("op")
    if (op in BROWSER_OPS and kind != "browser") or (op in PHONE_OPS and kind != "messenger"):
        log(event="cred-caller-refused", user=user, op=str(op)[:20], pid=pid)
        return {"ok": False, "error": "only the ZENOS Browser and ZENOS Messages may use the sign-in service"}
    return dispatch(user, m, pid)


def dispatch(user, m, pid):
    op = m.get("op")
    if op == "accounts":
        return op_accounts(user, m)
    if op == "ask":
        return op_ask(user, pid, m)
    if op == "wait":
        return op_wait(user, pid, m)
    if op == "cancel":
        return op_cancel(user, pid, m)
    if op == "pending":
        return op_pending(user, m)
    if op == "answer":
        return op_answer(user, m)
    if op == "enroll-start":
        return op_enroll_start(user, m)
    if op == "enroll-finish":
        return op_enroll_finish(user, m)
    return {"ok": False, "error": "unknown op"}


def client(c):
    try:
        pid, uid, _ = struct.unpack("3i", c.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
        c.settimeout(10)
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = c.recv(65536)
            if not chunk:
                break
            buf += chunk
            if len(buf) > MAX_LINE:
                raise ValueError("too large")
        m = json.loads(buf or b"{}")
        if not isinstance(m, dict):
            raise ValueError
        c.settimeout(None)
        out = handle(m, uid, pid)
    except Exception:
        out = {"ok": False, "error": "bad request"}
    try:
        c.sendall((json.dumps(out) + "\n").encode())
    except OSError:
        pass
    c.close()


def cli():
    a = sys.argv[1:]
    if len(a) == 2 and a[0] == "--enroll":
        pwd.getpwnam(a[1])
        code = "%08d" % secrets.randbelow(10 ** 8)
        save(a[1], "enroll.json", {"hash": hashlib.sha256(code.encode()).hexdigest(), "expires": time.time() + ENROLL_TTL,
                                   "tries": 0})
        print("Enrolment code for %s (one use, 15 minutes): %s" % (a[1], code))
        print("On the phone: ZENOS Messages -> Settings -> Sign-in with this phone -> Set up.")
        return 0
    if len(a) == 2 and a[0] == "--phones":
        for k, p in phones(a[1]).items():
            print(k[:12], p.get("name"), p.get("origin"), "enrolled", p.get("created"), "last used", p.get("used", "-"))
        return 0
    if len(a) == 3 and a[0] == "--revoke":
        ph = phones(a[1])
        gone = [k for k in ph if k.startswith(a[2])]
        for k in gone:
            del ph[k]
        save(a[1], "phones.json", ph)
        print("revoked", len(gone), "phone(s); passwords saved with them can no longer be opened")
        return 0
    print("usage: zenos_credd.py [--enroll USER | --phones USER | --revoke USER PHONE]", file=sys.stderr)
    return 2


def main():
    if len(sys.argv) > 1:
        return cli()
    os.makedirs(DATA, mode=0o700, exist_ok=True)
    os.makedirs(os.path.dirname(SOCK), exist_ok=True)
    os.chmod(os.path.dirname(SOCK), 0o755)
    try:
        os.unlink(SOCK)
    except OSError:
        pass
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(SOCK)
    os.chmod(SOCK, 0o666)                 # anyone may ask; the answer depends on who asks (SO_PEERCRED)
    s.listen(16)
    log(event="credd-start")
    while True:
        c, _ = s.accept()
        threading.Thread(target=client, args=(c,), daemon=True).start()


if __name__ == "__main__":
    sys.exit(main())
