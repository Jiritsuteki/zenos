"""An officer's signature on a request: an Ed25519 key in the browser (until now), or a passkey in the phone's secure
chip (iPhone: Secure Enclave; Android: the hardware key store).

Enrolled officers' keys are in /etc/zenos/approvers (root only writes there):
  <name>.pub            a raw Ed25519 public key (the browser key, WebCrypto non-extractable)
  <name>.passkey.json   a passkey: {"cred_id", "public_key" (SPKI, base64url), "alg", "rp_id", "origin", "count",
                        "transports"} (zenos_guardd.py --enroll-passkey)
When both exist the passkey is used: enrolling a passkey is how an officer moves off the browser key.

A passkey signature arrives as JSON: {"passkey": 1, "credential_id", "authenticator_data", "client_data_json",
"signature" (base64url), "attachment", "exception"}. The passkey signs the request's message itself (the digest of
the request: which PC, which file, who, when; "decline:" + digest to decline) as the WebAuthn challenge. The facts
(zwebauthn.check_assertion) go to the proven decision (formal/ZenosFormal/Approval.lean, zenos-decide
"passkey_approval"), with whether the phone was near the PC: an approval made on the PC's screen with a phone that
read the PC's QR code (the passkey standard's cross-device sign-in, which checks over Bluetooth that the phone is
close) reports "cross-platform". The PC's own browser reports it; it is not part of the signature, so it is as good
as the PC (ZENOS) is.

Policy: /etc/zenos/approval.json {"near_from_level": 3, "exceptions": false}
  near_from_level   from this level up, an approval must be made with the phone near the PC (0: never required)
  exceptions        true lets an officer approve from afar by saying so ("exception": "remote"); it is written to
                    the ledger every time
"""
import base64, hashlib, json, os
from pathlib import Path

try:
    from . import zwebauthn
except ImportError:
    import zwebauthn

POLICY = Path(os.environ.get("ZENOS_APPROVAL_POLICY", "/etc/zenos/approval.json"))


class Refused(Exception):
    pass


def policy():
    try:
        p = json.loads(POLICY.read_text())
    except FileNotFoundError:
        return {"near_from_level": 0, "exceptions": True}
    except (OSError, ValueError):
        return {"near_from_level": 1, "exceptions": False}      # a broken policy never loosens the check
    return {"near_from_level": max(0, int(p.get("near_from_level", 0) or 0)), "exceptions": bool(p.get("exceptions", False))}


def kind(pub_dir, name):
    name = os.path.basename(str(name))
    d = Path(pub_dir)
    if (d / f"{name}.passkey.json").exists():
        return "passkey"
    if (d / f"{name}.pub").exists():
        return "ed25519"
    return None


def enrolled(pub_dir, name):
    return kind(pub_dir, name) is not None


def roster(pub_dir):
    d = Path(pub_dir)
    if not d.is_dir():
        return []
    return sorted({p.name[:-len(".passkey.json")] if p.name.endswith(".passkey.json") else p.stem
                   for p in d.iterdir() if p.name.endswith(".pub") or p.name.endswith(".passkey.json")})


SEEN_MAX = 4096


def _save(cf, counts):
    try:
        cf.parent.mkdir(parents=True, exist_ok=True)
        tmp = cf.with_name(cf.name + ".tmp")
        tmp.write_text(json.dumps(counts))
        os.replace(tmp, cf)
    except OSError:
        pass


def _counter_file(state):
    return Path(state) if state else None


def check(pub_dir, name, sig, message, level=0, state=None, pol=None):
    """(ok, reason, facts) for one officer's signature over `message` (bytes). Never raises on bad input."""
    import zdecide
    name = os.path.basename(str(name))
    k = kind(pub_dir, name)
    pol = pol or policy()
    near_required = pol["near_from_level"] > 0 and int(level) >= pol["near_from_level"]
    if k is None:
        return False, "not-enrolled", {}
    if k == "ed25519":
        if isinstance(sig, str) and sig.lstrip().startswith("{"):
            return False, "signature", {}
        if near_required:
            # a key in a browser cannot show that the phone was near the PC
            return False, "phone-not-near", {"key": "ed25519"}
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            Ed25519PublicKey.from_public_bytes((Path(pub_dir) / f"{name}.pub").read_bytes()).verify(
                base64.b64decode(sig), message)
            return True, None, {"key": "ed25519"}
        except Exception:
            return False, "signature", {"key": "ed25519"}
    try:
        phone = json.loads((Path(pub_dir) / f"{name}.passkey.json").read_text())
        a = json.loads(sig) if isinstance(sig, str) else sig
        if not isinstance(a, dict) or a.get("passkey") != 1:
            raise ValueError("not a passkey signature")
        if a.get("credential_id") != phone.get("cred_id"):
            raise ValueError("another passkey")
        ad, cdj, s = (zwebauthn.unb64u(a[x]) for x in ("authenticator_data", "client_data_json", "signature"))
    except (OSError, ValueError, KeyError, TypeError):
        return False, "signature", {"key": "passkey"}
    cf = _counter_file(state)
    try:
        counts = json.loads(cf.read_text()) if cf and cf.exists() else {}
    except (OSError, ValueError):
        counts = {}
    # every passkey signature is taken once, whatever the outcome: many phones keep the signature counter at 0, and
    # "attachment" is not signed, so the same signature sent again with another claim must not count
    counts = counts if isinstance(counts, dict) else {}
    seen = counts.get("_seen") if isinstance(counts.get("_seen"), list) else []
    sh = hashlib.sha256(s).hexdigest()
    if cf:
        if sh in seen:
            return False, "replayed", {"key": "passkey", "credential": phone.get("cred_id")}
        counts["_seen"] = (seen + [sh])[-SEEN_MAX:]
        _save(cf, counts)
    phone = dict(phone, count=max(int(phone.get("count") or 0), int(counts.get(phone["cred_id"], 0))))
    f = zwebauthn.check_assertion(phone, ad, cdj, s, message)
    near = a.get("attachment") == "cross-platform"
    exc = a.get("exception") == "remote"
    facts = {"key": "passkey", "credential": phone["cred_id"], **{k2: v for k2, v in f.items() if k2 != "count"}, "near": near,
             "near_required": near_required, "exception_allowed": pol["exceptions"], "exception_used": exc}
    try:
        ans = zdecide.ask({"op": "passkey_approval", "sig_ok": f["sig_ok"], "challenge_ok": f["challenge_ok"],
                           "origin_ok": f["origin_ok"], "user_verified": f["user_verified"],
                           "counter_ok": f["counter_ok"], "near": near, "near_required": near_required,
                           "exception_allowed": pol["exceptions"], "exception_used": exc})
    except Exception as e:
        return False, "no decision: %s" % e, facts
    if not ans.get("ok"):
        return False, ans.get("reason") or "refused", facts
    if cf and f.get("count"):
        counts[phone["cred_id"]] = f["count"]
        _save(cf, counts)
    facts["exception"] = bool(near_required and not near and exc)
    return True, None, facts


def ledger_fields(facts):
    """what the ledger keeps about one approval's key: which key (the passkey's ID; there is no phone serial number,
    and a synced passkey has the same ID on all of the officer's devices), whether the phone was near the PC, whether
    it was an exception, and whether the passkey is synced"""
    out = {"key": facts.get("key")}
    if facts.get("key") == "passkey":
        out.update(credential=facts.get("credential"), near=bool(facts.get("near")),
                   user_verified=bool(facts.get("user_verified")), synced=facts.get("synced"),
                   exception=bool(facts.get("exception")))
    return {k: v for k, v in out.items() if v is not None}


def enroll_passkey(pub_dir, name, reg):
    """write an officer's passkey (the result of zwebauthn.register) as their approval key"""
    import re
    if not re.fullmatch(r"[a-z0-9_.-]{1,32}", str(name)):
        raise Refused("bad officer name")
    need = ("cred_id", "public_key", "alg", "rp_id", "origin")
    if not isinstance(reg, dict) or any(k not in reg for k in need):
        raise Refused("not a passkey registration")
    zwebauthn.unb64u(reg["public_key"])
    d = Path(pub_dir)
    d.mkdir(parents=True, exist_ok=True)
    tmp = d / f".{name}.passkey.json.tmp"
    tmp.write_text(json.dumps({k: reg[k] for k in need + ("count", "transports") if k in reg}))
    os.chmod(tmp, 0o644)
    os.replace(tmp, d / f"{name}.passkey.json")
    return hashlib.sha256(zwebauthn.unb64u(reg["public_key"])).hexdigest()[:16].upper()
