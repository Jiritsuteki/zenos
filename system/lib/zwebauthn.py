"""Passkey (WebAuthn) checks for phone sign-in: registering a phone's passkey and checking its signatures.

Only what ZENOS needs: ES256 (P-256) and EdDSA (Ed25519) passkeys, attestation "none" (a phone is trusted because the
person registered it with an enrolment code from the PC's administrator, not because of its maker's certificate).
The checks return facts; whether a password is released is decided by `zenos-decide` (ZenosFormal/Cred.lean).
"""
import base64, hashlib, json, struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

FLAG_UP, FLAG_UV, FLAG_BS, FLAG_AT, FLAG_ED = 0x01, 0x04, 0x10, 0x40, 0x80


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s):
    s = str(s)
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class Bad(ValueError):
    pass


# ---------- CBOR: the subset authenticators use (RFC 8949 major types 0-5, 7 simple values)
def _cbor(b, i, depth=0):
    if depth > 16 or i >= len(b):
        raise Bad("cbor")
    ib = b[i]; i += 1
    mt, ai = ib >> 5, ib & 31
    if ai < 24:
        n = ai
    elif ai in (24, 25, 26, 27):
        k = 1 << (ai - 24)
        if i + k > len(b):
            raise Bad("cbor")
        n = int.from_bytes(b[i:i + k], "big"); i += k
    else:
        raise Bad("cbor: indefinite lengths are not used")
    if mt == 0:
        return n, i
    if mt == 1:
        return -1 - n, i
    if mt in (2, 3):
        if i + n > len(b):
            raise Bad("cbor")
        v = bytes(b[i:i + n]); i += n
        return (v if mt == 2 else v.decode()), i
    if mt == 4:
        out = []
        for _ in range(n):
            v, i = _cbor(b, i, depth + 1); out.append(v)
        return out, i
    if mt == 5:
        out = {}
        for _ in range(n):
            k, i = _cbor(b, i, depth + 1); v, i = _cbor(b, i, depth + 1); out[k] = v
        return out, i
    if mt == 7:
        return {20: False, 21: True, 22: None}.get(ai, None), i
    raise Bad("cbor: tags are not used")


def cbor_decode(b, i=0):
    return _cbor(b, i)


# ---------- keys
def cose_to_spki(cose):
    """COSE public key (dict) -> (SubjectPublicKeyInfo DER, alg)"""
    kty, alg = cose.get(1), cose.get(3)
    if kty == 2 and alg == -7 and cose.get(-1) == 1:
        x, y = cose.get(-2), cose.get(-3)
        if not (isinstance(x, bytes) and isinstance(y, bytes) and len(x) == 32 and len(y) == 32):
            raise Bad("bad P-256 key")
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + x + y)
    elif kty == 1 and alg == -8 and cose.get(-1) == 6:
        x = cose.get(-2)
        if not (isinstance(x, bytes) and len(x) == 32):
            raise Bad("bad Ed25519 key")
        pub = ed25519.Ed25519PublicKey.from_public_bytes(x)
    else:
        raise Bad("unsupported passkey type")
    return pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo), alg


def verify_sig(spki, alg, sig, msg):
    try:
        pub = serialization.load_der_public_key(spki)
        if alg == -7 and isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
        elif alg == -8 and isinstance(pub, ed25519.Ed25519PublicKey):
            pub.verify(sig, msg)
        else:
            return False
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


# ---------- authenticator data and client data
def parse_auth_data(ad):
    if len(ad) < 37:
        raise Bad("authenticator data too short")
    out = {"rp_id_hash": ad[:32], "flags": ad[32], "count": struct.unpack(">I", ad[33:37])[0]}
    i = 37
    if out["flags"] & FLAG_AT:
        if len(ad) < i + 18:
            raise Bad("authenticator data too short")
        n = struct.unpack(">H", ad[i + 16:i + 18])[0]
        out["cred_id"] = ad[i + 18:i + 18 + n]
        if len(out["cred_id"]) != n:
            raise Bad("authenticator data too short")
        out["cose"], i = cbor_decode(ad, i + 18 + n)
    return out


def client_data(raw):
    try:
        cd = json.loads(raw)
    except ValueError:
        raise Bad("client data is not JSON")
    if not isinstance(cd, dict):
        raise Bad("client data is not an object")
    return cd


def register(attestation_object, client_data_json, challenge, origin, rp_id):
    """A phone's new passkey. Raises Bad unless it was made on the phone page `origin` for `rp_id` over `challenge`,
    with the person verified. Returns what is stored for the phone."""
    cd = client_data(client_data_json)
    if cd.get("type") != "webauthn.create" or cd.get("challenge") != b64u(challenge) or cd.get("origin") != origin:
        raise Bad("the passkey was not made for this enrolment")
    att, _ = cbor_decode(attestation_object)
    if not isinstance(att, dict) or not isinstance(att.get("authData"), bytes):
        raise Bad("bad attestation object")
    ad = parse_auth_data(att["authData"])
    if ad["rp_id_hash"] != hashlib.sha256(rp_id.encode()).digest():
        raise Bad("the passkey belongs to another site")
    if not (ad["flags"] & FLAG_UP and ad["flags"] & FLAG_UV):
        raise Bad("the phone did not verify the person (fingerprint, face or PIN)")
    if "cose" not in ad:
        raise Bad("no public key in the attestation")
    spki, alg = cose_to_spki(ad["cose"])
    return {"cred_id": b64u(ad["cred_id"]), "public_key": b64u(spki), "alg": alg, "rp_id": rp_id, "origin": origin,
            "count": ad["count"]}


def check_assertion(phone, authenticator_data, client_data_json, signature, challenge):
    """Facts about one passkey signature from a registered phone (never raises on bad input: facts are False)."""
    f = {"sig_ok": False, "challenge_ok": False, "origin_ok": False, "user_verified": False, "counter_ok": False,
         "count": None, "synced": None}
    try:
        ad = parse_auth_data(authenticator_data)
        cd = client_data(client_data_json)
    except Bad:
        return f
    msg = authenticator_data + hashlib.sha256(client_data_json).digest()
    f["sig_ok"] = verify_sig(unb64u(phone["public_key"]), phone["alg"], signature, msg)
    f["challenge_ok"] = cd.get("type") == "webauthn.get" and cd.get("challenge") == b64u(challenge)
    f["origin_ok"] = (cd.get("origin") == phone["origin"] and not cd.get("crossOrigin")
                      and ad["rp_id_hash"] == hashlib.sha256(phone["rp_id"].encode()).digest())
    f["user_verified"] = bool(ad["flags"] & FLAG_UP and ad["flags"] & FLAG_UV)
    old, new = int(phone.get("count") or 0), ad["count"]
    f["counter_ok"] = (old == 0 and new == 0) or new > old       # a counter that does not move forward: a cloned key
    f["count"] = new
    f["synced"] = bool(ad["flags"] & FLAG_BS)                     # kept in a synced store (iCloud Keychain and the like)
    return f
