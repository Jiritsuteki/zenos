"""ZENOS Data: records kept by a server program with no plaintext and no key at rest.

A server program (a case system, a web service, a staff database) keeps its records here instead of in tables of
plain text. For each record:

  - it is encrypted with its own random key (AES-256-GCM; the record's id, table and level are bound to it);
  - the encrypted record is copied to several storage peers (`zenos_datapeer.py --role store`), which hold only
    ciphertext; any one of them is enough to read it back, and a changed copy does not decrypt;
  - its key is split into n shares of which any k make the key (Shamir's scheme over GF(2^8)), and each share is
    sealed to one key peer (`--role key`), each run by a different party. The shares travel with the record; a
    share opens only at its own peer.

The server keeps no key. To read a record it signs a request naming the record, the person it is for (with that
person's proof of sign-in, which the peers check themselves) and the purpose, and asks the key peers. Each peer
decides on its own facts (zenos-decide "share", formal/ZenosFormal/DataStore.lean) and records its answer in its
own ledger; a share it releases is sealed to a one-time key of this request. With k shares the server makes the
key in memory, decrypts, and forgets the key.

Someone who copies the server's disk, its database and every storage peer gets ciphertext and sealed shares only.
Someone who takes over the running server can read only what the key peers agree to release while they hold it,
for persons who are signed in, and every release is in k ledgers the server does not control.

Equality search: a field can be indexed with a blind index (an HMAC of the value under a key per table that is
itself a ZENOS Data record, read through the key peers when the server starts and kept only in memory). The index
shows which records share a value, not the value. Ranges, sorting and full-text search over protected fields are
not possible this way; such fields are read and filtered after release.
"""
import base64, hashlib, hmac, json, os, secrets, time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

VERSION = 1


class Refused(Exception):
    pass


class Unavailable(Exception):
    pass


def b64(b):
    return base64.b64encode(b).decode()


def unb64(s):
    return base64.b64decode(str(s), validate=True)


def canon(o):
    return json.dumps(o, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def raw(pub):
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def fingerprint(pub_raw):
    return hashlib.sha256(pub_raw).hexdigest()[:16]


# ---------------------------------------------------------------- Shamir's secret sharing over GF(2^8)
# The field of AES (x^8 + x^4 + x^3 + x + 1). Each byte of the secret is the constant term of its own random
# polynomial of degree k-1; share x holds the polynomials' values at x (1..255).
_EXP, _LOG = [0] * 512, [0] * 256
_v = 1
for _i in range(255):
    _EXP[_i] = _v
    _LOG[_v] = _i
    _v ^= (_v << 1) ^ (0x11B if _v & 0x80 else 0)       # multiply by the generator 3
    _v &= 0xFF
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def _mul(a, b):
    return 0 if a == 0 or b == 0 else _EXP[_LOG[a] + _LOG[b]]


def _div(a, b):
    if b == 0:
        raise ZeroDivisionError
    return 0 if a == 0 else _EXP[(_LOG[a] - _LOG[b]) % 255]


def split(secret, k, n):
    """[(x, share bytes)] for x = 1..n; any k of them give `secret` back, fewer give nothing about it"""
    if not 1 <= k <= n <= 255:
        raise ValueError("need 1 <= k <= n <= 255")
    coeffs = [[b] + [secrets.randbelow(256) for _ in range(k - 1)] for b in secret]
    out = []
    for x in range(1, n + 1):
        ys = bytearray()
        for c in coeffs:
            y = 0
            for a in reversed(c):                         # Horner
                y = _mul(y, x) ^ a
            ys.append(y)
        out.append((x, bytes(ys)))
    return out


def combine(shares):
    """the secret from k shares [(x, bytes)] (Lagrange interpolation at 0)"""
    xs = [x for x, _ in shares]
    if len(set(xs)) != len(xs) or any(not 1 <= x <= 255 for x in xs):
        raise ValueError("shares must have distinct x in 1..255")
    if len({len(s) for _, s in shares}) != 1:
        raise ValueError("shares of different lengths")
    out = bytearray(len(shares[0][1]))
    for i, (xi, yi) in enumerate(shares):
        li = 1
        for j, (xj, _) in enumerate(shares):
            if i != j:
                li = _mul(li, _div(xj, xj ^ xi))
        for t in range(len(out)):
            out[t] ^= _mul(yi[t], li)
    return bytes(out)


# ---------------------------------------------------------------- sealing a share to a peer, and back
def _kdf(shared, info):
    return HKDF(hashes.SHA256(), 32, None, info).derive(shared)


def seal_to(pub_raw, data, info):
    """data readable only by the holder of the X25519 key `pub_raw`; `info` (bytes) binds it to its context"""
    e = X25519PrivateKey.generate()
    k = _kdf(e.exchange(X25519PublicKey.from_public_bytes(pub_raw)), b"zenos-data-seal1|" + info)
    n = os.urandom(12)
    return {"eph": b64(raw(e.public_key())), "nonce": b64(n), "ct": b64(AESGCM(k).encrypt(n, data, info))}


def open_sealed(priv, s, info):
    k = _kdf(priv.exchange(X25519PublicKey.from_public_bytes(unb64(s["eph"]))), b"zenos-data-seal1|" + info)
    return AESGCM(k).decrypt(unb64(s["nonce"]), unb64(s["ct"]), info)


def share_info(rid, table, level, x):
    return b"share|%s|%s|%d|%d" % (rid.encode(), table.encode(), int(level), int(x))


def record_aad(rid, table, level):
    return canon({"v": VERSION, "id": rid, "table": table, "level": int(level)})


# ---------------------------------------------------------------- what the key peers are told
def request_core(server, rid, table, level, person, purpose, eph_pub_raw, t=None, nonce=None):
    return {"server": server, "id": rid, "table": table, "level": int(level), "person": person, "purpose": purpose,
            "eph": b64(eph_pub_raw), "t": int(t if t is not None else time.time()),
            "nonce": nonce or secrets.token_hex(16)}


def request_digest(core):
    return hashlib.sha256(canon(core)).digest()


def idp_token(idp_key, person, ttl=3600, now=None):
    """a sign-in proof made by the organization's sign-in service: who, until when. The key peers enrol the sign-in
    service's public key and check this themselves; the server cannot make one."""
    now = int(now if now is not None else time.time())
    body = {"person": person, "iat": now, "exp": now + int(ttl)}
    return {"body": body, "sig": b64(idp_key.sign(canon(body)))}


# ---------------------------------------------------------------- the server's side
class Peer:
    """how the server reaches one peer: `call(path, body) -> dict` (HTTP in use, a direct call in tests)"""
    def __init__(self, name, call, pub_b64=None):
        self.name, self.call = name, call
        self.pub = unb64(pub_b64) if pub_b64 else None


def http_peer(name, url, pub_b64=None, timeout=10):
    import urllib.request, ssl
    from urllib.parse import urlparse
    u = urlparse(url)
    if u.scheme != "https" and u.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("a peer must be reached over https")

    def call(path, body):
        req = urllib.request.Request(url.rstrip("/") + path, data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout,
                                        context=ssl.create_default_context() if u.scheme == "https" else None) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            try:
                return json.loads(e.read())
            except Exception:
                return {"ok": False, "error": "http %d" % e.code}
    return Peer(name, call, pub_b64)


class Store:
    """a server's ZENOS Data: `key_peers` (each with its X25519 public key), the threshold `k`, `stores`"""

    def __init__(self, server, key, key_peers, k, stores, min_copies=None):
        if not 1 <= k <= len(key_peers):
            raise ValueError("the threshold must be between 1 and the number of key peers")
        self.server, self.key = server, key                  # the server's enrolled Ed25519 key
        self.key_peers, self.k, self.stores = list(key_peers), int(k), list(stores)
        self.min_copies = min_copies or max(1, len(self.stores) // 2 + 1)
        self._index_keys = {}

    # ---- writing
    def put(self, table, value, level, rid=None):
        """encrypt and place one record; returns its id. `value` is any JSON value."""
        rid = rid or secrets.token_hex(16)
        dek = AESGCM.generate_key(bit_length=256)
        n = os.urandom(12)
        ct = AESGCM(dek).encrypt(n, canon(value), record_aad(rid, table, level))
        shares = []
        for (x, y), p in zip(split(dek, self.k, len(self.key_peers)), self.key_peers):
            shares.append({"peer": p.name, "x": x, "sealed": seal_to(p.pub, y, share_info(rid, table, level, x))})
        rec = {"v": VERSION, "id": rid, "table": table, "level": int(level), "nonce": b64(n), "ct": b64(ct),
               "k": self.k, "shares": shares}
        body = {"server": self.server, "record": rec, "t": int(time.time())}
        body["sig"] = b64(self.key.sign(canon({k2: v for k2, v in body.items() if k2 != "sig"})))
        placed = 0
        for s in self.stores:
            try:
                if s.call("/v1/put", body).get("ok"):
                    placed += 1
            except Exception:
                pass
        if placed < self.min_copies:
            raise Unavailable(f"placed on {placed} storage peers, {self.min_copies} needed")
        return rid

    # ---- reading
    def fetch(self, rid):
        """the encrypted record from the first storage peer that has it (a changed copy fails to decrypt later and
        the next copy is tried)"""
        body = {"server": self.server, "id": rid, "t": int(time.time())}
        body["sig"] = b64(self.key.sign(canon(body)))
        for s in self.stores:
            try:
                r = s.call("/v1/get", body)
            except Exception:
                continue
            if r.get("ok") and isinstance(r.get("record"), dict) and r["record"].get("id") == rid:
                yield r["record"]

    def get(self, rid, person, proof, purpose):
        """the record's value, for `person` (signed in: `proof` from the sign-in service) and `purpose`"""
        last = Unavailable("no storage peer has the record")
        for rec in self.fetch(rid):
            try:
                dek = self._key(rec, person, proof, purpose)
            except Refused:
                raise
            except Exception as e:                        # this copy's shares do not open: try the next copy
                last = e
                continue
            try:
                v = AESGCM(dek).decrypt(unb64(rec["nonce"]), unb64(rec["ct"]),
                                        record_aad(rec["id"], rec["table"], rec["level"]))
            except Exception:
                last = Unavailable("a storage peer's copy was changed")
                continue
            finally:
                dek = None
            return json.loads(v)
        raise last

    def _key(self, rec, person, proof, purpose):
        eph = X25519PrivateKey.generate()
        core = request_core(self.server, rec["id"], rec["table"], rec["level"], person, purpose,
                            raw(eph.public_key()))
        sig = b64(self.key.sign(canon(core)))
        got, reasons = [], {}
        by_peer = {s["peer"]: s for s in rec["shares"]}
        for p in self.key_peers:
            if len(got) >= rec["k"]:
                break
            s = by_peer.get(p.name)
            if not s:
                continue
            try:
                a = p.call("/v1/share", {"request": core, "sig": sig, "proof": proof, "x": s["x"], "sealed": s["sealed"]})
            except Exception as e:
                reasons[p.name] = "unreachable"
                continue
            if not a.get("ok"):
                reasons[p.name] = a.get("reason") or a.get("error") or "refused"
                continue
            try:
                y = open_sealed(eph, a["share"], b"answer|" + request_digest(core) + b"|%d" % s["x"])
            except Exception:
                reasons[p.name] = "bad answer"
                continue
            got.append((s["x"], y))
        if len(got) < rec["k"]:
            refusals = {v for v in reasons.values() if v not in ("unreachable", "bad answer")}
            msg = f"{len(got)} of {rec['k']} key peers released their share: " + \
                  ", ".join(f"{n}: {r}" for n, r in sorted(reasons.items()))
            raise (Refused if refusals else Unavailable)(msg)
        return combine(got)

    # ---- blind index for equality lookups
    def index_key(self, table, person, proof, purpose="index"):
        if table not in self._index_keys:
            rid = "index-" + hashlib.sha256(table.encode()).hexdigest()[:24]
            try:
                v = self.get(rid, person, proof, purpose)
            except Unavailable as e:
                if "no storage peer has the record" not in str(e):
                    raise
                self.put(table + ".index", {"key": b64(secrets.token_bytes(32))}, 0, rid=rid)
                v = self.get(rid, person, proof, purpose)
            self._index_keys[table] = unb64(v["key"])
        return self._index_keys[table]

    def blind(self, table, field, value, person, proof):
        k = self.index_key(table, person, proof)
        return hmac.new(k, canon([table, field, value]), hashlib.sha256).hexdigest()
