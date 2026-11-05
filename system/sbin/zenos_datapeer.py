#!/usr/bin/env python3
"""ZENOS Data peer: a key peer or a storage peer for servers that keep their records with ZENOS Data (zdata.py).

  zenos_datapeer.py --role key   --state DIR [--host H --port P --cert C --key K]
  zenos_datapeer.py --role store --state DIR [...]
  zenos_datapeer.py --state DIR --pub              this peer's public key (key peers: the X25519 key shares are
                                                   sealed to; give it to the servers' administrators)

A key peer holds one X25519 key. Shares of record keys are sealed to it and travel with the records; the peer stores
none of them. For each request it decides on its own facts (zenos-decide "share", DataStore.lean): the server is
enrolled and signed this request now (never twice), the audit node heard from the server recently, the person is
signed in (a token of a sign-in service this peer enrolled, checked here), the purpose is registered for the server
and the table, the person's clearance (as this peer holds it) covers the record's level or a grant names the record,
and the rate limits. Only then does it open its share and seal it to the request's one-time key. Every answer, yes
or no, goes into this peer's own ledger (DIR/ledger.jsonl, hash-chained).

A share is sealed together with the record's id, table and level: a server that names a lower level or another
record in its request cannot open it ("share-mismatch" in the ledger).

A storage peer keeps encrypted records from enrolled servers (signed puts) and gives them back on signed requests.
It never sees a key.

DIR/conf.json, or the file named with --conf (edited by the peer's own administrator, not by the servers):
  {"servers": {"cases": {"pub": "<Ed25519, base64>", "purposes": {"cases": ["casework", "audit"]},
                         "rate_max": 600}},
   "idps": ["<the sign-in service's Ed25519 public key, base64>"],
   "clearance": {"tanaka": 3, "sato": 4},       grants: {"<record id>": ["sato"]},
   "rate_max": 30, "window": 60, "skew": 120, "silence": 90,
   "audit": {"url": "https://audit.example", "pub": "<base64>"} | "off"}
With "audit": "off" the silence check is not made (testing only); with no "audit" at all every request is refused.
"""
import argparse, json, os, re, ssl, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "lib", "zenos"))
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "lib"))
sys.path.append(os.path.dirname(os.path.realpath(__file__)))
import zdata, zdecide, zledger                                    # noqa: E402
from cryptography.hazmat.primitives import serialization          # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey   # noqa: E402
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey   # noqa: E402

RID = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
MAX_RECORD = 8 * 1024 * 1024


class Peer:
    def __init__(self, state, role, audit=None, now=time.time, conf_path=None):
        self.dir, self.role, self.now = Path(state), role, now
        self.conf_path = Path(conf_path) if conf_path else self.dir / "conf.json"
        self.dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.dir, 0o700)
        kf = self.dir / "peer.key"
        if not kf.exists():
            k = X25519PrivateKey.generate()
            tmp = kf.with_suffix(".tmp")
            tmp.write_bytes(k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                            serialization.NoEncryption()))
            os.chmod(tmp, 0o600)
            os.replace(tmp, kf)
        self.xkey = X25519PrivateKey.from_private_bytes(kf.read_bytes())
        self.audit = audit
        self.lock = threading.Lock()
        self.rates, self.nonces = {}, {}
        (self.dir / "records").mkdir(exist_ok=True)

    def pub_b64(self):
        return zdata.b64(zdata.raw(self.xkey.public_key()))

    def conf(self):
        try:
            return json.loads(self.conf_path.read_text())
        except (OSError, ValueError):
            return {}

    def log(self, event, actor, **kw):
        zledger.append(str(self.dir / "ledger.jsonl"), event, actor, "datapeer-" + self.role, **kw)

    def _server_sig_ok(self, c, server, body, sig):
        s = (c.get("servers") or {}).get(server)
        if not s:
            return None, False
        try:
            Ed25519PublicKey.from_public_bytes(zdata.unb64(s["pub"])).verify(zdata.unb64(sig), zdata.canon(body))
            return s, True
        except Exception:
            return s, False

    def _fresh(self, c, server, t, nonce):
        now = self.now()
        if abs(now - float(t)) > float(c.get("skew", 120)):
            return False
        with self.lock:
            seen = self.nonces.setdefault(server, {})
            for n, at in list(seen.items()):
                if now - at > 2 * float(c.get("skew", 120)):
                    del seen[n]
            if nonce in seen:
                return False
            seen[nonce] = now
        return True

    def _person_ok(self, c, person, proof):
        try:
            body, sig = proof["body"], zdata.unb64(proof["sig"])
        except (KeyError, TypeError, ValueError):
            return False
        for idp in c.get("idps") or []:
            try:
                Ed25519PublicKey.from_public_bytes(zdata.unb64(idp)).verify(sig, zdata.canon(body))
            except Exception:
                continue
            now = self.now()
            return body.get("person") == person and float(body.get("iat", now + 1)) <= now + 5 \
                and now <= float(body.get("exp", 0))
        return False

    def _last_seen(self, c, server):
        a = c.get("audit")
        if a == "off":
            return self.now()
        if not a:
            return 0
        try:
            h = (self.audit or _node_audit(a)).health(server)
            return float((h or {}).get("last_seen") or 0)
        except Exception:
            return 0

    def _recent(self, key, window):
        now = self.now()
        with self.lock:
            log = [t for t in self.rates.get(key, []) if now - t <= window]
            self.rates[key] = log
            return len(log)

    def _count(self, key):
        with self.lock:
            self.rates.setdefault(key, []).append(self.now())

    # ---------------------------------------------------------------- key peer
    def share(self, b):
        if self.role != "key":
            return 404, {"ok": False, "error": "not a key peer"}
        c = self.conf()
        try:
            core, sig, proof, x, sealed = b["request"], b["sig"], b.get("proof") or {}, int(b["x"]), b["sealed"]
            server, rid, table, level = core["server"], core["id"], core["table"], int(core["level"])
            person, purpose = str(core["person"]), str(core["purpose"])
            if not (NAME.match(server) and RID.match(rid) and NAME.match(table) and NAME.match(person)
                    and 0 <= level <= 5 and 1 <= x <= 255):
                raise ValueError
            eph = zdata.unb64(core["eph"])
        except (KeyError, TypeError, ValueError):
            return 400, {"ok": False, "error": "bad request"}
        s, sig_ok = self._server_sig_ok(c, server, core, sig)
        enrolled = s is not None
        window = float(c.get("window", 60))
        facts = {"op": "share", "enrolled": enrolled, "sig_ok": sig_ok,
                 "fresh": bool(sig_ok and self._fresh(c, server, core.get("t", 0), str(core.get("nonce", "")))),
                 "now": int(self.now()), "last_seen": int(self._last_seen(c, server)) if enrolled else 0,
                 "silence": int(c.get("silence", 90)), "person_verified": self._person_ok(c, person, proof),
                 "purpose_ok": enrolled and purpose in ((s.get("purposes") or {}).get(table) or []),
                 "level": level, "clearance": max(0, min(5, int((c.get("clearance") or {}).get(person, 0)))),
                 "grant_ok": person in ((c.get("grants") or {}).get(rid) or []),
                 "recent": self._recent(("p", server, person), window), "rate_max": int(c.get("rate_max", 30)),
                 "server_recent": self._recent(("s", server), window),
                 "server_rate_max": int((s or {}).get("rate_max", 600))}
        try:
            ans = zdecide.ask(facts)
        except Exception as e:
            ans = {"allow": False, "reason": "no decision: %s" % e}
        what = dict(server=server, id=rid, table=table, level=level, purpose=purpose)
        if not ans.get("allow"):
            self.log("share-refused", person, reason=ans.get("reason"), **what)
            return 403, {"ok": False, "reason": ans.get("reason")}
        try:
            y = zdata.open_sealed(self.xkey, sealed, zdata.share_info(rid, table, level, x))
        except Exception:
            self.log("share-mismatch", person, **what)
            return 403, {"ok": False, "reason": "share-mismatch"}
        self._count(("p", server, person))
        self._count(("s", server))
        self.log("share-released", person, **what)
        return 200, {"ok": True, "share": zdata.seal_to(eph, y, b"answer|" + zdata.request_digest(core) + b"|%d" % x)}

    # ---------------------------------------------------------------- storage peer
    def put(self, b):
        if self.role != "store":
            return 404, {"ok": False, "error": "not a storage peer"}
        c = self.conf()
        try:
            server, rec, sig = b["server"], b["record"], b["sig"]
            rid = rec["id"]
            if not (NAME.match(server) and RID.match(rid)) or len(json.dumps(rec)) > MAX_RECORD:
                raise ValueError
        except (KeyError, TypeError, ValueError):
            return 400, {"ok": False, "error": "bad request"}
        s, ok = self._server_sig_ok(c, server, {k: v for k, v in b.items() if k != "sig"}, sig)
        if not ok or not self._fresh(c, server, b.get("t", 0), "put:" + zdata.b64(zdata.request_digest(b))):
            self.log("put-refused", server, id=rid)
            return 403, {"ok": False, "error": "not an enrolled server, or not signed now"}
        p = self.dir / "records" / f"{rid}.json"
        if p.exists():
            try:
                if json.loads(p.read_text()).get("server") != server:
                    self.log("put-refused", server, id=rid, reason="owned by another server")
                    return 403, {"ok": False, "error": "owned by another server"}
            except (OSError, ValueError):
                pass
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps({"server": server, "record": rec}))
        os.replace(tmp, p)
        self.log("put", server, id=rid, table=str(rec.get("table")), level=rec.get("level"))
        return 200, {"ok": True}

    def get(self, b):
        if self.role != "store":
            return 404, {"ok": False, "error": "not a storage peer"}
        c = self.conf()
        try:
            server, rid, sig = b["server"], b["id"], b["sig"]
            if not (NAME.match(server) and RID.match(rid)):
                raise ValueError
        except (KeyError, TypeError, ValueError):
            return 400, {"ok": False, "error": "bad request"}
        s, ok = self._server_sig_ok(c, server, {k: v for k, v in b.items() if k != "sig"}, sig)
        if not ok or abs(self.now() - float(b.get("t", 0))) > float(c.get("skew", 120)):
            return 403, {"ok": False, "error": "not an enrolled server, or not signed now"}
        p = self.dir / "records" / f"{rid}.json"
        try:
            d = json.loads(p.read_text())
        except (OSError, ValueError):
            return 404, {"ok": False, "error": "no such record"}
        if d.get("server") != server:
            return 404, {"ok": False, "error": "no such record"}
        return 200, {"ok": True, "record": d["record"]}


def _node_audit(a):
    import zenos_keysvc
    return zenos_keysvc.NodeAudit(a["url"], a["pub"])


def serve(peer, host, port, cert=None, key=None):
    class H(BaseHTTPRequestHandler):
        def reply(self, code, obj):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            m = re.match(r"^/v1/(share|put|get)$", self.path)
            if not m:
                return self.reply(404, {"ok": False})
            n = int(self.headers.get("Content-Length") or 0)
            if n <= 0 or n > MAX_RECORD + 65536:
                return self.reply(413, {"ok": False, "error": "too large"})
            try:
                b = json.loads(self.rfile.read(n))
            except Exception:
                return self.reply(400, {"ok": False, "error": "not JSON"})
            self.reply(*getattr(peer, m.group(1))(b))

        def do_GET(self):
            if self.path == "/v1/peer":
                return self.reply(200, {"ok": True, "role": peer.role, "pub": peer.pub_b64()})
            self.reply(404, {"ok": False})

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer((host, port), H)
    if cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cert, key)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print(f"ZENOS Data {peer.role} peer on {host}:{port} ({'TLS' if cert else 'plain HTTP, local testing only'})",
          flush=True)
    srv.serve_forever()


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--state", required=True)
    ap.add_argument("--role", choices=["key", "store"], default="key")
    ap.add_argument("--conf", help="the peer's settings (default: STATE/conf.json)")
    ap.add_argument("--pub", action="store_true")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8470)
    ap.add_argument("--cert")
    ap.add_argument("--key")
    a = ap.parse_args()
    p = Peer(a.state, a.role, conf_path=a.conf)
    if a.pub:
        print(p.pub_b64())
        return
    if a.host not in ("127.0.0.1", "localhost", "::1") and not a.cert:
        sys.exit("a peer reachable from other machines needs TLS (--cert, --key)")
    serve(p, a.host, a.port, a.cert, a.key)


if __name__ == "__main__":
    main()
