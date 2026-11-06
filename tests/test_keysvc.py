"""The key service: sealed files whose key is not on the PC.
Run: python3 -m unittest discover -s tests   (no root; the service runs on 127.0.0.1 in this process)"""
import base64, hashlib, importlib, json, os, pwd, socket, sys, tempfile, threading, time, unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path[0:0] = [str(REPO / "system" / "lib"), str(REPO / "system" / "sbin")]
import zkeysvc, zwebauthn                                                  # noqa: E402
import zenos_keysvc                                                       # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey   # noqa: E402
from cryptography.hazmat.primitives import serialization                          # noqa: E402

MACHINE = "pc-test"
RP, ORIGIN = "zenos.local", "https://zenos.local"


def raw_pub(k):
    return k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class KeyService(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="zenos-keysvc-"))
        cls.user = pwd.getpwuid(os.getuid()).pw_name
        cls.audit = cls.tmp / "audit"
        (cls.audit / "machines").mkdir(parents=True)
        (cls.audit / "chains").mkdir()
        cls.svc = zenos_keysvc.Service(cls.tmp / "svc", cls.audit, silence=90, rate_max=1000, rate_window=60,
                                       presence_from=6)
        cls.port = free_port()
        threading.Thread(target=zenos_keysvc.serve, args=(cls.svc, "127.0.0.1", cls.port), kwargs={"reconcile_every": 3600},
                         daemon=True).start()
        # the PC: keyd with its own (local) stores, configured for the key service
        d = cls.tmp / "pc"
        d.mkdir()
        cls.saved = (zkeysvc.CONF, zkeysvc.ID_KEY)
        zkeysvc.CONF, zkeysvc.ID_KEY = d / "keysvc.json", d / "audit-device.key"
        cls.conf = {"url": f"http://127.0.0.1:{cls.port}", "pub": cls.svc.pub_b64(), "machine": MACHINE}
        zkeysvc.CONF.write_text(json.dumps(cls.conf))
        os.environ.update(ZENOS_KEYD_KEYS=str(d / "keys"), ZENOS_CLEARANCE=str(d / "clearance"),
                          ZENOS_APPROVERS=str(d / "approvers"), ZENOS_KEYD_LOG=str(d / "keyd.jsonl"),
                          ZENOS_KEYD_LEDGER=str(d / "ledger.jsonl"), ZENOS_EXPOSED=str(d / "exposed.json"),
                          ZENOS_AIGUARD_SOCK=str(d / "aiguard.sock"), ZENOS_OPEN_HOLDERS=str(d / "holders.json"), ZENOS_HALT=str(d / "halt.json"),
                          ZENOS_RESEAL_STATE=str(d / "reseal.json"))
        import zenos_keyd
        cls.K = importlib.reload(zenos_keyd)
        cls.K.ensure_keys()
        (d / "clearance").write_text(f"{cls.user} = 5\n")       # the PC claims everything; the service decides
        (d / "approvers").mkdir()
        cls.officers = {n: Ed25519PrivateKey.generate() for n in ("sato", "tanaka")}
        for n, k in cls.officers.items():
            (d / "approvers" / f"{n}.pub").write_bytes(raw_pub(k))
            cls.svc.add_approver(n, base64.b64encode(raw_pub(k)).decode())
        cls.svc.enroll(MACHINE, base64.b64encode(zkeysvc.identity_key().pub()).decode())
        cls.svc.set_clearance(cls.user, 3)
        cls.svc.assign(MACHINE, cls.user)
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", cls.port), timeout=1).close()
                break
            except OSError:
                time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        zkeysvc.CONF, zkeysvc.ID_KEY = cls.saved

    def setUp(self):
        self.healthy()
        self.svc.presence_from, self.svc.rate_max, self.svc.machine_rate_max = 6, 1000, 1000
        self.svc.rates.clear()

    def healthy(self, seen=None, services="active", halted=False):
        m = self.audit / "machines"
        (m / f"{MACHINE}.seen").write_text(str(seen if seen is not None else time.time()))
        st = {"services": {s: services if s == "zenos-keyd" else "active" for s in
                           ("zenos-keyd", "zenos-guardd", "zenos-aiguard", "zenos-netsentinel", "zenos-firewall")},
              "halted": halted}
        (m / f"{MACHINE}.status.json").write_text(json.dumps(
            {"status": st, "down": [] if services == "active" else ["zenos-keyd"]}))

    def call(self, **m):
        return self.K.handle(m, os.getuid(), os.getpid())

    def seal(self, level, data=b"secret"):
        r = self.call(op="seal", level=level, name="f.txt", data=base64.b64encode(data).decode())
        self.assertTrue(r.get("ok"), r)
        return base64.b64decode(r["blob"])

    def open(self, blob, **kw):
        return self.call(op="open", blob=base64.b64encode(blob).decode(), **kw)

    def header(self, blob):
        return json.loads(blob[len(self.K.MAGIC):].split(b"\n", 1)[0])

    def releases(self):
        return [json.loads(l) for l in Path(self.svc.ledger).read_text(encoding="utf-8").splitlines() if l.strip()]

    # ------------------------------------------------------------------
    def test_roundtrip_and_no_key_on_pc(self):
        blob = self.seal(3, "予算案".encode())
        h = self.header(blob)
        self.assertEqual(h["fmt"], "zks1")
        self.assertRegex(h["fid"], r"^[0-9a-f]{32}$")
        r = self.open(blob)
        self.assertTrue(r["ok"], r)
        self.assertEqual(base64.b64decode(r["data"]).decode(), "予算案")
        # everything the PC holds (its level keys, fragment keys, its identity key) does not decrypt the file
        d = Path(os.environ["ZENOS_KEYD_KEYS"])
        _, hb, ct = self.K.parse_verify(blob)
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        for p in list(d.glob("L*.key")) + [zkeysvc.ID_KEY]:
            k = p.read_bytes()[:32]
            with self.assertRaises(Exception):
                AESGCM(k).decrypt(base64.b64decode(h["nonce"]), ct, hb)
        ev = [(e["event"], e.get("fid")) for e in self.releases()]
        self.assertIn(("key-issued", h["fid"]), ev)
        self.assertIn(("file-sealed", h["fid"]), ev)
        self.assertIn(("key-release", h["fid"]), ev)
        self.assertTrue(zenos_keysvc.zledger.verify(self.svc.ledger)[0])     # the service's own log is one chain

    def test_silent_unhealthy_or_stopped_pc_gets_no_key(self):
        blob = self.seal(2)
        self.healthy(seen=time.time() - 600)
        self.assertEqual(self.open(blob)["error"], "keysvc-silent")
        self.healthy(services="inactive")
        self.assertEqual(self.open(blob)["error"], "keysvc-unhealthy")
        self.healthy(halted=True)
        self.assertEqual(self.open(blob)["error"], "keysvc-halted")
        (self.audit / "machines" / f"{MACHINE}.seen").write_text("silent")
        self.assertEqual(self.open(blob)["error"], "keysvc-silent")
        self.healthy()
        self.assertTrue(self.open(blob)["ok"])

    def test_service_clearance_not_the_pcs(self):
        """the PC's clearance file says 5; the service holds 3 for this user"""
        r = self.call(op="seal", level=4, name="x", data=base64.b64encode(b"x").decode())
        self.assertFalse(r["ok"])
        self.assertEqual(r["error"], "keysvc")
        self.svc.set_clearance(self.user, 5)
        blob = self.seal(4)
        self.svc.set_clearance(self.user, 3)
        self.assertEqual(self.open(blob)["error"], "keysvc-clearance")

    def test_grant_names_the_file_as_the_service_recorded_it(self):
        self.svc.set_clearance(self.user, 5)
        high, other = self.seal(4, b"L4"), self.seal(4, b"other")
        self.svc.set_clearance(self.user, 3)

        def grant(blob, signers):
            core = {"id": "r1", "requester": self.user, "file": "/x/f.zen", "file_hash": hashlib.sha256(blob).hexdigest(),
                    "level": 4, "reason": "test", "created": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
            dg = hashlib.sha256(json.dumps(core, sort_keys=True, ensure_ascii=False).encode()).digest()
            return {"request": "r1", "requester": self.user, "file_hash": core["file_hash"], "level": 4, "expires": 4e9,
                    "digest": base64.b64encode(dg).decode(), "core": core,
                    "approvals": [{"approver": n, "sig": base64.b64encode(self.officers[n].sign(dg)).decode()} for n in signers]}
        self.assertTrue(self.open(high, grant=grant(high, ["sato", "tanaka"]))["ok"])
        self.assertFalse(self.open(other, grant=grant(high, ["sato", "tanaka"]))["ok"])
        self.assertFalse(self.open(high, grant=grant(high, ["sato"]))["ok"])

    def test_root_on_the_pc_asking_directly(self):
        """with the PC's identity key, the service's own checks still hold: wrong level, unknown file, rate, replay"""
        blob = self.seal(3)
        fid = self.header(blob)["fid"]
        with self.assertRaises(zkeysvc.Refused) as e:
            zkeysvc.open_key(self.user, fid, 1)                      # claims L1 for an L3 file
        self.assertEqual(e.exception.error, "unknown-file")
        with self.assertRaises(zkeysvc.Refused) as e:
            zkeysvc.open_key(self.user, "0" * 32, 3)
        self.assertEqual(e.exception.error, "unknown-file")
        self.svc.rate_max = 3
        for _ in range(3):
            zkeysvc.open_key(self.user, fid, 3)
        with self.assertRaises(zkeysvc.Refused) as e:
            zkeysvc.open_key(self.user, fid, 3)
        self.assertEqual(e.exception.error, "rate")
        self.svc.rates.clear()
        key = zkeysvc.identity_key()
        req = {"op": "open", "machine": MACHINE, "t": int(time.time()), "nonce": zkeysvc.b64(os.urandom(16)),
               "eph": zkeysvc.b64(os.urandom(32)), "user": self.user, "fid": fid, "level": 3}
        body = {"req": req, "sig": zkeysvc.b64(key.sign(zkeysvc.canon(req)))}
        self.assertEqual(self.svc.handle("open", body)[0], 200)
        code, ans = self.svc.handle("open", json.loads(json.dumps(body)))
        self.assertEqual((code, ans["error"]), (403, "replay"))
        other = Ed25519PrivateKey.generate()
        body = {"req": dict(req, nonce=zkeysvc.b64(os.urandom(16))), "sig": ""}
        body["sig"] = zkeysvc.b64(other.sign(zkeysvc.canon(body["req"])))
        self.assertEqual(self.svc.handle("open", body)[1]["error"], "signature")
        body["req"]["machine"] = "pc-unknown"
        self.assertEqual(self.svc.handle("open", body)[1]["error"], "machine")

    def test_only_users_assigned_to_this_pc(self):
        """root on this PC naming a user who works elsewhere gets nothing, even for a file it holds"""
        self.svc.set_clearance("elsewhere", 5)
        self.svc.assign("pc-other", "elsewhere")
        blob = self.seal(2)
        with self.assertRaises(zkeysvc.Refused) as e:
            zkeysvc.open_key("elsewhere", self.header(blob)["fid"], 2)
        self.assertEqual(e.exception.error, "not-assigned")
        with self.assertRaises(zkeysvc.Refused) as e:
            zkeysvc.new_file_key("elsewhere", 2, "x")
        self.assertEqual(e.exception.error, "not-assigned")

    def test_opens_only_on_the_pc_that_sealed_it(self):
        blob = self.seal(2)
        other = Ed25519PrivateKey.generate()
        self.svc.enroll("pc-two", base64.b64encode(raw_pub(other)).decode())
        self.svc.assign("pc-two", self.user)
        (self.audit / "machines" / "pc-two.seen").write_text(str(time.time()))
        (self.audit / "machines" / "pc-two.status.json").write_text(
            (self.audit / "machines" / f"{MACHINE}.status.json").read_text())
        with self.assertRaises(zkeysvc.Refused) as e:
            zkeysvc.open_key(self.user, self.header(blob)["fid"], 2, c=dict(self.conf, machine="pc-two"), key=other)
        self.assertEqual(e.exception.error, "unknown-file")

    def test_rate_per_pc_and_in_parallel(self):
        blob = self.seal(2)
        fid = self.header(blob)["fid"]
        self.svc.rate_max, self.svc.machine_rate_max = 1000, 5
        self.svc.rates.clear()
        results = []

        def one():
            try:
                zkeysvc.open_key(self.user, fid, 2)
                results.append("ok")
            except zkeysvc.Refused as e:
                results.append(e.error)
        ts = [threading.Thread(target=one) for _ in range(20)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertEqual(results.count("ok"), 5, results)
        self.assertEqual(results.count("rate"), 15)

    def test_grant_expiry_is_bounded_by_what_was_signed(self):
        self.svc.set_clearance(self.user, 5)
        blob = self.seal(4)
        self.svc.set_clearance(self.user, 3)
        core = {"id": "r1", "requester": self.user, "file": "/x/f.zen", "file_hash": hashlib.sha256(blob).hexdigest(),
                "level": 4, "reason": "test", "created": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(time.time() - 3 * 86400))}
        dg = hashlib.sha256(json.dumps(core, sort_keys=True, ensure_ascii=False).encode()).digest()
        g = {"request": "r1", "requester": self.user, "file_hash": core["file_hash"], "level": 4, "expires": 1e18,
             "digest": base64.b64encode(dg).decode(), "core": core,
             "approvals": [{"approver": n, "sig": base64.b64encode(self.officers[n].sign(dg)).decode()} for n in self.officers]}
        self.assertFalse(self.open(blob, grant=g)["ok"])          # an old grant with its expiry pushed out

    def test_a_digest_names_one_file_only(self):
        a = self.seal(2, b"a")
        b_fid, _ = zkeysvc.new_file_key(self.user, 2, "b")         # a file sealed later, not yet named
        with self.assertRaises(zkeysvc.Refused):
            zkeysvc.sealed(b_fid, hashlib.sha256(a).hexdigest())    # pointing a's digest (and a's grants) at it
        with self.assertRaises(zkeysvc.Refused):
            zkeysvc.sealed(self.header(a)["fid"], "0" * 64)          # renaming a file once named

    def test_broken_configuration_never_falls_back_to_a_key_on_the_pc(self):
        zkeysvc.CONF.write_text("{not json")
        try:
            r = self.call(op="seal", level=2, name="x", data=base64.b64encode(b"x").decode())
            self.assertEqual((r["ok"], r["error"]), (False, "keysvc"))
            zkeysvc.CONF.write_text(json.dumps({"url": self.conf["url"]}))
            self.assertFalse(self.call(op="seal", level=2, name="x", data=base64.b64encode(b"x").decode())["ok"])
        finally:
            zkeysvc.CONF.write_text(json.dumps(self.conf))

    def test_old_files_sealed_again_then_local_keys_destroyed(self):
        saved = zkeysvc.CONF
        zkeysvc.CONF = self.tmp / "none.json"                     # as before the key service was configured
        try:
            self.K.ensure_keys()
            old = self.K.seal("昔の予算".encode(), 2, "old.txt", self.user)
        finally:
            zkeysvc.CONF = saved
        self.assertNotEqual(self.header(old).get("fmt"), "zks1")
        d = self.tmp / "docs"
        (d / "sub").mkdir(parents=True)
        (d / "sub" / "old.zen").write_bytes(old)
        os.chmod(d / "sub" / "old.zen", 0o640)
        (d / "plain.txt").write_text("not sealed")
        self.assertEqual(self.K.reseal([str(d)], dry=True), 1)
        # a folder swapped for a link to somewhere else: nothing is written there, the file counts as left
        elsewhere = self.tmp / "elsewhere"
        elsewhere.mkdir()
        (elsewhere / "old.zen").write_bytes(old)
        (d / "link").symlink_to(elsewhere)
        self.assertEqual(self.K.reseal([str(d / "link" / "old.zen")]), 1)
        self.assertEqual((elsewhere / "old.zen").read_bytes(), old)
        (d / "link").unlink()
        with self.assertRaises(SystemExit):
            self.K.drop_local_keys()                               # the last run left a file: keys stay
        self.assertEqual(self.K.reseal([str(d)]), 0)
        new = (d / "sub" / "old.zen").read_bytes()
        self.assertEqual(self.header(new)["fmt"], "zks1")
        self.assertEqual(oct(os.stat(d / "sub" / "old.zen").st_mode & 0o777), "0o640")
        self.assertEqual((d / "plain.txt").read_text(), "not sealed")
        self.assertEqual(self.K.reseal([str(d)], dry=True), 0)
        keys = Path(os.environ["ZENOS_KEYD_KEYS"])
        self.assertTrue(list(keys.glob("L*.key")))
        self.K.drop_local_keys()
        self.assertEqual(list(keys.glob("L*.key")), [])
        self.K.ensure_keys()                                       # a restart makes no new key on the PC
        self.assertEqual(list(keys.glob("L*.key")), [])
        r = self.open(new)
        self.assertTrue(r["ok"], r)
        self.assertEqual(base64.b64decode(r["data"]).decode(), "昔の予算")
        self.assertFalse(self.open(old)["ok"])                     # the old copy is gone for good

    def test_answer_from_another_service_is_not_used(self):
        blob = self.seal(2)
        bad = dict(self.conf, pub=base64.b64encode(raw_pub(Ed25519PrivateKey.generate())).decode())
        zkeysvc.CONF.write_text(json.dumps(bad))
        try:
            self.assertEqual(self.open(blob)["error"], "keysvc-unavailable")
        finally:
            zkeysvc.CONF.write_text(json.dumps(self.conf))
        self.assertTrue(self.open(blob)["ok"])

    def test_a_signature_handed_in_by_the_pc_does_not_count(self):
        """whoever controls the PC controls its WebAuthn client (origin, challenge): only the service's page counts"""
        sk = Ed25519PrivateKey.generate()
        spki = sk.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.svc.add_passkey(self.user, {"cred_id": "cred1", "public_key": zwebauthn.b64u(spki), "alg": -8,
                                         "rp_id": RP, "origin": ORIGIN, "count": 0}, notify=False)
        self.addCleanup(lambda: (self.svc.dir / "passkeys" / f"{self.user}.json").unlink(missing_ok=True))
        self.svc.presence_from = 3
        low, blob = self.seal(2, b"L2"), self.seal(3, b"L3")
        self.assertTrue(self.open(low)["ok"])                         # below the presence level
        r = self.open(blob)
        self.assertEqual(r["error"], "keysvc-presence")
        self.assertNotIn("confirm_url", r)
        ad = hashlib.sha256(RP.encode()).digest() + bytes([0x05]) + (1).to_bytes(4, "big")
        cdj = json.dumps({"type": "webauthn.get", "challenge": r["challenge"], "origin": ORIGIN}).encode()
        p = {"cred_id": "cred1", "authenticator_data": zwebauthn.b64u(ad), "client_data_json": zwebauthn.b64u(cdj),
             "signature": zwebauthn.b64u(sk.sign(ad + hashlib.sha256(cdj).digest()))}
        self.assertEqual(self.open(blob, presence=p)["error"], "keysvc-presence")

    def test_confirmation_on_the_services_own_page(self):
        """enrol a passkey on the service's page, then confirm one file there; the PC only refers to the challenge"""
        import urllib.request
        origin = f"http://127.0.0.1:{self.port}"
        self.svc.origin, self.svc.rp_id = origin, "127.0.0.1"
        pk = self.svc.dir / "passkeys" / f"{self.user}.json"

        def undo():
            self.svc.origin = self.svc.rp_id = None
            pk.unlink(missing_ok=True)
        self.addCleanup(undo)
        self.svc.presence_from = 3
        inbox = []
        self.svc.messages_account = lambda user: "tanaka.02"
        self.svc.send_to_person = lambda user, text: inbox.append((user, text)) or True
        self.addCleanup(lambda: (self.svc.__dict__.pop("send_to_person", None), self.svc.__dict__.pop("messages_account", None)))
        pages = self.tmp / "pages"
        pages.mkdir(exist_ok=True)
        for n in ("confirm", "enrol"):
            (pages / f"{n}.html").write_text("<script>const D=/*ZENOS_DATA*/null;</script>")
        zenos_keysvc.PAGES = pages

        def post(path, body):
            r = urllib.request.Request(origin + path, data=json.dumps(body).encode(), method="POST",
                                       headers={"Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(r) as a:
                    return a.status, json.loads(a.read())
            except urllib.error.HTTPError as e:
                return e.code, json.loads(e.read())

        def get(path):
            try:
                with urllib.request.urlopen(origin + path) as a:
                    return a.status, a.read().decode()
            except urllib.error.HTTPError as e:
                return e.code, e.read().decode()
        import urllib.error
        # enrolment: a one-time address, a passkey made for this service
        url = self.svc.enrol_code(self.user)
        code = url.rsplit("/", 1)[1]
        st, page = get("/e/" + code)
        self.assertEqual(st, 200)
        data = json.loads(page.split("const D=", 1)[1].split(";</script>")[0])
        sk = Ed25519PrivateKey.generate()
        x = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        cose = bytes([0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20]) + x     # OKP, EdDSA, Ed25519
        ad = (hashlib.sha256(b"127.0.0.1").digest() + bytes([0x45]) + (0).to_bytes(4, "big") + bytes(16)
              + (5).to_bytes(2, "big") + b"credX" + cose)
        att = bytes([0xa3, 0x63]) + b"fmt" + bytes([0x64]) + b"none" + bytes([0x67]) + b"attStmt" + bytes([0xa0]) \
            + bytes([0x68]) + b"authData" + bytes([0x59]) + len(ad).to_bytes(2, "big") + ad
        cdj = json.dumps({"type": "webauthn.create", "challenge": data["challenge"], "origin": origin}).encode()
        st, a = post("/v1/enrol", {"code": code, "attestation_object": zwebauthn.b64u(att),
                                   "client_data_json": zwebauthn.b64u(cdj)})
        self.assertEqual((st, a["ok"]), (200, True), a)
        self.assertEqual(post("/v1/enrol", {"code": code})[0], 410)               # one use
        cred = zwebauthn.b64u(b"credX")
        self.assertIn("passkey-added", (self.svc.dir / "alerts.jsonl").read_text())
        blob = self.seal(3, b"L3 by phone")
        n = [0]

        def request(blob):
            """the PC asks; the link (with its secret) arrives only in the person's Messages"""
            inbox.clear()
            r = self.open(blob)
            self.assertEqual((r["error"], r["confirm_sent"]), ("keysvc-presence", True))
            self.assertNotIn("/c/", json.dumps(r))                 # nothing in the PC's answer leads to the page
            return r["challenge"], inbox[-1][1].rsplit("/c/", 1)[1]

        def assertion(token, origin=origin):
            n[0] += 1
            ad = hashlib.sha256(b"127.0.0.1").digest() + bytes([0x05]) + n[0].to_bytes(4, "big")
            cdj = json.dumps({"type": "webauthn.get", "challenge": token, "origin": origin}).encode()
            return {"token": token, "cred_id": cred, "authenticator_data": zwebauthn.b64u(ad),
                    "client_data_json": zwebauthn.b64u(cdj), "signature": zwebauthn.b64u(sk.sign(ad + hashlib.sha256(cdj).digest()))}
        ch, token = request(blob)
        self.assertEqual(get("/c/" + ch)[0], 410)                     # the PC's reference does not open the page
        st, page = get("/c/" + token)
        self.assertEqual(st, 200)
        view = json.loads(page.split("const D=", 1)[1].split(";</script>")[0])
        self.assertEqual((view["file"], view["level"], view["allow"]), ("f.txt", 3, [cred]))
        self.assertFalse(self.open(blob, presence={"challenge": ch})["ok"])      # not confirmed yet: used up
        ch, token = request(blob)
        st, a = post("/v1/confirm", assertion(token))
        self.assertEqual(st, 200, a)
        self.assertEqual(post("/v1/confirm", assertion(token))[0], 410)         # one try
        ok = self.open(blob, presence={"challenge": ch})
        self.assertTrue(ok["ok"], ok)
        self.assertEqual(base64.b64decode(ok["data"]), b"L3 by phone")
        self.assertFalse(self.open(blob, presence={"challenge": ch})["ok"])      # one use
        other = self.seal(3, b"other")
        och, otoken = request(other)
        post("/v1/confirm", assertion(otoken))
        self.assertFalse(self.open(blob, presence={"challenge": och})["ok"])     # confirmed for another file
        ch, token = request(blob)
        self.assertEqual(post("/v1/confirm", assertion(token, origin="https://evil.example"))[0], 403)
        self.assertFalse(self.open(blob, presence={"challenge": ch})["ok"])
        ch, token = request(blob)
        self.assertEqual(post("/v1/confirm", dict(assertion(ch), token=ch))[0], 410)   # signed over the PC's reference

    def test_reconcile_finds_a_suppressed_pc_record(self):
        blob = self.seal(2)
        fid = self.header(blob)["fid"]
        self.assertTrue(self.open(blob)["ok"])
        chain = self.audit / "chains" / f"{MACHINE}__guard.jsonl"
        chain.write_text("")                              # the PC's ledger as the audit node holds it: no unseal
        f = [x for x in self.svc.reconcile(grace=0) if x["fid"] == fid]
        self.assertEqual([x["state"] for x in f], ["missing-on-pc"])
        alerts = (self.svc.dir / "alerts.jsonl").read_text()
        self.assertIn("release-not-in-pc-ledger", alerts)
        self.assertEqual([x for x in self.svc.reconcile(grace=0) if x["fid"] == fid], [])     # reported once
        self.assertTrue(self.open(blob)["ok"])
        with open(chain, "a") as fh:                      # this time the PC's record reached the audit node
            for l in Path(os.environ["ZENOS_KEYD_LEDGER"]).read_text().splitlines(keepends=True):
                r = json.loads(l)
                if r.get("event") == "unseal" and r.get("fid") == fid:
                    fh.write(l)
        f = [x for x in self.svc.reconcile(grace=0) if x["fid"] == fid]
        self.assertEqual([x["state"] for x in f], ["recorded"])


class AuditOverHTTPS(unittest.TestCase):
    """the key service asks the audit node for a PC's health; an answer not signed by that node counts as no answer"""
    def test_signed_health(self):
        import zenos_auditnode
        tmp = Path(tempfile.mkdtemp(prefix="zenos-keysvc-node-"))
        node = zenos_auditnode.Node(tmp / "audit")
        port = free_port()
        threading.Thread(target=zenos_auditnode.serve, args=(node, "127.0.0.1", port), daemon=True).start()
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=1).close()
                break
            except OSError:
                time.sleep(0.1)
        m = node.dir / "machines"
        (m / "pc-a.seen").write_text(str(time.time()))
        (m / "pc-a.status.json").write_text(json.dumps({"status": {"services": {"zenos-keyd": "active"}, "halted": False},
                                                        "down": []}))
        good = zenos_keysvc.NodeAudit(f"http://127.0.0.1:{port}", node.pub_b64())
        last, ok, halted = zenos_keysvc.Service(tmp / "s1", good).health("pc-a")
        self.assertTrue(time.time() - last < 60 and ok and not halted)
        self.assertEqual(zenos_keysvc.Service(tmp / "s1", good).health("pc-b"), (0, False, False))
        forged = zenos_keysvc.NodeAudit(f"http://127.0.0.1:{port}", base64.b64encode(raw_pub(Ed25519PrivateKey.generate())).decode())
        self.assertEqual(zenos_keysvc.Service(tmp / "s2", forged).health("pc-a"), (0, False, False))
        chain = node.chain_path("pc-a", "guard")
        chain.write_text(json.dumps({"event": "unseal", "fid": "f" * 32, "actor": "u"}) + "\n"
                         + json.dumps({"event": "seal", "fid": "e" * 32, "actor": "u"}) + "\n")
        self.assertEqual(good.unseals("pc-a"), {("f" * 32, "u")})
        with self.assertRaises(Exception):
            forged.unseals("pc-a")


if __name__ == "__main__":
    unittest.main()
