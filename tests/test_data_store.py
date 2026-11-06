"""ZENOS Data (zdata.py, zenos_datapeer.py, zenos-decide "share"): a server's records with no plaintext and no key
at rest. Three key peers (any two make a key) and three storage peers run in this process; one test runs them over
HTTP on 127.0.0.1."""
import json, os, shutil, sys, tempfile, threading, time, unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path[0:0] = [str(REPO / "system" / "lib"), str(REPO / "system" / "sbin")]
import zdata, zledger, zenos_datapeer as DP                       # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey   # noqa: E402


def direct(peer, name):
    def call(path, body):
        code, out = getattr(peer, path.rsplit("/", 1)[1])(json.loads(json.dumps(body)))
        return out
    return zdata.Peer(name, call, peer.pub_b64())


class Shamir(unittest.TestCase):
    def test_any_k_of_n_give_the_secret_back(self):
        import itertools, os as _os
        for k, n in ((1, 1), (2, 3), (3, 5), (5, 5)):
            s = _os.urandom(32)
            sh = zdata.split(s, k, n)
            for sub in itertools.combinations(sh, k):
                self.assertEqual(zdata.combine(list(sub)), s)

    def test_fewer_than_k_give_something_else(self):
        s = bytes(32)
        sh = zdata.split(s, 3, 5)
        self.assertNotEqual(zdata.combine(sh[:2]), s)

    def test_one_share_says_nothing_about_the_secret(self):
        """with k = 2 every value of one share byte is equally likely, whatever the secret (counted over 25600 runs)"""
        from collections import Counter
        for secret in (b"\x00", b"\xff"):
            c = Counter(zdata.split(secret, 2, 3)[0][1][0] for _ in range(25600))
            self.assertEqual(len(c), 256)
            self.assertLess(max(c.values()), 180)       # 100 expected per value


class DataStore(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="zenos-data-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.server_key = Ed25519PrivateKey.generate()
        self.idp = Ed25519PrivateKey.generate()
        self.keys = [DP.Peer(self.tmp / f"key{i}", "key") for i in range(3)]
        self.stores = [DP.Peer(self.tmp / f"store{i}", "store") for i in range(3)]
        self.conf = {"servers": {"cases": {"pub": zdata.b64(zdata.raw(self.server_key.public_key())),
                                           "purposes": {"cases": ["casework"], "cases.index": ["index"]},
                                           "rate_max": 600}},
                     "idps": [zdata.b64(zdata.raw(self.idp.public_key()))],
                     "clearance": {"tanaka": 3, "sato": 4}, "rate_max": 30, "window": 60, "audit": "off"}
        for p in self.keys + self.stores:
            self.write_conf(p, self.conf)
        self.db = zdata.Store("cases", self.server_key, [direct(p, f"k{i}") for i, p in enumerate(self.keys)], 2,
                              [direct(p, f"s{i}") for i, p in enumerate(self.stores)])
        self.tanaka = zdata.idp_token(self.idp, "tanaka", aud="cases")

    def write_conf(self, p, c):
        (p.dir / "conf.json").write_text(json.dumps(c))

    def ledger(self, p):
        f = p.dir / "ledger.jsonl"
        return [json.loads(l) for l in f.read_text().splitlines()] if f.exists() else []

    def test_a_record_is_read_back_for_a_signed_in_person_with_a_purpose(self):
        rid = self.db.put("cases", {"name": "Yamada Hanako", "case": "benefit claim"}, 3)
        self.assertEqual(self.db.get(rid, "tanaka", self.tanaka, "casework")["name"], "Yamada Hanako")
        events = [e["event"] for p in self.keys for e in self.ledger(p) if e["event"].startswith("share")]
        self.assertEqual(events.count("share-released"), 2)          # two peers were enough, the third was not asked

    def test_nothing_readable_is_at_rest(self):
        rid = self.db.put("cases", {"name": "Yamada Hanako"}, 3)
        for root in [p.dir for p in self.keys + self.stores]:
            for f in Path(root).rglob("*"):
                if f.is_file():
                    self.assertNotIn(b"Yamada", f.read_bytes())
        rec = json.loads((self.stores[0].dir / "records" / "cases" / f"{rid}.json").read_text())["record"]
        self.assertEqual(len(rec["shares"]), 3)
        self.assertEqual(set(rec), {"v", "id", "table", "level", "nonce", "ct", "k", "shares"})
        self.assertEqual(set(rec["shares"][0]), {"peer", "x", "sealed"})       # a share only sealed to its peer

    def test_a_sign_in_token_counts_only_for_its_server_and_for_a_short_time(self):
        rid = self.db.put("cases", {"x": 1}, 3)
        other = zdata.idp_token(self.idp, "tanaka", aud="payroll")             # made for another server
        with self.assertRaises(zdata.Refused):
            self.db.get(rid, "tanaka", other, "casework")
        long = zdata.idp_token(self.idp, "tanaka", ttl=7 * 86400, aud="cases")   # a week: too long to be a sign-in
        with self.assertRaises(zdata.Refused):
            self.db.get(rid, "tanaka", long, "casework")
        self.assertEqual(self.db.get(rid, "tanaka", self.tanaka, "casework"), {"x": 1})

    def test_another_server_cannot_open_this_servers_records(self):
        """a second enrolled server holding a copy of the record and a table of the same name gets no key"""
        rid = self.db.put("cases", {"x": 1}, 3)
        rec = json.loads((self.stores[0].dir / "records" / "cases" / f"{rid}.json").read_text())["record"]
        tax_key = Ed25519PrivateKey.generate()
        c = json.loads(json.dumps(self.conf))
        c["servers"]["tax"] = {"pub": zdata.b64(zdata.raw(tax_key.public_key())),
                               "purposes": {"cases": ["casework"]}, "rate_max": 600}
        for p in self.keys + self.stores:
            self.write_conf(p, c)
        other = zdata.Store("tax", tax_key, self.db.key_peers, self.db.k, self.db.stores)
        with self.assertRaises(Exception):
            other._key(rec, "tanaka", zdata.idp_token(self.idp, "tanaka", aud="tax"), "casework")
        self.assertEqual(self.db.get(rid, "tanaka", self.tanaka, "casework"), {"x": 1})

    def test_unsigned_requests_leave_no_trace(self):
        peer = self.keys[0]
        f = peer.dir / "ledger.jsonl"
        before = len(f.read_text().splitlines()) if f.exists() else 0
        for _ in range(50):
            code, _ = peer.share({"request": {"server": "nobody", "id": "a" * 32, "table": "cases", "level": 1,
                                              "person": "x", "purpose": "p", "eph": "AAAA"},
                                  "sig": "AA", "x": 1, "sealed": "AA"})
            self.assertEqual(code, 403)
        after = len(f.read_text().splitlines()) if f.exists() else 0
        self.assertEqual(after, before)
        self.assertEqual(peer.rates, {})

    def test_a_storage_read_cannot_be_replayed(self):
        rid = self.db.put("cases", {"x": 1}, 3)
        body = {"server": "cases", "id": rid, "t": int(time.time()), "nonce": "ab" * 16}
        body["sig"] = zdata.b64(self.server_key.sign(zdata.canon(body)))
        self.assertEqual(self.stores[0].get(dict(body))[0], 200)
        self.assertEqual(self.stores[0].get(dict(body))[0], 403)                # the same signed request again

    def test_above_the_clearance_no_peer_releases(self):
        rid = self.db.put("cases", {"x": 1}, 4)
        with self.assertRaises(zdata.Refused) as e:
            self.db.get(rid, "tanaka", self.tanaka, "casework")
        self.assertIn("level", str(e.exception))
        self.assertEqual(self.db.get(rid, "sato", zdata.idp_token(self.idp, "sato", aud="cases"), "casework"), {"x": 1})

    def test_a_grant_on_the_peers_opens_one_record(self):
        rid = self.db.put("cases", {"x": 2}, 5)
        c = dict(self.conf, grants={rid: ["tanaka"]})
        for p in self.keys:
            self.write_conf(p, c)
        self.assertEqual(self.db.get(rid, "tanaka", self.tanaka, "casework"), {"x": 2})

    def test_the_server_cannot_vouch_for_a_person_itself(self):
        rid = self.db.put("cases", {"x": 3}, 1)
        forged = zdata.idp_token(self.server_key, "sato", aud="cases")                 # signed by the server, not the sign-in service
        with self.assertRaises(zdata.Refused) as e:
            self.db.get(rid, "sato", forged, "casework")
        self.assertIn("person-not-verified", str(e.exception))
        expired = zdata.idp_token(self.idp, "tanaka", ttl=-10, aud="cases")
        with self.assertRaises(zdata.Refused):
            self.db.get(rid, "tanaka", expired, "casework")
        with self.assertRaises(zdata.Refused):                            # a token for someone else
            self.db.get(rid, "sato", self.tanaka, "casework")

    def test_an_unregistered_purpose_is_refused(self):
        rid = self.db.put("cases", {"x": 4}, 1)
        with self.assertRaises(zdata.Refused) as e:
            self.db.get(rid, "tanaka", self.tanaka, "marketing")
        self.assertIn("purpose", str(e.exception))

    def test_a_lower_level_named_in_the_request_does_not_open_the_share(self):
        rid = self.db.put("cases", {"x": 5}, 4)
        rec = next(self.db.fetch(rid))
        rec = dict(rec, level=1)                                            # the server lies about the level
        with self.assertRaises(Exception):
            self.db._key(rec, "tanaka", self.tanaka, "casework")
        self.assertIn("share-mismatch", [e["event"] for e in self.ledger(self.keys[0])])

    def test_one_key_peer_down_still_reads_two_down_does_not(self):
        rid = self.db.put("cases", {"x": 6}, 1)
        broken = zdata.Peer("k0", lambda path, body: (_ for _ in ()).throw(OSError("down")), self.keys[0].pub_b64())
        self.db.key_peers[0] = broken
        self.assertEqual(self.db.get(rid, "tanaka", self.tanaka, "casework"), {"x": 6})
        self.db.key_peers[1] = zdata.Peer("k1", broken.call, self.keys[1].pub_b64())
        with self.assertRaises(zdata.Unavailable):
            self.db.get(rid, "tanaka", self.tanaka, "casework")

    def test_a_changed_copy_on_a_storage_peer_is_passed_over(self):
        rid = self.db.put("cases", {"x": 7}, 1)
        p = self.stores[0].dir / "records" / "cases" / f"{rid}.json"
        d = json.loads(p.read_text())
        ct = bytearray(zdata.unb64(d["record"]["ct"]))
        ct[0] ^= 1
        d["record"]["ct"] = zdata.b64(bytes(ct))
        p.write_text(json.dumps(d))
        self.assertEqual(self.db.get(rid, "tanaka", self.tanaka, "casework"), {"x": 7})

    def test_a_replayed_request_is_refused(self):
        rid = self.db.put("cases", {"x": 8}, 1)
        rec = next(self.db.fetch(rid))
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        eph = X25519PrivateKey.generate()
        core = zdata.request_core("cases", rid, "cases", 1, "tanaka", "casework", zdata.raw(eph.public_key()))
        body = {"request": core, "sig": zdata.b64(self.server_key.sign(zdata.canon(core))), "proof": self.tanaka,
                "x": rec["shares"][0]["x"], "sealed": rec["shares"][0]["sealed"]}
        self.assertEqual(self.keys[0].share(dict(body))[0], 200)
        code, out = self.keys[0].share(dict(body))
        self.assertEqual((code, out["reason"]), (403, "replay"))

    def test_rate_limit_per_person(self):
        c = dict(self.conf, rate_max=2)
        for p in self.keys:
            self.write_conf(p, c)
        rid = self.db.put("cases", {"x": 9}, 1)
        self.db.get(rid, "tanaka", self.tanaka, "casework")
        self.db.get(rid, "tanaka", self.tanaka, "casework")
        with self.assertRaises(zdata.Refused) as e:
            self.db.get(rid, "tanaka", self.tanaka, "casework")
        self.assertIn("rate", str(e.exception))

    def test_without_an_audit_setting_every_request_is_refused(self):
        rid = self.db.put("cases", {"x": 10}, 1)
        c = {k: v for k, v in self.conf.items() if k != "audit"}
        for p in self.keys:
            self.write_conf(p, c)
        with self.assertRaises(zdata.Refused) as e:
            self.db.get(rid, "tanaka", self.tanaka, "casework")
        self.assertIn("silent", str(e.exception))

    def test_an_unenrolled_server_cannot_store_or_read(self):
        other = zdata.Store("cases", Ed25519PrivateKey.generate(), self.db.key_peers, 2, self.db.stores)
        with self.assertRaises(zdata.Unavailable):
            other.put("cases", {"x": 11}, 1)
        rid = self.db.put("cases", {"x": 11}, 1)
        self.assertEqual(list(other.fetch(rid)), [])

    def test_blind_index_finds_equal_values_without_the_value(self):
        a = self.db.blind("cases", "postcode", "100-8914", "tanaka", self.tanaka)
        b = self.db.blind("cases", "postcode", "100-8914", "tanaka", self.tanaka)
        c = self.db.blind("cases", "postcode", "100-0001", "tanaka", self.tanaka)
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)
        self.assertNotIn("100", a)
        fresh = zdata.Store("cases", self.server_key, self.db.key_peers, 2, self.db.stores)   # a restarted server
        self.assertEqual(fresh.blind("cases", "postcode", "100-8914", "tanaka", self.tanaka), a)

    def test_every_answer_is_in_the_peers_chained_ledger(self):
        rid = self.db.put("cases", {"x": 12}, 4)
        try:
            self.db.get(rid, "tanaka", self.tanaka, "casework")
        except zdata.Refused:
            pass
        for p in self.keys:
            self.assertTrue(zledger.verify(str(p.dir / "ledger.jsonl"))[0])
        refused = [e for e in self.ledger(self.keys[0]) if e["event"] == "share-refused"]
        self.assertEqual((refused[0]["actor"], refused[0]["reason"], refused[0]["id"]), ("tanaka", "level", rid))

    def test_over_http(self):
        from http.server import ThreadingHTTPServer
        import socket
        urls = []
        for p in self.keys + self.stores:
            s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
            t = threading.Thread(target=DP.serve, args=(p, "127.0.0.1", port), daemon=True)
            t.start()
            urls.append(f"http://127.0.0.1:{port}")
        time.sleep(0.3)
        db = zdata.Store("cases", self.server_key,
                         [zdata.http_peer(f"k{i}", urls[i], self.keys[i].pub_b64()) for i in range(3)], 2,
                         [zdata.http_peer(f"s{i}", urls[3 + i]) for i in range(3)])
        rid = db.put("cases", {"name": "Suzuki"}, 2)
        self.assertEqual(db.get(rid, "tanaka", self.tanaka, "casework"), {"name": "Suzuki"})
        with self.assertRaises(zdata.Refused):
            db.get(rid, "tanaka", self.tanaka, "marketing")


if __name__ == "__main__":
    unittest.main()
