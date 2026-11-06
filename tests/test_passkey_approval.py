"""An officer's approval made with a passkey (zapprove.py, zenos-decide "passkey_approval", Approval.lean): bound to
the request, the person verified on the phone, a copied passkey caught by its counter, and, when the policy asks,
made on the PC's screen with the phone near it. The phone is simulated with a P-256 key (as in an iPhone's Secure
Enclave); the browser's part (authenticator data, client data) is built as WebAuthn defines it."""
import base64, hashlib, json, os, struct, sys, tempfile, unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path[0:0] = [str(REPO / "system" / "lib")]
import zapprove, zwebauthn                                      # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, ed25519  # noqa: E402

RP, ORIGIN = "localhost", "http://localhost:8461"
b64u = zwebauthn.b64u


class Phone:
    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cred = os.urandom(16)
        self.count = 0

    def registration(self):
        spki = self.key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        return {"cred_id": b64u(self.cred), "public_key": b64u(spki), "alg": -7, "rp_id": RP, "origin": ORIGIN,
                "count": 0, "transports": ["hybrid", "internal"]}

    def approve(self, message, near=True, uv=True, origin=ORIGIN, count=None, exception=None, synced=False):
        if count is None:
            self.count += 1
            count = self.count
        flags = 0x01 | (0x04 if uv else 0) | (0x18 if synced else 0)
        ad = hashlib.sha256(RP.encode()).digest() + bytes([flags]) + struct.pack(">I", count)
        cdj = json.dumps({"type": "webauthn.get", "challenge": b64u(message), "origin": origin,
                          "crossOrigin": False}).encode()
        sig = self.key.sign(ad + hashlib.sha256(cdj).digest(), ec.ECDSA(hashes.SHA256()))
        a = {"passkey": 1, "credential_id": b64u(self.cred), "authenticator_data": b64u(ad), "client_data_json": b64u(cdj),
             "signature": b64u(sig), "attachment": "cross-platform" if near else "platform"}
        if exception:
            a["exception"] = exception
        return json.dumps(a)


class PasskeyApproval(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="zenos-approve-"))
        self.pub = self.tmp / "approvers"
        self.phone = Phone()
        zapprove.enroll_passkey(self.pub, "suzuki", self.phone.registration())
        self.digest = hashlib.sha256(b'{"file": "budget.xlsx", "level": 3, "requester": "tanaka"}').digest()
        self.strict = {"near_from_level": 3, "exceptions": False}
        self.state = self.tmp / "counters.json"

    def check(self, sig, level=3, pol=None, message=None, state=True):
        return zapprove.check(self.pub, "suzuki", sig, message or self.digest, level, self.state if state else None,
                              pol or self.strict)

    def test_near_phone_approves(self):
        ok, why, facts = self.check(self.phone.approve(self.digest, near=True))
        self.assertEqual((ok, why), (True, None))
        self.assertTrue(facts["near"] and facts["user_verified"] and facts["sig_ok"])

    def test_phone_far_away_is_refused(self):
        self.assertEqual(self.check(self.phone.approve(self.digest, near=False))[:2], (False, "phone-not-near"))

    def test_below_the_level_nearness_is_not_asked(self):
        self.assertEqual(self.check(self.phone.approve(self.digest, near=False), level=2)[:2], (True, None))

    def test_an_exception_counts_only_when_allowed_and_is_flagged(self):
        sig = self.phone.approve(self.digest, near=False, exception="remote")
        self.assertEqual(self.check(sig)[:2], (False, "phone-not-near"))
        ok, why, facts = self.check(self.phone.approve(self.digest, near=False, exception="remote"),
                                    pol={"near_from_level": 3, "exceptions": True})
        self.assertTrue(ok)
        self.assertTrue(facts["exception"])         # zenos.py and the guard write "approval-exception" to the ledger

    def test_signature_is_bound_to_the_request(self):
        sig = self.phone.approve(hashlib.sha256(b"another request").digest())
        self.assertEqual(self.check(sig)[:2], (False, "not-for-this-request"))

    def test_decline_signature_does_not_approve(self):
        sig = self.phone.approve(b"decline:" + self.digest)
        self.assertFalse(self.check(sig)[0])
        self.assertTrue(self.check(self.phone.approve(b"decline:" + self.digest), message=b"decline:" + self.digest)[0])

    def test_person_not_verified_is_refused(self):
        self.assertEqual(self.check(self.phone.approve(self.digest, uv=False))[:2], (False, "person-not-verified"))

    def test_another_site_is_refused(self):
        sig = self.phone.approve(self.digest, origin="https://evil.example")
        self.assertEqual(self.check(sig)[:2], (False, "wrong-page"))

    def test_a_copied_passkey_shows_in_its_counter(self):
        self.assertTrue(self.check(self.phone.approve(self.digest, count=5))[0])
        self.assertEqual(self.check(self.phone.approve(self.digest, count=5))[:2], (False, "cloned-passkey"))
        self.assertTrue(self.check(self.phone.approve(self.digest, count=6))[0])

    def test_a_tampered_signature_is_refused(self):
        a = json.loads(self.phone.approve(self.digest))
        s = bytearray(zwebauthn.unb64u(a["signature"]))
        s[-1] ^= 1
        a["signature"] = b64u(bytes(s))
        self.assertFalse(self.check(json.dumps(a))[0])

    def test_another_phones_passkey_is_refused(self):
        self.assertFalse(self.check(Phone().approve(self.digest))[0])

    def test_browser_key_cannot_show_nearness(self):
        k = ed25519.Ed25519PrivateKey.generate()
        (self.pub / "sato.pub").write_bytes(k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        sig = base64.b64encode(k.sign(self.digest)).decode()
        self.assertEqual(zapprove.check(self.pub, "sato", sig, self.digest, 3, None, self.strict)[:2], (False, "phone-not-near"))
        self.assertEqual(zapprove.check(self.pub, "sato", sig, self.digest, 2, None, self.strict)[:2], (True, None))
        self.assertEqual(zapprove.roster(self.pub), ["sato", "suzuki"])

    def test_a_passkey_replaces_the_browser_key(self):
        k = ed25519.Ed25519PrivateKey.generate()
        (self.pub / "suzuki.pub").write_bytes(k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        old = base64.b64encode(k.sign(self.digest)).decode()
        self.assertFalse(self.check(old, level=1)[0])           # once a passkey is enrolled, the old key no longer signs
        self.assertTrue(self.check(self.phone.approve(self.digest), level=1)[0])

    def test_rechecking_a_stored_approval_holds(self):
        sig = self.phone.approve(self.digest)
        self.assertTrue(self.check(sig)[0])
        self.assertTrue(self.check(sig, state=False)[0])          # the guard re-checks stored approvals without counters

    def test_the_ledger_line_names_the_key_and_whether_the_phone_was_near(self):
        ok, _, facts = self.check(self.phone.approve(self.digest, near=True, synced=True))
        self.assertTrue(ok)
        self.assertEqual(zapprove.ledger_fields(facts), {"key": "passkey", "credential": b64u(self.phone.cred),
                         "near": True, "user_verified": True, "synced": True, "exception": False})
        ok, _, facts = self.check(self.phone.approve(self.digest, near=False, exception="remote"),
                                  pol={"near_from_level": 3, "exceptions": True})
        f = zapprove.ledger_fields(facts)
        self.assertEqual((f["near"], f["exception"], f["synced"]), (False, True, False))
        self.assertEqual(zapprove.ledger_fields({"key": "ed25519"}), {"key": "ed25519"})
        self.assertEqual(zapprove.ledger_fields({}), {})

    def test_a_synced_passkey_with_its_counter_at_zero_approves(self):
        """iCloud Keychain passkeys keep the counter at 0 (seen on a physical iPhone, 5 Nov 2026)"""
        for _ in range(3):
            self.assertTrue(self.check(self.phone.approve(self.digest, count=0, synced=True))[0])


    def test_a_signature_sent_again_with_another_nearness_claim_is_refused(self):
        far = self.phone.approve(self.digest, near=False, count=0, synced=True)
        self.assertEqual(self.check(far)[:2], (False, "phone-not-near"))
        near = json.dumps(dict(json.loads(far), attachment="cross-platform"))   # the unsigned field changed
        self.assertEqual(self.check(near)[:2], (False, "replayed"))

if __name__ == "__main__":
    unittest.main()
