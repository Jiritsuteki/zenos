"""trust agent pieces that need no network: OneCRL key format, signature check, route rating"""
import base64, json, os, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../system/lib"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../system/sbin"))
import zdistrust
import zenos_trustwatch as T
from cryptography import x509
from cryptography.hazmat.primitives import serialization

FIX = open(os.path.join(os.path.dirname(__file__), "fixtures/emudhra-compromised.crt")).read()


class TrustWatch(unittest.TestCase):
    def test_a_program_someone_else_can_change_is_never_run_as_root(self):
        import tempfile
        with tempfile.TemporaryDirectory() as t:
            f = os.path.join(t, "node")
            open(f, "wb").write(b"\x7fELF")
            os.chmod(t, 0o777)
            self.assertFalse(T.root_only(f))
        self.assertTrue(T.root_only("/usr/bin/env") or os.stat("/usr/bin/env").st_uid != 0)

    def test_issuer_serial_matches_onecrl_format(self):
        c = x509.load_pem_x509_certificates(FIX.encode())[0]
        der = c.public_bytes(serialization.Encoding.DER)
        iss, ser = zdistrust.issuer_serial(der).split(":")
        self.assertEqual(base64.b64decode(iss), c.issuer.public_bytes())
        self.assertEqual(int.from_bytes(base64.b64decode(ser), "big", signed=True), c.serial_number)

    def test_learned_list_is_enforced_without_restart(self):
        with open("/etc/ssl/certs/ca-certificates.crt", "rb") as f:
            c = x509.load_pem_x509_certificates(f.read())[5]
        der = c.public_bytes(serialization.Encoding.DER)
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "learned.json")
            old = zdistrust.LISTS[1]
            zdistrust.LISTS[1] = p
            try:
                self.assertIsNone(zdistrust.why(der))
                with open(p, "w") as f:
                    json.dump({"issuer_serial": {zdistrust.issuer_serial(der): "test"}}, f)
                self.assertEqual(zdistrust.why(der), "test")
            finally:
                zdistrust.LISTS[1] = old

    def test_tampered_onecrl_is_rejected(self):
        d = {"metadata": {"signature": {"signature": base64.urlsafe_b64encode(b"\1" * 96).decode()}},
             "changes": [], "timestamp": 1}
        with self.assertRaises(Exception):
            T.verify_changeset(d, FIX.encode())   # chain does not end at Mozilla's root

    def test_root_that_cross_signed_a_compromised_key_is_found(self):
        bad = T.compromised_pems()
        self.assertEqual(len(bad), 16)
        # the AAA root that cross-signed the eMudhra intermediates is in Node's built-in list
        import subprocess, ssl, tempfile
        # written to a file: `node -p` into a pipe can cut its output at 64 KiB when node exits
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, "roots.json")
            subprocess.run(["node", "-e", "require('fs').writeFileSync(process.argv[1], JSON.stringify(require('tls').rootCertificates))", f],
                           check=True, env={"PATH": os.environ["PATH"]})
            with open(f) as fh:
                pems = json.load(fh)
        roots = T.certs_of([ssl.PEM_cert_to_DER_cert(p) for p in pems])
        hits = {T.vouches(r, bad) for r in roots} - {None}
        # every compromised certificate whose issuer is among Node's roots must be found (Node 20 still carried the
        # AAA root that cross-signed them; later Node releases may not)
        subjects = {r["obj"].subject for r in roots}
        expected = {name for name, c in bad if c.issuer in subjects}
        self.assertEqual(hits, expected)


if __name__ == "__main__":
    unittest.main()
