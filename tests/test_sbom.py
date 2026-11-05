"""ZENOS's own SBOM (tools/sbom.py): SPDX 2.3 and CycloneDX 1.6 from the lock files, the pinned binaries, the ZENOS
packages and the image's Debian package list. Checked against the official validators when they are installed
(spdx-tools, cyclonedx-python-lib), and for the facts a ministry's inventory needs either way."""
import json, os, subprocess, sys, tempfile, unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))
import sbom                                                     # noqa: E402


class SBOM(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="zenos-sbom-"))
        listing = cls.tmp / "image.packages"
        listing.write_text("bash\t5.2.37-2+b5\nlibc6:amd64\t2.41-12\nopenssl\t3.5.4-1~deb13u1\n")
        os.environ["SOURCE_DATE_EPOCH"] = "1793865232"
        cls.b = sbom.build("0.2.0", [], str(listing), "zenos-test")
        cls.spdx, cls.cdx = sbom.spdx(cls.b), sbom.cyclonedx(cls.b)

    def test_every_component_has_a_purl_and_a_version(self):
        for c in self.b["components"]:
            self.assertTrue(c["purl"].startswith("pkg:"), c)
            self.assertTrue(c["version"], c)
        purls = [c["purl"] for c in self.b["components"]]
        self.assertEqual(len(purls), len(set(purls)))

    def test_what_is_listed(self):
        purls = {c["purl"] for c in self.b["components"]}
        self.assertIn("pkg:deb/debian/libc6@2.41-12?arch=amd64&distro=trixie", purls)
        self.assertTrue(any(p.startswith("pkg:github/livekit/livekit@v") for p in purls))
        self.assertTrue(any(p.startswith("pkg:npm/%40signalapp/libsignal-client@") for p in purls))
        lk = next(c for c in self.b["components"] if c["name"] == "livekit-server")
        self.assertEqual(len(lk["sha256"]), 64)

    def test_development_tools_are_left_out(self):
        lock = json.loads((REPO / "apps" / "docs" / "package-lock.json").read_text())
        entries = {}
        for path, v in lock["packages"].items():
            if path and "version" in v:
                entries.setdefault((path.split("node_modules/")[-1], v["version"]), []).append(bool(v.get("dev")))
        dev_only = {k for k, devs in entries.items() if all(devs)}
        listed = {(c["name"], c["version"]) for c in self.b["components"]
                  if c["type"] == "npm" and c["used_by"] == "ZENOS Docs"}
        self.assertTrue(dev_only)
        self.assertFalse(dev_only & listed)

    def test_same_inputs_same_output(self):
        again = sbom.spdx(sbom.build("0.2.0", [], str(self.tmp / "image.packages"), "zenos-test"))
        self.assertEqual(json.dumps(again, sort_keys=True), json.dumps(self.spdx, sort_keys=True))

    def test_spdx_validates(self):
        try:
            from spdx_tools.spdx.parser.parse_anything import parse_file
            from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document
        except ImportError:
            self.skipTest("spdx-tools is not installed")
        p = self.tmp / "t.spdx.json"
        p.write_text(json.dumps(self.spdx))
        self.assertEqual(validate_full_spdx_document(parse_file(str(p))), [])

    def test_cyclonedx_validates(self):
        try:
            from cyclonedx.validation.json import JsonStrictValidator
            from cyclonedx.schema import SchemaVersion
        except ImportError:
            self.skipTest("cyclonedx-python-lib is not installed")
        self.assertIsNone(JsonStrictValidator(SchemaVersion.V1_6).validate_str(json.dumps(self.cdx)))


if __name__ == "__main__":
    unittest.main()
