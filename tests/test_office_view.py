"""ZENOS Office (apps/office): the LibreOffice engine draws and edits Word, Excel and PowerPoint files in a ZENOS
window, and ZENOS keeps the rules around it. Needs LOKDocView (gir1.2-lokdocview-0.1), LibreOffice, bubblewrap and
Xvfb; skipped where they are missing.

Checked: a document opens and is drawn; at L1 the selection can be copied out through the window; at L4 copying out
is refused and the system clipboard stays as it was (Ctrl+C inside the engine never reaches it); saving writes the
file back in its own format; pages for the print path are made as PDF; the in-memory copy is gone after closing.
"""
import io, json, os, shutil, subprocess, sys, tempfile, time, unittest, zipfile
HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.join(HERE, "..", "apps", "office", "zenos_office.py")
PY = next((p for p in ("/usr/bin/python3", "/usr/bin/python3.12", "/usr/bin/python3.13") if os.path.exists(p) and
           subprocess.run([p, "-c", "import gi; gi.require_version('LOKDocView', '0.1'); from gi.repository import LOKDocView"],
                          capture_output=True).returncode == 0), None)


def make_docx(path, text):
    """a small Word file written by hand (no Office program needed)"""
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>')
        z.writestr("_rels/.rels", '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>')
        z.writestr("word/document.xml", '<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>' + text + '</w:t></w:r></w:p><w:tbl><w:tr><w:tc><w:p><w:r><w:t>cell</w:t></w:r></w:p></w:tc></w:tr></w:tbl><w:p/></w:body></w:document>')


@unittest.skipUnless(PY and shutil.which("Xvfb") and shutil.which("soffice") and shutil.which("bwrap"),
                     "LOKDocView, LibreOffice, bubblewrap or Xvfb missing")
class OfficeView(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.disp = ":%d" % (90 + os.getpid() % 50)
        cls.x = subprocess.Popen(["Xvfb", cls.disp, "-screen", "0", "1280x860x24"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.5)

    @classmethod
    def tearDownClass(cls):
        cls.x.terminate()
        cls.x.wait()

    def run_app(self, path, level):
        env = {**os.environ, "DISPLAY": self.disp, "ZENOS_OFFICE_SELFTEST": "1", "NO_AT_BRIDGE": "1"}
        r = subprocess.run([PY, APP, path, "--level", str(level)], env=env, capture_output=True, text=True, timeout=240)
        line = [l for l in r.stdout.splitlines() if l.startswith("{")]
        self.assertTrue(line, r.stderr[-800:])
        return json.loads(line[-1])

    def test_rules(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "note.docx")
            make_docx(p, "Shelter list, north school")
            before = os.path.getmtime(p)
            a = self.run_app(p, 1)
            self.assertIn("Shelter list, north school", a["clipboard"] or "")
            self.assertTrue(a["saved"] and a["pdf"])
            self.assertGreater(os.path.getmtime(p), before)
            with zipfile.ZipFile(p) as z:                   # written back as Word, the table kept
                self.assertIn(b"<w:tbl>", z.read("word/document.xml"))
            self.assertFalse(os.path.exists(a["ram"]))      # the in-memory copy is gone
            b = self.run_app(p, 4)
            self.assertEqual(b["clipboard"], "untouched")   # L4: nothing copied out


if __name__ == "__main__":
    unittest.main()
