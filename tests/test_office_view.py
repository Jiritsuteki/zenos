"""ZENOS Office (apps/office): the LibreOffice engine draws and edits Word, Excel and PowerPoint files in a ZENOS
window, and ZENOS keeps the rules around it. Needs LOKDocView (gir1.2-lokdocview-0.1), LibreOffice, bubblewrap and
Xvfb; skipped where they are missing.

Checked: a document opens and is drawn in the window laid out like the office suites (ribbon tabs File, Home,
Insert ...; a sheet bar for spreadsheets); at L1 the selection can be copied out through the window; at L4 copying
out is refused and the system clipboard stays as it was (Ctrl+C inside the engine never reaches it); saving writes
the file back in its own format; pages for the print path are made as PDF and the print banner (level, file, who,
when) is on every page; the in-memory copy is gone after closing. Office files open in this window from the file
manager (the desktop file and the default applications of new users).
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
            self.assertEqual(a["tabs"][:3], ["File", "Home", "Insert"])
            self.assertTrue(a["banner_drawn"])              # the banner is on every printed page
            self.assertIn("note.docx", a["banner"])
            b = self.run_app(p, 4)
            self.assertEqual(b["clipboard"], "untouched")   # L4: nothing copied out

    def test_sheets(self):
        sys.path.insert(0, os.path.join(HERE, "..", "system", "lib"))
        import zoffice
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "shelters.xlsx")
            with open(p, "wb") as f:
                f.write(zoffice.convert(b"School,Beds\nNorth,120\nSouth,80\n", "csv", "xlsx"))
            a = self.run_app(p, 0)
            self.assertEqual(a["kind"], "spreadsheet")
            self.assertIn("Formulas", a["tabs"])
            self.assertGreaterEqual(a["parts"], 1)          # the sheet bar has the sheets
            self.assertIsNone(a["banner"])                  # a plain file prints without a banner


class FileManager(unittest.TestCase):
    def test_office_files_open_in_the_window(self):
        root = os.path.join(HERE, "..")
        with open(os.path.join(root, "desktop", "applications", "zenos-office.desktop")) as f:
            desk = f.read()
        self.assertIn("Exec=/usr/bin/zenos-office %f", desk)
        mimes = [m for m in desk.split("MimeType=")[1].split("\n")[0].split(";") if m]
        for m in ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", "application/msword",
                  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "application/vnd.ms-excel",
                  "application/vnd.openxmlformats-officedocument.presentationml.presentation", "application/vnd.ms-powerpoint"):
            self.assertIn(m, mimes)
        with open(os.path.join(root, "desktop", "skel", ".config", "mimeapps.list")) as f:
            apps = f.read()
        defaults = apps.split("[Default Applications]")[1].split("[Added Associations]")[0]
        for m in mimes:
            self.assertIn(m + "=zenos-office.desktop", defaults)


if __name__ == "__main__":
    unittest.main()
