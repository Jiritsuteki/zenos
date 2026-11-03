"""The office engine under ZENOS's rules (system/lib/zoffice.py): LibreOffice in the sandbox, the file in and out
through pipes (only in the sandbox's tmpfs), a locked-down profile. Skipped where LibreOffice or bubblewrap is
missing."""
import io, os, shutil, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "system", "lib"))
import zoffice


@unittest.skipUnless(shutil.which("bwrap") and shutil.which("soffice"), "LibreOffice or bubblewrap missing")
class Engine(unittest.TestCase):
    def test_round_trip_keeps_structure(self):
        import openpyxl
        wb = openpyxl.Workbook(); ws = wb.active
        ws["A1"] = "合計"; ws["B1"] = "=SUM(1,2)"; ws.merge_cells("C1:D2"); ws.print_area = "A1:D4"
        b = io.BytesIO(); wb.save(b)
        out = zoffice.convert(b.getvalue(), "xlsx", "xlsx")
        w = openpyxl.load_workbook(io.BytesIO(out)).active
        self.assertEqual(w["A1"].value, "合計")
        self.assertEqual(str(w["B1"].value).upper(), "=SUM(1,2)")
        self.assertIn("C1:D2", [str(r) for r in w.merged_cells.ranges])
        self.assertTrue(w.print_area)

    def test_old_format_and_pages(self):
        import openpyxl
        wb = openpyxl.Workbook(); wb.active["A1"] = "old format"
        b = io.BytesIO(); wb.save(b)
        xls = zoffice.convert(b.getvalue(), "xlsx", "xls")
        self.assertTrue(xls.startswith(b"\xd0\xcf\x11\xe0"))       # the binary Office format
        back = zoffice.convert(xls, "xls", "xlsx")
        self.assertEqual(openpyxl.load_workbook(io.BytesIO(back)).active["A1"].value, "old format")
        self.assertTrue(zoffice.convert(back, "xlsx", "pdf").startswith(b"%PDF-"))

    def test_lockdown(self):
        self.assertIn("DisableMacrosExecution", zoffice.LOCKDOWN)
        self.assertIn("AutoCheckEnabled", zoffice.LOCKDOWN)
        self.assertIn('oor:finalized="true"', zoffice.LOCKDOWN)
        with self.assertRaises(ValueError):
            zoffice.convert(b"x", "exe", "docx")

    def test_unreadable_is_refused(self):
        with self.assertRaises(zoffice.Failed):
            zoffice.convert(b"not a document at all", "docx", "docx")


if __name__ == "__main__":
    unittest.main()
