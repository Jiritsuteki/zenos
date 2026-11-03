#!/usr/bin/python3
"""ZENOS Office: Word, Excel and PowerPoint files drawn and edited by the LibreOffice engine (LibreOfficeKit, through
its GTK view LOKDocView, Debian packages liblibreofficekitgtk and gir1.2-lokdocview-0.1), inside a ZENOS window.

ZENOS keeps everything around the engine:
  - the file comes from memory: a sealed file is opened into a tmpfs (ZENOS_OFFICE_RAM, default $XDG_RUNTIME_DIR,
    which is a tmpfs) and removed when the window closes; the engine is told the tmpfs path only
  - copying out of the document to the system clipboard goes only through this window (copy_out), and is refused
    from level L3 up; the engine's own clipboard stays inside the document view
  - printing goes through ZENOS's print path (the page images are made by the engine as PDF, then the print limits
    and the banner apply) and is never sent from the engine to a printer
  - no network: the window is started inside the sandbox (zenos-office in system/sbin starts it with bubblewrap and
    no network)
  - macros never run, no autosave, no recovery copies, no update check (the profile from zoffice.py)

  zenos_office.py FILE [--level N]        (FILE: a plain file for now; sealed files arrive through the vault service)
"""
import os, shutil, sys, tempfile
import gi
gi.require_version("Gtk", "3.0")
gi.require_version("LOKDocView", "0.1")
from gi.repository import Gtk, Gdk, GLib, LOKDocView

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "system", "lib"))
sys.path.insert(0, "/usr/lib/zenos")
import zoffice  # noqa: E402

LO = "/usr/lib/libreoffice/program"


class OfficeWindow(Gtk.Window):
    def __init__(self, path, level=1):
        super().__init__(title="ZENOS Office")
        self.level = level
        self.origin = os.path.abspath(path)
        self.set_default_size(1200, 800)
        self.ram = tempfile.mkdtemp(prefix="zoffice-", dir=os.environ.get("ZENOS_OFFICE_RAM") or os.environ.get("XDG_RUNTIME_DIR") or "/tmp")
        os.chmod(self.ram, 0o700)
        self.doc = os.path.join(self.ram, "document" + os.path.splitext(path)[1].lower())
        with open(path, "rb") as a, open(self.doc, "wb") as b:
            shutil.copyfileobj(a, b)
        profile = os.path.join(self.ram, "profile")
        shutil.copytree(zoffice._template(), profile)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        bar = Gtk.Box(spacing=6)
        bar.set_border_width(6)
        self.status = Gtk.Label(label=os.path.basename(path) + f"  ·  L{level}")
        bar.pack_start(self.status, False, False, 6)
        for label, cb in (("Copy", self.copy_out), ("Save", self.save), ("PDF", self.to_pdf)):
            b = Gtk.Button(label=label)
            b.connect("clicked", cb)
            bar.pack_end(b, False, False, 0)
        box.pack_start(bar, False, False, 0)
        self.view = LOKDocView.View.new_from_user_profile(LO, "file://" + profile, None)
        self.view.connect("load-changed", self.loaded)
        scroll = Gtk.ScrolledWindow()
        scroll.add(self.view)
        box.pack_start(scroll, True, True, 0)
        self.add(box)
        self.connect("destroy", self.closed)
        self.view.open_document(self.doc, "{}", None, self.opened, None)

    def opened(self, view, result, data):
        try:
            view.open_document_finish(result)
            view.set_edit(True)
        except GLib.Error as e:
            self.status.set_text("Could not open: " + e.message)

    def loaded(self, view, progress):
        if progress >= 1.0 and not getattr(self, "_ready", False):
            self._ready = True
            self.status.set_text(self.status.get_text() + "  ·  ready")
            if os.environ.get("ZENOS_OFFICE_SELFTEST") == "1":
                GLib.timeout_add(1000, self.selftest)

    def copy_out(self, *_):
        if self.level >= 3:
            self.status.set_text("Copying out of an L3+ document is not allowed.")
            return
        text = self.view.copy_selection("text/plain;charset=utf-8")
        if text and text[0]:
            Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD).set_text(text[0], -1)

    def save(self, *_):
        # the engine writes the document back to its tmpfs copy, in the file's own format (Word stays Word)
        self.view.post_command(".uno:Save", "{}", False)
        GLib.timeout_add(1200, self._write_back)
        self.status.set_text("Saved")

    def _write_back(self):
        # a plain file goes back where it came from; a sealed file goes back through the vault (sealed again there)
        if os.environ.get("ZENOS_OFFICE_WRITE_BACK", "1") == "1" and os.access(self.origin, os.W_OK):
            tmp = self.origin + ".zenos-saving"
            shutil.copyfile(self.doc, tmp)
            os.replace(tmp, self.origin)
        return False

    def to_pdf(self, *_):
        # pages for the print path: made from the saved copy in a separate sandbox; the engine never prints itself
        self.save()
        GLib.timeout_add(1500, self._pdf)

    def _pdf(self):
        with open(self.doc, "rb") as f:
            data = f.read()
        pdf = zoffice.convert(data, os.path.splitext(self.doc)[1], "pdf")
        with open(os.path.join(self.ram, "print.pdf"), "wb") as f:
            f.write(pdf)
        self.status.set_text("Pages ready for the print path")
        return False

    # ---- self-test (ZENOS_OFFICE_SELFTEST=1): select all, copy out, save, pages; results on stdout as JSON
    def selftest(self):
        import json, time
        out = {"level": self.level}
        self.view.post_command(".uno:SelectAll", "{}", False)
        def step2():
            before = os.path.getmtime(self.doc)
            Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD).set_text("untouched", -1)
            self.copy_out()
            out["clipboard"] = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD).wait_for_text()
            time.sleep(0.2)
            self.save()
            def step3():
                out["saved"] = os.path.getmtime(self.doc) > before
                self._pdf()
                p = os.path.join(self.ram, "print.pdf")
                out["pdf"] = os.path.exists(p) and open(p, "rb").read(5) == b"%PDF-"
                out["ram"] = self.ram
                print(json.dumps(out, ensure_ascii=False), flush=True)
                self.destroy()
                return False
            GLib.timeout_add(3000, step3)
            return False
        GLib.timeout_add(2000, step2)
        return False

    def closed(self, *_):
        shutil.rmtree(self.ram, ignore_errors=True)
        Gtk.main_quit()


if __name__ == "__main__":
    a = sys.argv[1:]
    lvl = int(a[a.index("--level") + 1]) if "--level" in a else 1
    w = OfficeWindow(a[0], lvl)
    w.show_all()
    Gtk.main()
