#!/usr/bin/python3
"""ZENOS Office: Word, Excel and PowerPoint files drawn and edited by the LibreOffice engine (LibreOfficeKit, through
its GTK view LOKDocView, Debian packages liblibreofficekitgtk and gir1.2-lokdocview-0.1), inside a ZENOS window laid
out like the office suites people already know: a ribbon with tabs (File, Home, Insert, Layout, Review, View), a
formula bar and sheet tabs for spreadsheets, a slide list for presentations, a status bar with the zoom.

ZENOS keeps everything around the engine:
  - the file comes from memory: it is copied into a tmpfs (ZENOS_OFFICE_RAM, default $XDG_RUNTIME_DIR, which is a
    tmpfs) and removed when the window closes; the engine is told the tmpfs path only
  - copying out of the document to the system clipboard goes only through this window (Copy), and is refused from
    level L3 up; the engine's own clipboard stays inside the document view
  - printing goes through ZENOS's print path: the decision is the proved one (zdecide.flow to "printer", with the
    print_max_level of /etc/zenos/policy.conf), it is written to the audit log, and a sealed file's pages carry the
    banner (level, file, who, when). The engine never talks to a printer: the pages are made as PDF from the saved
    copy in a separate sandbox and drawn by this window
  - no network: the window is started inside the sandbox (zenos-office starts it with bubblewrap and no network)
  - macros never run, no autosave, no recovery copies, no update check (the profile from zoffice.py)
  - commands that would take the document out of its place (Save As, Export, Send, links to the outside) are not
    offered; a sealed file goes back to its place and is sealed again by zenos.py when the window closes

  zenos_office.py FILE [--level N]        (N: the file's level; 0 for a plain file)
"""
import json, os, shutil, sys, tempfile, threading, time
import gi
gi.require_version("Gtk", "3.0")
gi.require_version("LOKDocView", "0.1")
from gi.repository import Gtk, Gdk, GLib, GdkPixbuf, LOKDocView

try:
    gi.require_version("Poppler", "0.18")
    from gi.repository import Poppler
except (ValueError, ImportError):
    Poppler = None

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "system", "lib"))
sys.path.insert(0, "/usr/lib/zenos")
import zoffice  # noqa: E402
try:
    import zdecide  # noqa: E402
except ImportError:
    zdecide = None

LO = "/usr/lib/libreoffice/program"
WRITER, CALC, IMPRESS = "text", "spreadsheet", "presentation"
KIND = {".docx": WRITER, ".doc": WRITER, ".docm": WRITER, ".odt": WRITER, ".rtf": WRITER,
        ".xlsx": CALC, ".xls": CALC, ".xlsm": CALC, ".ods": CALC, ".csv": CALC,
        ".pptx": IMPRESS, ".ppt": IMPRESS, ".pptm": IMPRESS, ".odp": IMPRESS}
ACCENT = {WRITER: "#2b579a", CALC: "#217346", IMPRESS: "#b7472a"}
APPNAME = {WRITER: "Documents", CALC: "Sheets", IMPRESS: "Slides"}
SIZES = ["8", "9", "10", "10.5", "11", "12", "14", "16", "18", "20", "24", "28", "36", "48", "72"]


def print_max():
    try:
        with open("/etc/zenos/policy.conf") as f:
            for line in f:
                k, _, v = line.partition("=")
                if k.strip() == "print_max_level":
                    return int(v.strip())
    except (OSError, ValueError):
        pass
    return 3


def may_print(level):
    """the proved decision (formal/ZenosFormal, flow to "printer"); without the decision program nothing is
    printed above L0 (fail closed)"""
    if level <= 0:
        return True
    if zdecide is None:
        return False
    return zdecide.flow(level, "printer", print_max=print_max())


def audit(event, **kw):
    try:
        sys.path.insert(0, "/usr/share/zenos/bin")
        import zenos
        zenos.audit(event, **kw)
    except Exception:
        pass


def s(v):
    return {"type": "string", "value": v}


# ---- the ribbon: (tab, [(group, [item, ...]), ...]) per kind. An item is
#      (label, icon, uno-command or callable name, args or None, toggle?)  or a special string ("font", "size", "style")
def ribbon(kind):
    clip = ("Clipboard", [("Paste", "edit-paste", ".uno:Paste", None, False),
                          ("Cut", "edit-cut", ".uno:Cut", None, False),
                          ("Copy", "edit-copy", ".uno:Copy", None, False),
                          ("Format painter", "format-stroke-color", ".uno:FormatPaintbrush", None, False)])
    font = ("Font", ["font", "size",
                     ("Bold", "format-text-bold", ".uno:Bold", None, True),
                     ("Italic", "format-text-italic", ".uno:Italic", None, True),
                     ("Underline", "format-text-underline", ".uno:Underline", None, True),
                     ("Strikethrough", "format-text-strikethrough", ".uno:Strikeout", None, True),
                     ("Subscript", "format-text-subscript", ".uno:SubScript", None, True),
                     ("Superscript", "format-text-superscript", ".uno:SuperScript", None, True),
                     ("Grow font", "format-font-size-more", ".uno:Grow", None, False),
                     ("Shrink font", "format-font-size-less", ".uno:Shrink", None, False),
                     ("Clear formatting", "edit-clear", ".uno:ResetAttributes", None, False)])
    align = [("Align left", "format-justify-left", ".uno:LeftPara", None, True),
             ("Center", "format-justify-center", ".uno:CenterPara", None, True),
             ("Align right", "format-justify-right", ".uno:RightPara", None, True),
             ("Justify", "format-justify-fill", ".uno:JustifyPara", None, True)]
    para = ("Paragraph", [("Bullets", "format-list-unordered", ".uno:DefaultBullet", None, True),
                          ("Numbering", "format-list-ordered", ".uno:DefaultNumbering", None, True),
                          ("Decrease indent", "format-indent-less", ".uno:DecrementIndent", None, False),
                          ("Increase indent", "format-indent-more", ".uno:IncrementIndent", None, False)] + align)
    edit = ("Editing", [("Find", "edit-find", "find", None, False),
                        ("Select all", "edit-select-all", ".uno:SelectAll", None, False)])
    review = ("Review", [("Proofing", [("Spelling", "tools-check-spelling", ".uno:SpellOnline", None, True),
                                       ("Word count", "accessories-text-editor", ".uno:WordCountDialog", None, False)]),
                         ("Comments", [("New comment", "edit-comment", ".uno:InsertAnnotation", None, False),
                                       ("Delete comment", "edit-delete", ".uno:DeleteComment", None, False)]),
                         ("Tracking", [("Track changes", "document-edit", ".uno:TrackChanges", None, True),
                                       ("Accept all", "dialog-ok-apply", ".uno:AcceptAllTrackedChanges", None, False),
                                       ("Reject all", "dialog-cancel", ".uno:RejectAllTrackedChanges", None, False)])])
    view = ("View", [("Zoom", [("Zoom in", "zoom-in", "zoom_in", None, False),
                               ("Zoom out", "zoom-out", "zoom_out", None, False),
                               ("100%", "zoom-original", "zoom_100", None, False)])])
    file_ = ("File", [("Document", [("Save", "document-save", "save", None, False),
                                    ("Print", "document-print", "print_doc", None, False),
                                    ("Export PDF", "application-pdf", "export_pdf", None, False),
                                    ("Close", "window-close", "close", None, False)])])
    if kind == CALC:
        home = ("Home", [clip, font,
                         ("Alignment", align + [("Wrap text", "format-text-direction-ltr", ".uno:WrapText", None, True),
                                                ("Merge & center", "format-justify-center", ".uno:ToggleMergeCells", None, True)]),
                         ("Number", [("Currency", "format-currency", ".uno:NumberFormatCurrency", None, True),
                                     ("Percent", "format-number-percent", ".uno:NumberFormatPercent", None, True),
                                     ("Thousands", "gnumeric-format-thousand-separator", ".uno:NumberFormatThousands", None, True),
                                     ("Date", "x-office-calendar", ".uno:NumberFormatDate", None, True),
                                     ("Add decimal", "format-precision-more", ".uno:NumberFormatIncDecimals", None, False),
                                     ("Remove decimal", "format-precision-less", ".uno:NumberFormatDecDecimals", None, False)]),
                         ("Cells", [("Insert rows", "edit-table-insert-row-above", ".uno:InsertRowsBefore", None, False),
                                    ("Insert columns", "edit-table-insert-column-left", ".uno:InsertColumnsBefore", None, False),
                                    ("Delete rows", "edit-table-delete-row", ".uno:DeleteRows", None, False),
                                    ("Delete columns", "edit-table-delete-column", ".uno:DeleteColumns", None, False)]),
                         ("Editing", [("AutoSum", "format-text-symbol", ".uno:AutoSum", None, False),
                                      ("Sort A-Z", "view-sort-ascending", ".uno:SortAscending", None, False),
                                      ("Sort Z-A", "view-sort-descending", ".uno:SortDescending", None, False),
                                      ("Filter", "view-filter", ".uno:DataFilterAutoFilter", None, True),
                                      ("Find", "edit-find", "find", None, False)])])
        tabs = [file_, home,
                ("Insert", [("Tables", [("Chart", "office-chart-bar", ".uno:InsertObjectChart", None, False),
                                        ("Comment", "edit-comment", ".uno:InsertAnnotation", None, False)]),
                            ("Sheet", [("New sheet", "list-add", "add_sheet", None, False)])]),
                ("Layout", [("Page", [("Portrait", "object-rotate-left", "orient_portrait", None, False),
                                      ("Landscape", "object-rotate-right", "orient_landscape", None, False)]),
                            ("Freeze", [("Freeze panes", "object-locked", ".uno:FreezePanes", None, True)])]),
                ("Formulas", [("Functions", [("AutoSum", "format-text-symbol", ".uno:AutoSum", None, False),
                                             ("Recalculate", "view-refresh", ".uno:Calculate", None, False)])]),
                ("Data", [("Sort & filter", [("Sort A-Z", "view-sort-ascending", ".uno:SortAscending", None, False),
                                             ("Sort Z-A", "view-sort-descending", ".uno:SortDescending", None, False),
                                             ("Filter", "view-filter", ".uno:DataFilterAutoFilter", None, True)]),
                          ("Outline", [("Group", "format-indent-more", ".uno:Group", None, False),
                                       ("Ungroup", "format-indent-less", ".uno:Ungroup", None, False)])]),
                review, view]
    elif kind == IMPRESS:
        home = ("Home", [clip, ("Slides", [("New slide", "list-add", ".uno:InsertPage", None, False),
                                           ("Duplicate", "edit-copy", ".uno:DuplicatePage", None, False),
                                           ("Delete slide", "list-remove", ".uno:DeletePage", None, False)]),
                         font, para, edit])
        tabs = [file_, home,
                ("Insert", [("Insert", [("Table", "insert-table", "insert_table", None, False),
                                        ("Text box", "insert-text", ".uno:Text", None, False),
                                        ("Picture", "insert-image", "insert_picture", None, False),
                                        ("Shape", "draw-rectangle", ".uno:BasicShapes.rectangle", None, False),
                                        ("Comment", "edit-comment", ".uno:InsertAnnotation", None, False)])]),
                ("Design", [("Slide", [("Hide slide", "view-hidden", ".uno:HideSlide", None, False),
                                       ("Show slide", "view-visible", ".uno:ShowSlide", None, False)])]),
                review, view]
    else:
        home = ("Home", [clip, font, para, ("Styles", ["style"]), edit])
        tabs = [file_, home,
                ("Insert", [("Insert", [("Table", "insert-table", "insert_table", None, False),
                                        ("Picture", "insert-image", "insert_picture", None, False),
                                        ("Page break", "insert-page-break", ".uno:InsertPagebreak", None, False),
                                        ("Comment", "edit-comment", ".uno:InsertAnnotation", None, False),
                                        ("Footnote", "insert-text", ".uno:InsertFootnote", None, False),
                                        ("Page number", "format-list-ordered", ".uno:InsertPageNumberField", None, False)])]),
                ("Layout", [("Page", [("Portrait", "object-rotate-left", "orient_portrait", None, False),
                                      ("Landscape", "object-rotate-right", "orient_landscape", None, False)]),
                            ("Text", [("Vertical text", "format-text-direction-vertical", "vertical_text", None, False)])]),
                review, view]
    return tabs


STYLES = ["Default Paragraph Style", "Title", "Subtitle", "Heading 1", "Heading 2", "Heading 3", "Text Body", "Quotations"]

CSS = """
.zo-top { background: @accent; color: #fff; }
.zo-top label { color: #fff; }
.zo-top button { color: #fff; }
.zo-title { font-weight: 600; }
.zo-level { background: rgba(255,255,255,0.18); border-radius: 3px; padding: 1px 8px; font-size: 90%%; }
.zo-level.high { background: #c62828; }
.zo-tabs button { color: #fff; background: transparent; border: none; box-shadow: none; padding: 4px 14px; border-radius: 0; }
.zo-tabs button.active { background: #f3f3f3; color: @accent; }
.zo-tabs button.active label { color: @accent; }
.zo-ribbon { background: #f3f3f3; border-bottom: 1px solid #d6d6d6; padding: 4px 6px; }
.zo-group { border-right: 1px solid #d6d6d6; padding: 0 8px; }
.zo-group-name { color: #555; font-size: 85%%; }
.zo-ribbon button { background: transparent; border: none; box-shadow: none; padding: 3px; border-radius: 3px; }
.zo-ribbon button:hover { background: #e1e1e1; }
.zo-ribbon button:checked { background: #c8d7ee; }
.zo-formula { background: #fff; border-bottom: 1px solid #d6d6d6; padding: 2px 6px; }
.zo-status { background: @accent; color: #fff; padding: 1px 8px; font-size: 90%%; }
.zo-status label { color: #fff; }
.zo-sheets button { border-radius: 0; border: none; border-right: 1px solid #d6d6d6; background: #f3f3f3; padding: 2px 14px; }
.zo-sheets button.active { background: #fff; color: @accent; border-bottom: 2px solid @accent; }
.zo-slides { background: #ebebeb; }
.zo-slides button { background: transparent; border: 2px solid transparent; padding: 2px; }
.zo-slides button.active { border-color: @accent; }
.zo-doc { background: #e6e6e6; }
scrollbar slider { background: @accent; min-width: 8px; min-height: 8px; border-radius: 4px; }
scrollbar trough { background: transparent; }
"""


class OfficeWindow(Gtk.Window):
    def __init__(self, path, level=0):
        super().__init__(title="ZENOS Office")
        self.level = level
        self.origin = os.path.abspath(path)
        self.name = os.path.basename(path)
        self.kind = KIND.get(os.path.splitext(path)[1].lower(), WRITER)
        self.set_default_size(1280, 860)
        self.ram = tempfile.mkdtemp(prefix="zoffice-", dir=os.environ.get("ZENOS_OFFICE_RAM") or os.environ.get("XDG_RUNTIME_DIR") or "/tmp")
        os.chmod(self.ram, 0o700)
        self.doc = os.path.join(self.ram, "document" + os.path.splitext(path)[1].lower())
        with open(path, "rb") as a, open(self.doc, "wb") as b:
            shutil.copyfileobj(a, b)
        profile = os.path.join(self.ram, "profile")
        shutil.copytree(zoffice._template(), profile)
        self.toggles = {}           # uno command -> ToggleButton (state from the engine)
        self._quiet = False
        self.dirty = False
        self._style()
        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        root.pack_start(self._top(), False, False, 0)
        self.ribbon_stack = Gtk.Stack()
        self.ribbon_stack.set_transition_type(Gtk.StackTransitionType.NONE)
        root.pack_start(self.ribbon_stack, False, False, 0)
        self._build_ribbon()
        if self.kind == CALC:
            root.pack_start(self._formula_bar(), False, False, 0)
        self.view = LOKDocView.View.new_from_user_profile(LO, "file://" + profile, None)
        for sig, cb in (("load-changed", self.loaded), ("command-changed", self.command_changed),
                        ("formula-changed", self.formula_changed), ("part-changed", self.part_changed),
                        ("address-changed", self.address_changed),
                        ("edit-changed", lambda *a: None), ("search-not-found", self.not_found)):
            try:
                self.view.connect(sig, cb)
            except TypeError:
                pass
        scroll = Gtk.ScrolledWindow()
        scroll.get_style_context().add_class("zo-doc")
        scroll.add(self.view)
        body = Gtk.Box()
        if self.kind == IMPRESS:
            self.slide_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
            self.slide_box.set_border_width(8)
            side = Gtk.ScrolledWindow()
            side.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
            side.set_size_request(200, -1)
            side.get_style_context().add_class("zo-slides")
            side.add(self.slide_box)
            body.pack_start(side, False, False, 0)
        if self.kind == CALC:            # the row numbers and column letters beside the cells, as in a spreadsheet
            self.scroll = scroll
            grid = Gtk.Grid()
            corner = Gtk.DrawingArea(); corner.set_size_request(46, 22)
            self.colhdr = Gtk.DrawingArea(); self.colhdr.set_size_request(-1, 22); self.colhdr.set_hexpand(True)
            self.rowhdr = Gtk.DrawingArea(); self.rowhdr.set_size_request(46, -1); self.rowhdr.set_vexpand(True)
            corner.connect("draw", lambda w, cr: self._hdr_bg(w, cr))
            self.colhdr.connect("draw", self._draw_cols)
            self.rowhdr.connect("draw", self._draw_rows)
            scroll.set_hexpand(True); scroll.set_vexpand(True)
            grid.attach(corner, 0, 0, 1, 1); grid.attach(self.colhdr, 1, 0, 1, 1)
            grid.attach(self.rowhdr, 0, 1, 1, 1); grid.attach(scroll, 1, 1, 1, 1)
            self.hdr = {"rows": [], "columns": []}
            for adj in (scroll.get_hadjustment(), scroll.get_vadjustment()):
                adj.connect("value-changed", lambda *_: self.update_headers())
            scroll.connect("size-allocate", lambda *_: self.update_headers())
            try:
                self.view.connect("invalidate-header", lambda *_: self.update_headers())
            except TypeError:
                pass
            body.pack_start(grid, True, True, 0)
        else:
            body.pack_start(scroll, True, True, 0)
        root.pack_start(body, True, True, 0)
        if self.kind == CALC:
            self.sheet_box = Gtk.Box()
            self.sheet_box.get_style_context().add_class("zo-sheets")
            root.pack_start(self.sheet_box, False, False, 0)
        root.pack_start(self._status_bar(), False, False, 0)
        self.add(root)
        self.connect("destroy", self.closed)
        self.connect("key-press-event", self.key)
        self.connect("show", lambda *_: GLib.idle_add(self.show_tab, None, "Home"))
        self.view.open_document(self.doc, "{}", None, self.opened, None)

    # ---------------- layout
    def _style(self):
        if os.path.isdir("/usr/share/icons/breeze"):          # the icons of the ZENOS desktop (KDE Plasma)
            Gtk.Settings.get_default().set_property("gtk-icon-theme-name", "breeze")
        p = Gtk.CssProvider()
        p.load_from_data((CSS % ()).replace("@accent", ACCENT[self.kind]).encode())
        Gtk.StyleContext.add_provider_for_screen(Gdk.Screen.get_default(), p, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)

    def _top(self):
        top = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        top.get_style_context().add_class("zo-top")
        line = Gtk.Box(spacing=8)
        line.set_border_width(6)
        for label, icon, cb in (("Save", "document-save", self.save), ("Undo", "edit-undo", lambda *_: self.uno(".uno:Undo")),
                                ("Redo", "edit-redo", lambda *_: self.uno(".uno:Redo"))):
            b = Gtk.Button.new_from_icon_name(icon + "-symbolic", Gtk.IconSize.BUTTON)
            b.set_tooltip_text(label)
            b.set_relief(Gtk.ReliefStyle.NONE)
            b.connect("clicked", cb)
            line.pack_start(b, False, False, 0)
        t = Gtk.Label(label=f"{self.name}  —  ZENOS {APPNAME[self.kind]}")
        t.get_style_context().add_class("zo-title")
        line.set_center_widget(t)
        lv = Gtk.Label(label=f"L{self.level}" if self.level else "Not sealed")
        lv.get_style_context().add_class("zo-level")
        if self.level >= 3:
            lv.get_style_context().add_class("high")
            lv.set_tooltip_text("Copying out and printing are restricted at this level.")
        line.pack_end(lv, False, False, 6)
        top.pack_start(line, False, False, 0)
        self.tabbar = Gtk.Box()
        self.tabbar.get_style_context().add_class("zo-tabs")
        top.pack_start(self.tabbar, False, False, 0)
        return top

    def _build_ribbon(self):
        self.tab_buttons = {}
        for name, groups in ribbon(self.kind):
            b = Gtk.Button(label=name)
            b.connect("clicked", self.show_tab, name)
            self.tabbar.pack_start(b, False, False, 0)
            self.tab_buttons[name] = b
            row = Gtk.Box(spacing=0)
            row.get_style_context().add_class("zo-ribbon")
            for gname, items in groups:
                g = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
                g.get_style_context().add_class("zo-group")
                grid = Gtk.Grid(column_spacing=2, row_spacing=2)
                grid.set_valign(Gtk.Align.CENTER)
                combos = [it for it in items if isinstance(it, str)]
                rest = [it for it in items if not isinstance(it, str)]
                if combos:              # Word's font group: the boxes and a few buttons on top, the rest below
                    top = Gtk.Box(spacing=2)
                    for it in combos:
                        top.pack_start(self._item(it), False, False, 0)
                    extra = [it for it in rest if it[2] in (".uno:Grow", ".uno:Shrink", ".uno:ResetAttributes")]
                    for it in extra:
                        top.pack_start(self._item(it), False, False, 0)
                    grid.attach(top, 0, 0, 1, 1)
                    low = Gtk.Box(spacing=2)
                    for it in rest:
                        if it not in extra:
                            low.pack_start(self._item(it), False, False, 0)
                    grid.attach(low, 0, 1, 1, 1)
                else:
                    per = len(rest) if len(rest) <= 6 else (len(rest) + 1) // 2
                    for i, it in enumerate(rest):
                        grid.attach(self._item(it), i % per, i // per, 1, 1)
                g.pack_start(grid, True, True, 0)
                lab = Gtk.Label(label=gname)
                lab.get_style_context().add_class("zo-group-name")
                g.pack_end(lab, False, False, 0)
                row.pack_start(g, False, False, 0)
            self.ribbon_stack.add_named(row, name)
        self.show_tab(None, "Home")

    def _item(self, it):
        if it == "font":
            self.font = Gtk.ComboBoxText.new_with_entry()
            for f in ("Calibri", "Carlito", "Liberation Serif", "Liberation Sans", "IPAMincho", "IPAGothic",
                      "BIZ UDGothic", "Noto Sans CJK JP", "Noto Serif CJK JP", "Inter"):
                self.font.append_text(f)
            self.font.get_child().set_width_chars(14)
            self.font.connect("changed", self.font_set)
            return self.font
        if it == "size":
            self.size = Gtk.ComboBoxText.new_with_entry()
            for v in SIZES:
                self.size.append_text(v)
            self.size.get_child().set_width_chars(4)
            self.size.connect("changed", self.size_set)
            return self.size
        if it == "style":
            self.style_box = Gtk.ComboBoxText()
            for st in STYLES:
                self.style_box.append_text(st)
            self.style_box.connect("changed", self.style_set)
            return self.style_box
        label, icon, cmd, args, toggle = it
        b = Gtk.ToggleButton() if toggle else Gtk.Button()
        b.set_image(Gtk.Image.new_from_icon_name(icon, Gtk.IconSize.LARGE_TOOLBAR))
        b.set_tooltip_text(label)
        b.set_always_show_image(True)
        if toggle:
            self.toggles[cmd] = b
            b.connect("toggled", self.toggled, cmd)
        else:
            b.connect("clicked", self.clicked, cmd, args)
        return b

    def show_tab(self, _btn, name):
        self.ribbon_stack.show_all()
        self.ribbon_stack.set_visible_child_name(name)
        for n, b in self.tab_buttons.items():
            (b.get_style_context().add_class if n == name else b.get_style_context().remove_class)("active")

    def _formula_bar(self):
        bar = Gtk.Box(spacing=6)
        bar.get_style_context().add_class("zo-formula")
        self.addr = Gtk.Entry()
        self.addr.set_width_chars(8)
        self.addr.set_placeholder_text("A1")
        self.addr.connect("activate", self.goto_cell)
        bar.pack_start(self.addr, False, False, 0)
        bar.pack_start(Gtk.Label(label="fx"), False, False, 4)
        self.formula = Gtk.Entry()
        self.formula.connect("activate", self.enter_formula)
        bar.pack_start(self.formula, True, True, 0)
        return bar

    def _status_bar(self):
        bar = Gtk.Box(spacing=10)
        bar.get_style_context().add_class("zo-status")
        self.status = Gtk.Label(label="Opening…")
        self.status.set_xalign(0)
        bar.pack_start(self.status, True, True, 0)
        self.findbox = Gtk.SearchEntry()
        self.findbox.set_placeholder_text("Find")
        self.findbox.set_no_show_all(True)
        self.findbox.connect("activate", lambda e: self.view.find_next(e.get_text(), False))
        bar.pack_end(self.findbox, False, False, 0)
        self.zoom = Gtk.Scale.new_with_range(Gtk.Orientation.HORIZONTAL, 25, 400, 5)
        self.zoom.set_value(100)
        self.zoom.set_size_request(160, -1)
        self.zoom.set_draw_value(False)
        self.zoom.connect("value-changed", lambda z: self.view.set_zoom(z.get_value() / 100.0))
        self.zoom_label = Gtk.Label(label="100%")
        self.zoom.connect("value-changed", lambda z: self.zoom_label.set_text("%d%%" % z.get_value()))
        self.zoom.connect("value-changed", lambda z: GLib.timeout_add(150, lambda: (self.update_headers(), False)[1]))
        bar.pack_end(self.zoom_label, False, False, 0)
        bar.pack_end(self.zoom, False, False, 0)
        return bar

    # ---------------- spreadsheet headers (LibreOfficeKit gives the positions; this window draws them)
    def update_headers(self):
        if self.kind != CALC or not getattr(self, "_ready", False):
            return
        h, v = self.scroll.get_hadjustment(), self.scroll.get_vadjustment()
        z = max(0.25, self.zoom.get_value() / 100.0)
        tw = 15.0 / z                      # twips per screen pixel at this zoom (96 dpi)
        q = ".uno:ViewRowColumnHeaders?x=%d&y=%d&width=%d&height=%d" % (
            h.get_value() * tw, v.get_value() * tw, max(1, h.get_page_size()) * tw + 3000, max(1, v.get_page_size()) * tw + 3000)
        try:
            self.hdr = json.loads(self.view.get_command_values(q) or "{}")
        except (ValueError, GLib.Error):
            return
        self.colhdr.queue_draw()
        self.rowhdr.queue_draw()

    @staticmethod
    def _hdr_bg(w, cr):
        a = w.get_allocation()
        cr.set_source_rgb(0.953, 0.953, 0.953)
        cr.rectangle(0, 0, a.width, a.height)
        cr.fill()

    def _draw_hdr(self, w, cr, key, horizontal, offset):
        self._hdr_bg(w, cr)
        a = w.get_allocation()
        es = self.hdr.get(key) or []
        if not es:
            return
        cr.select_font_face("sans-serif", 0, 0)
        cr.set_font_size(11)
        prev = es[0].get("size", 0)
        for e in es[1:]:
            end = e.get("size", prev)
            s0, s1 = prev - offset, end - offset
            prev = end
            if s1 < 0:
                continue
            if s0 > (a.width if horizontal else a.height):
                break
            cr.set_source_rgb(0.78, 0.78, 0.78)
            if horizontal:
                cr.rectangle(s1 - 0.5, 0, 1, a.height)
            else:
                cr.rectangle(0, s1 - 0.5, a.width, 1)
            cr.fill()
            txt = str(e.get("text", ""))
            ext = cr.text_extents(txt)
            cr.set_source_rgb(0.27, 0.27, 0.27)
            if horizontal:
                cr.move_to((s0 + s1) / 2 - ext.width / 2, a.height / 2 + ext.height / 2)
            else:
                cr.move_to(a.width / 2 - ext.width / 2, (s0 + s1) / 2 + ext.height / 2)
            cr.show_text(txt)

    def _draw_cols(self, w, cr):
        self._draw_hdr(w, cr, "columns", True, self.scroll.get_hadjustment().get_value())

    def _draw_rows(self, w, cr):
        self._draw_hdr(w, cr, "rows", False, self.scroll.get_vadjustment().get_value())

    # ---------------- engine events
    def opened(self, view, result, data):
        try:
            view.open_document_finish(result)
            view.set_edit(True)
        except GLib.Error as e:
            self.status.set_text("Could not open: " + e.message)

    def loaded(self, view, progress):
        if progress >= 1.0 and not getattr(self, "_ready", False):
            self._ready = True
            self.status.set_text("Ready")
            self.refresh_parts()
            GLib.timeout_add(800, lambda: (self.refresh_parts(), self.update_headers(), False)[2])
            if self.kind == IMPRESS:
                threading.Thread(target=self._thumbs, daemon=True).start()
            if os.environ.get("ZENOS_OFFICE_SELFTEST") == "1":
                GLib.timeout_add(1000, self.selftest)

    def command_changed(self, view, text):
        cmd, _, val = (text or "").partition("=")
        self._quiet = True
        try:
            if cmd in self.toggles:
                self.toggles[cmd].set_active(val == "true")
            elif cmd == ".uno:CharFontName" and hasattr(self, "font") and val:
                self.font.get_child().set_text(val)
            elif cmd == ".uno:FontHeight" and hasattr(self, "size") and val:
                self.size.get_child().set_text(val)
            elif cmd == ".uno:StyleApply" and hasattr(self, "style_box") and val:
                name = val.split(";")[0]
                if name in STYLES:
                    self.style_box.set_active(STYLES.index(name))
            elif cmd == ".uno:ModifiedStatus":
                self.dirty = val == "true"
            elif cmd in (".uno:StatePageNumber", ".uno:StateWordCount", ".uno:RowColSelCount") and val:
                self.status.set_text(val)
            elif cmd == ".uno:Position" and hasattr(self, "addr") and val:
                self.addr.set_text(val)
        finally:
            self._quiet = False

    def formula_changed(self, view, text):
        if hasattr(self, "formula"):
            self.formula.set_text(text or "")

    def address_changed(self, view, text):
        if hasattr(self, "addr"):
            self.addr.set_text(text or "")

    def part_changed(self, view, part):
        self.refresh_parts()

    def not_found(self, view, text):
        self.status.set_text(f'"{text}" was not found')

    def refresh_parts(self):
        n = self.view.get_parts()
        cur = self.view.get_part()
        if self.kind == CALC:
            for c in self.sheet_box.get_children():
                self.sheet_box.remove(c)
            for i in range(n):
                b = Gtk.Button(label=self.view.get_part_name(i) or f"Sheet{i + 1}")
                if i == cur:
                    b.get_style_context().add_class("active")
                b.connect("clicked", lambda _b, k: self.view.set_part(k), i)
                self.sheet_box.pack_start(b, False, False, 0)
            add = Gtk.Button.new_from_icon_name("list-add-symbolic", Gtk.IconSize.BUTTON)
            add.set_tooltip_text("New sheet")
            add.connect("clicked", lambda *_: self.add_sheet())
            self.sheet_box.pack_start(add, False, False, 0)
            self.sheet_box.show_all()
        elif self.kind == IMPRESS:
            kids = self.slide_box.get_children()
            if len(kids) != n:
                for c in kids:
                    self.slide_box.remove(c)
                for i in range(n):
                    b = Gtk.Button()
                    b.add(Gtk.Label(label=f"{i + 1}  {self.view.get_part_name(i) or ''}"))
                    b.connect("clicked", lambda _b, k: self.view.set_part(k), i)
                    self.slide_box.pack_start(b, False, False, 0)
                self.slide_box.show_all()
            for i, b in enumerate(self.slide_box.get_children()):
                (b.get_style_context().add_class if i == cur else b.get_style_context().remove_class)("active")
        elif n > 1:
            self.status.set_text(f"{n} pages")

    def _thumbs(self):
        """slide pictures for the list: the saved copy made into pages in the separate sandbox, drawn small"""
        if Poppler is None:
            return
        try:
            with open(self.doc, "rb") as f:
                pdf = zoffice.convert(f.read(), os.path.splitext(self.doc)[1], "pdf")
        except Exception:
            return
        pics = []
        self.page_pt = None
        tp = os.path.join(self.ram, "slides.pdf")
        with open(tp, "wb") as f:
            f.write(pdf)
        doc = Poppler.Document.new_from_file("file://" + tp, None)
        import cairo
        for i in range(doc.get_n_pages()):
            pg = doc.get_page(i)
            w, h = pg.get_size()
            self.page_pt = self.page_pt or (w, h)
            sc = 168.0 / w
            surf = cairo.ImageSurface(cairo.FORMAT_ARGB32, int(w * sc), int(h * sc))
            cr = cairo.Context(surf)
            cr.set_source_rgb(1, 1, 1)
            cr.paint()
            cr.scale(sc, sc)
            pg.render(cr)
            pics.append(Gdk.pixbuf_get_from_surface(surf, 0, 0, surf.get_width(), surf.get_height()))
        GLib.idle_add(self._set_thumbs, pics)

    def _set_thumbs(self, pics):
        self.fit()
        for i, b in enumerate(self.slide_box.get_children()):
            if i < len(pics):
                box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
                box.pack_start(Gtk.Image.new_from_pixbuf(pics[i]), False, False, 0)
                box.pack_start(Gtk.Label(label=str(i + 1)), False, False, 0)
                b.remove(b.get_child())
                b.add(box)
        self.slide_box.show_all()
        return False

    # ---------------- commands
    def uno(self, cmd, args=None):
        self.view.post_command(cmd, json.dumps(args or {}), False)

    def clicked(self, _b, cmd, args):
        if cmd.startswith(".uno:"):
            self.uno(cmd, args)
        else:
            getattr(self, cmd)()

    def toggled(self, b, cmd):
        if not self._quiet:
            self.uno(cmd)

    def font_set(self, combo):
        name = combo.get_active_text()
        if name and not self._quiet and combo.get_active() >= 0:
            self.uno(".uno:CharFontName", {"CharFontName.FamilyName": s(name)})

    def size_set(self, combo):
        v = combo.get_active_text()
        if v and not self._quiet and combo.get_active() >= 0:
            try:
                self.uno(".uno:FontHeight", {"FontHeight.Height": {"type": "float", "value": float(v)}})
            except ValueError:
                pass

    def style_set(self, combo):
        st = combo.get_active_text()
        if st and not self._quiet:
            self.uno(".uno:StyleApply", {"Style": s(st), "FamilyName": s("ParagraphStyles")})

    def goto_cell(self, entry):
        self.uno(".uno:GoToCell", {"ToPoint": s(entry.get_text().strip())})

    def enter_formula(self, entry):
        self.uno(".uno:EnterString", {"StringName": s(entry.get_text())})

    def find(self):
        self.findbox.show()
        self.findbox.grab_focus()

    def zoom_in(self):
        self.zoom.set_value(min(400, self.zoom.get_value() + 10))

    def zoom_out(self):
        self.zoom.set_value(max(25, self.zoom.get_value() - 10))

    def zoom_100(self):
        self.zoom.set_value(100)

    def fit(self):
        """a slide fits the window, as in the presentation programs (zoom 1.0 draws a point as 96/72 pixels)"""
        if not getattr(self, "page_pt", None):
            return
        a = self.view.get_parent().get_allocation() if self.view.get_parent() else None
        if not a or a.width < 100:
            return
        w, h = self.page_pt
        z = min((a.width - 48) / (w * 96 / 72), (a.height - 48) / (h * 96 / 72))
        self.zoom.set_value(max(25, min(400, int(z * 100))))

    def add_sheet(self):
        n = self.view.get_parts()
        self.uno(".uno:Insert", {"Name": s(f"Sheet{n + 1}"), "Index": {"type": "long", "value": n + 1}})

    def insert_table(self):
        self.uno(".uno:InsertTable", {"Columns": {"type": "long", "value": 3}, "Rows": {"type": "long", "value": 3}})

    def insert_picture(self):
        # only pictures from the document's own folder (the sandbox has nothing else); the engine gets a copy in RAM
        d = Gtk.FileChooserDialog(title="Insert picture", transient_for=self, action=Gtk.FileChooserAction.OPEN)
        d.add_buttons("Cancel", Gtk.ResponseType.CANCEL, "Insert", Gtk.ResponseType.OK)
        d.set_current_folder(os.path.dirname(self.origin))
        flt = Gtk.FileFilter()
        flt.set_name("Pictures")
        for m in ("image/png", "image/jpeg", "image/gif", "image/svg+xml", "image/bmp"):
            flt.add_mime_type(m)
        d.add_filter(flt)
        if d.run() == Gtk.ResponseType.OK:
            src = d.get_filename()
            dst = os.path.join(self.ram, "insert-" + os.path.basename(src))
            shutil.copyfile(src, dst)
            self.uno(".uno:InsertGraphic", {"FileName": s("file://" + dst)})
        d.destroy()

    def orient_portrait(self):
        self.uno(".uno:Orientation", {"Orientation": {"type": "boolean", "value": False}}) if self.kind != WRITER else \
            self.uno(".uno:AttributePageSize", {"AttributePageSize.Landscape": {"type": "boolean", "value": False}})

    def orient_landscape(self):
        self.uno(".uno:Orientation", {"Orientation": {"type": "boolean", "value": True}}) if self.kind != WRITER else \
            self.uno(".uno:AttributePageSize", {"AttributePageSize.Landscape": {"type": "boolean", "value": True}})

    def vertical_text(self):
        self.uno(".uno:TextdirectionTopToBottom")

    def key(self, w, ev):
        ctrl = ev.state & Gdk.ModifierType.CONTROL_MASK
        k = Gdk.keyval_name(ev.keyval) or ""
        if ctrl and k.lower() == "s":
            self.save()
            return True
        if ctrl and k.lower() == "p":
            self.print_doc()
            return True
        if ctrl and k.lower() == "f":
            self.find()
            return True
        return False

    def close(self, *_):
        self.destroy()

    # ---------------- what ZENOS decides
    def copy_out(self, *_):
        if self.level >= 3:
            self.status.set_text("Copying out of an L3+ document is not allowed.")
            audit("copy-refused", file=self.name, level=self.level)
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
        # a plain file goes back where it came from; a sealed file's copy is in zenos.py's RAM folder, and zenos.py
        # seals it again at its level when this window closes
        if os.environ.get("ZENOS_OFFICE_WRITE_BACK", "1") == "1" and os.access(self.origin, os.W_OK):
            tmp = self.origin + ".zenos-saving"
            shutil.copyfile(self.doc, tmp)
            os.replace(tmp, self.origin)
        return False

    def _pdf(self):
        """pages from the saved copy, made in a separate sandbox; kept in RAM"""
        with open(self.doc, "rb") as f:
            data = f.read()
        pdf = zoffice.convert(data, os.path.splitext(self.doc)[1], "pdf")
        p = os.path.join(self.ram, "print.pdf")
        with open(p, "wb") as f:
            f.write(pdf)
        return p

    def banner(self):
        import getpass
        return "L%d · %s · printed by %s · %s" % (self.level, self.name, getpass.getuser(), time.strftime("%Y-%m-%d %H:%M"))

    def print_doc(self, *_):
        if not may_print(self.level):
            audit("print-refused", file=self.name, level=self.level)
            self.tell(f'"{self.name}" is L{self.level}. Files above L{print_max()} cannot be printed from this PC.')
            return
        self.view.post_command(".uno:Save", "{}", False)
        GLib.timeout_add(1500, self._print_now)

    def _print_now(self):
        if Poppler is None:
            self.tell("Printing needs the Poppler library (gir1.2-poppler-0.18).")
            return False
        try:
            pdf = Poppler.Document.new_from_file("file://" + self._pdf(), None)
        except Exception as e:
            self.tell("The pages could not be made: %s" % e)
            return False
        mark = self.banner() if self.level > 0 else None
        op = Gtk.PrintOperation()
        op.set_n_pages(pdf.get_n_pages())
        op.set_job_name(self.name)
        op.connect("draw-page", self._draw_page, pdf, mark)
        res = op.run(Gtk.PrintOperationAction.PRINT_DIALOG, self)
        if res == Gtk.PrintOperationResult.APPLY:
            audit("print", file=self.name, level=self.level, pages=pdf.get_n_pages())
        return False

    @staticmethod
    def _draw_page(op, ctx, n, pdf, mark):
        cr = ctx.get_cairo_context()
        pg = pdf.get_page(n)
        w, h = pg.get_size()
        sc = min(ctx.get_width() / w, ctx.get_height() / h)
        cr.save()
        cr.scale(sc, sc)
        pg.render_for_printing(cr)
        cr.restore()
        if mark:
            draw_banner(cr, ctx.get_width(), mark)

    def export_pdf(self):
        # a PDF next to the file is plain text of the document: only for files that are not sealed
        if self.level > 0:
            self.tell(f'"{self.name}" is sealed (L{self.level}). A PDF copy would leave it unsealed, so it is not made. Use Print.')
            audit("export-refused", file=self.name, level=self.level)
            return
        self.view.post_command(".uno:Save", "{}", False)
        def go():
            out = os.path.splitext(self.origin)[0] + ".pdf"
            shutil.copyfile(self._pdf(), out)
            self.status.set_text("PDF saved: " + os.path.basename(out))
            return False
        GLib.timeout_add(1500, go)

    def tell(self, text):
        if os.environ.get("ZENOS_OFFICE_SELFTEST") == "1":
            self.status.set_text(text)
            return
        d = Gtk.MessageDialog(transient_for=self, modal=True, message_type=Gtk.MessageType.INFO,
                              buttons=Gtk.ButtonsType.OK, text=text)
        d.run()
        d.destroy()

    # ---- self-test (ZENOS_OFFICE_SELFTEST=1): select all, copy out, save, pages, the print decision and banner
    def selftest(self):
        out = {"level": self.level, "kind": self.kind, "tabs": list(self.tab_buttons), "parts": self.view.get_parts()}
        self.view.post_command(".uno:SelectAll", "{}", False)
        def step2():
            before = os.path.getmtime(self.doc)
            Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD).set_text("untouched", -1)
            self.copy_out()
            out["clipboard"] = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD).wait_for_text()
            time.sleep(0.2)
            self.uno(".uno:Bold")
            self.save()
            def step3():
                out["saved"] = os.path.getmtime(self.doc) > before
                p = self._pdf()
                with open(p, "rb") as f:
                    out["pdf"] = f.read(5) == b"%PDF-"
                out["may_print"] = may_print(self.level)
                out["banner"] = self.banner() if self.level > 0 else None
                if Poppler is not None and out["pdf"]:
                    out["banner_drawn"] = banner_pdf_test(p, out["banner"], os.path.join(self.ram, "banner.pdf"))
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


def draw_banner(cr, width, mark):
    """the print banner: a red line of text across the top of every page (level, file, who, when)"""
    cr.save()
    cr.set_source_rgb(1, 1, 1)
    cr.rectangle(0, 0, width, 16)
    cr.fill()
    cr.set_source_rgb(0.69, 0, 0.125)
    cr.select_font_face("sans-serif", 0, 1)
    cr.set_font_size(8.5)
    cr.move_to(6, 11)
    cr.show_text(mark)
    cr.move_to(0, 16)
    cr.line_to(width, 16)
    cr.set_line_width(0.6)
    cr.stroke()
    cr.restore()


def banner_pdf_test(src, mark, dst):
    """the same drawing as printing, into a PDF, read back: the banner is on every page"""
    import cairo
    doc = Poppler.Document.new_from_file("file://" + src, None)
    w, h = doc.get_page(0).get_size()
    surf = cairo.PDFSurface(dst, w, h)
    cr = cairo.Context(surf)
    for i in range(doc.get_n_pages()):
        pg = doc.get_page(i)
        pw, ph = pg.get_size()
        surf.set_size(pw, ph)
        pg.render_for_printing(cr)
        if mark:
            draw_banner(cr, pw, mark)
        cr.show_page()
    surf.finish()
    if not mark:
        return False
    back = Poppler.Document.new_from_file("file://" + dst, None)
    return all(mark.split(" · ")[1] in (back.get_page(i).get_text() or "") for i in range(back.get_n_pages()))


if __name__ == "__main__":
    a = sys.argv[1:]
    lvl = int(a[a.index("--level") + 1]) if "--level" in a else int(os.environ.get("ZENOS_SEALED_LEVEL", "0") or 0)
    w = OfficeWindow(a[0], lvl)
    w.show_all()
    Gtk.main()
    # the engine writes its profile back when the process ends (LibreOfficeKit's own exit handler, seen in CI): the
    # document was saved already, so remove the RAM copy and end the process without running the engine's handlers
    sys.stdout.flush()
    sys.stderr.flush()
    shutil.rmtree(w.ram, ignore_errors=True)
    os._exit(0)
