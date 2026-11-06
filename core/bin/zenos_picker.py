"""ZENOS file picker: the open / save / choose-folder dialog for every ZENOS app, drawn in the ZENOS style.

    paths = zenos_picker.open_files(parent, "Import bookmarks", filters=[("Bookmark files (.html)", ["*.html", "*.htm"])])
    path  = zenos_picker.save_file(parent, "Export bookmarks", name="bookmarks.html", start=~/Documents, check=fn)
    path  = zenos_picker.choose_folder(parent, "Move to folder", check=fn)

check(path) may return an error text; the dialog then stays open and shows it (for example a level rule),
so the person can pick another place instead of starting over.
The dialog is modal and returns when the person chooses or cancels (a nested main loop, like Gtk.Dialog.run)."""
import os, json, gi
gi.require_version("Gtk", "3.0")
gi.require_version("WebKit2", "4.1")
from gi.repository import Gtk, WebKit2, Gdk, GLib

HOME = os.path.expanduser("~")
HTML = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "shell", "picker.html")
DESK = os.path.join(HOME, "Desktop")
LEVEL_NAMES = {"Basic · L1": 1, "Green · L2-L3": 2, "Red · L4": 4, "Black · L5": 5}
PLACES = [("Home", HOME, True), ("Desktop", DESK, False), ("Documents", os.path.join(HOME, "Documents"), False),
          ("Downloads", os.path.join(HOME, "Downloads"), False), ("Pictures", os.path.join(HOME, "Pictures"), False),
          ("Videos", os.path.join(HOME, "Videos"), False)]


def folder_level(p):
    import zformat
    return zformat.desk_level(p, os.path.join(HOME, "Desktop"))


class _Picker:
    def __init__(self, parent, mode, title, start, name, filters, multiple, check, ok_label, allow_sealed):
        self.mode, self.title, self.name, self.multiple, self.check = mode, title, name or "", multiple, check
        self.ok_label, self.allow_sealed = ok_label, allow_sealed
        self.filters = [{"name": n, "patterns": list(p)} for n, p in (filters or [])]
        if mode == "open" and self.filters and not any(f["patterns"] in ([], ["*"]) for f in self.filters):
            self.filters.append({"name": "All files", "patterns": []})
        start = start or (os.path.join(HOME, "Documents") if mode == "save" else HOME)
        while start and not os.path.isdir(start):
            start = os.path.dirname(start)
        self.start = start or HOME
        self.result = None
        self.loop = GLib.MainLoop()

        w = self.win = Gtk.Window(title=title)
        w.set_decorated(False)
        w.set_modal(True)
        w.set_type_hint(Gdk.WindowTypeHint.DIALOG)
        w.set_skip_taskbar_hint(True)
        if parent is not None:
            w.set_transient_for(parent)
            w.set_position(Gtk.WindowPosition.CENTER_ON_PARENT)
        else:
            w.set_position(Gtk.WindowPosition.CENTER)
        w.set_default_size(820, 520)
        ucm = WebKit2.UserContentManager()
        ucm.register_script_message_handler("zpick")
        ucm.connect("script-message-received::zpick", self.on_msg)
        self.view = WebKit2.WebView.new_with_user_content_manager(ucm)
        self.view.set_background_color(Gdk.RGBA(0.12, 0.12, 0.14, 1))
        self.view.get_settings().set_enable_developer_extras(False)
        self.view.connect("decide-policy", self._policy)
        self.view.connect("context-menu", lambda *a: True)
        w.add(self.view)
        w.connect("delete-event", lambda *a: (self._end(None), True)[1])
        w.connect("size-allocate", self._round)
        self.view.load_uri("file://" + HTML)

    def _policy(self, web, decision, dtype):
        if dtype == WebKit2.PolicyDecisionType.NAVIGATION_ACTION:
            uri = decision.get_navigation_action().get_request().get_uri() or ""
            if not uri.startswith("file://" + HTML):
                decision.ignore()
                return True
        return False

    def _round(self, w, alloc, r=14):
        import cairo
        W, H = alloc.width, alloc.height
        if W <= 2 * r or H <= 2 * r:
            return
        reg = cairo.Region(cairo.RectangleInt(0, r, W, H - 2 * r))
        reg.union(cairo.RectangleInt(r, 0, W - 2 * r, H))
        for i in range(r):
            dy = r - i - 0.5
            dx = r - int(round((r * r - dy * dy) ** 0.5))
            reg.union(cairo.RectangleInt(dx, i, W - 2 * dx, 1))
            reg.union(cairo.RectangleInt(dx, H - 1 - i, W - 2 * dx, 1))
        w.shape_combine_region(reg)

    def run(self):
        self.win.show_all()
        self.view.grab_focus()
        self.loop.run()
        self.win.destroy()
        return self.result

    def _end(self, result):
        self.result = result
        if self.loop.is_running():
            self.loop.quit()

    def _reply(self, rid, ok, data):
        try:
            self.view.run_javascript("window.__zr(%d,%s,%s)" % (rid, "true" if ok else "false", json.dumps(data, ensure_ascii=False)), None, None, None)
        except Exception:
            pass

    # ---------- page requests ----------
    def on_msg(self, ucm, js):
        try:
            msg = json.loads(js.get_js_value().to_string())
        except Exception:
            return
        rid, cmd, a = msg.get("id", 0), msg.get("cmd"), msg.get("args") or {}
        try:
            out = getattr(self, "c_" + cmd)(a)
            if cmd in ("done", "cancel", "drag") and out is None:
                return
            self._reply(rid, True, out)
        except Exception as e:
            self._reply(rid, False, str(e) if isinstance(e, (ValueError, OSError)) else "Something went wrong.")

    def c_init(self, a):
        places = [{"name": n, "path": p, "home": h} for n, p, h in PLACES if os.path.isdir(p)]
        levels = []
        if os.path.isdir(DESK):
            for n in sorted(os.listdir(DESK)):
                p = os.path.join(DESK, n)
                if n in LEVEL_NAMES and os.path.isdir(p):
                    levels.append({"name": n, "path": p, "level": LEVEL_NAMES[n]})
        levels.sort(key=lambda x: x["level"])
        return {"mode": self.mode, "title": self.title, "name": self.name, "filters": self.filters, "multiple": self.multiple,
                "dir": self.start, "places": places, "levels": levels, "okLabel": self.ok_label,
                "allowSealed": self.allow_sealed, "hideOthers": True, "allowMkdir": self.mode != "open"}

    def c_ls(self, a):
        d = os.path.realpath(a.get("dir") or HOME)
        if not os.path.isdir(d):
            raise ValueError("That folder is not there any more.")
        try:
            names = os.listdir(d)
        except PermissionError:
            raise ValueError("This folder cannot be opened.")
        lvl = folder_level(d)
        ents = []
        for n in names:
            if n.startswith(".") or n.endswith(".desktop"):
                continue
            p = os.path.join(d, n)
            try:
                st = os.stat(p)
            except OSError:
                continue
            isdir = os.path.isdir(p)
            e = {"name": n, "path": p, "dir": isdir, "size": 0 if isdir else st.st_size, "mtime": int(st.st_mtime)}
            if isdir:
                e["level"] = folder_level(p)
            elif n.endswith(".zen"):
                # never open a sealed file just to list it: reading protected files is what the sentinel watches for
                e["sealed"] = True
                e["level"] = lvl
            ents.append(e)
        crumbs = []
        cur = d
        while True:
            if cur == HOME:
                crumbs.insert(0, {"name": os.path.basename(HOME), "path": HOME, "home": True}); break
            crumbs.insert(0, {"name": os.path.basename(cur) or "/", "path": cur})
            nxt = os.path.dirname(cur)
            if nxt == cur:
                break
            cur = nxt
        parent = os.path.dirname(d) if d != "/" else None
        return {"dir": d, "parent": parent, "entries": ents, "crumbs": crumbs, "level": lvl}

    def c_mkdir(self, a):
        d, n = a.get("dir"), (a.get("name") or "").strip()
        if not n or "/" in n or n in (".", ".."):
            raise ValueError("Choose another folder name.")
        p = os.path.join(d, n)
        if os.path.exists(p):
            raise ValueError("“%s” already exists here." % n)
        os.mkdir(p)
        return p

    def c_check(self, a):
        d, n = a.get("dir"), (a.get("name") or "").strip()
        p = os.path.join(d, n)
        if os.path.isdir(p):
            return {"isdir": True, "path": p}
        if self.check:
            err = self.check(p)
            if err:
                return {"error": err}
        if os.path.exists(p):
            base, ext = os.path.splitext(n)
            if base.endswith(".tar"):
                base, ext = base[:-4], ".tar" + ext
            i = 1
            alt = os.path.join(d, "%s (%d)%s" % (base, i, ext))
            while os.path.exists(alt):
                i += 1
                alt = os.path.join(d, "%s (%d)%s" % (base, i, ext))
            return {"exists": True, "path": p, "alt": alt}
        return {"path": p}

    def c_done(self, a):
        paths = [p for p in a.get("paths", []) if p]
        if not paths:
            raise ValueError("Choose a file.")
        if self.check:
            for p in paths:
                err = self.check(p)
                if err:
                    raise ValueError(err)
        if self.mode == "folder":
            self._end(paths[0])
        elif self.mode == "save":
            self._end(paths[0])
        else:
            self._end(paths if self.multiple else paths[:1])
        return None

    def c_cancel(self, a):
        self._end(None)
        return None

    def c_drag(self, a):
        try:
            seat = Gdk.Display.get_default().get_default_seat()
            _, x, y = seat.get_pointer().get_position()
            self.win.begin_move_drag(1, x, y, Gtk.get_current_event_time())
        except Exception:
            pass
        return None


def open_files(parent, title="Open", start=None, filters=None, multiple=False, check=None, ok_label=None, allow_sealed=False):
    """returns a list of paths (empty when cancelled)"""
    return _Picker(parent, "open", title, start, None, filters, multiple, check, ok_label, allow_sealed).run() or []


def save_file(parent, title="Save", name="Untitled", start=None, filters=None, check=None, ok_label=None):
    """returns the chosen path (the person already agreed to replace it if it existed), or None"""
    return _Picker(parent, "save", title, start, name, filters, False, check, ok_label, False).run()


def choose_folder(parent, title="Choose folder", start=None, check=None, ok_label=None):
    return _Picker(parent, "folder", title, start, None, None, False, check, ok_label, False).run()
