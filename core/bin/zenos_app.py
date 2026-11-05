#!/usr/bin/env python3
"""ZENOS native app shell (WebKitGTK, non-Google). One frameless window whose chrome is drawn by the app's own HTML.
usage: zenos_app.py APP_HTML TITLE ICON WIDTHxHEIGHT [FILE]
The page talks to the shell through window.zenos.call(cmd, args) -> Promise (open/save dialogs, folder listing, window moves)."""
import os, sys, json, base64, shutil
os.environ.pop("WAYLAND_DISPLAY", None)
os.environ["GDK_BACKEND"] = "x11"
import gi
gi.require_version("Gtk", "3.0")
gi.require_version("WebKit2", "4.1")
gi.require_version("Gdk", "3.0")
from gi.repository import Gtk, WebKit2, Gdk, GLib
import threading
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import zenos_cloud
import zenos_picker

HOME = os.path.expanduser("~")
html, title, icon = sys.argv[1], sys.argv[2], sys.argv[3]
w, h = (int(x) for x in sys.argv[4].split("x"))
start_file = os.path.abspath(sys.argv[5]) if len(sys.argv) > 5 and sys.argv[5].strip() else ""
if start_file.startswith("file://"):
    start_file = GLib.filename_from_uri(start_file)[0]


def read_level():
    try:
        with open(os.path.join(HOME, ".config/zenos/level")) as f:
            return max(1, min(5, int(f.read().strip())))
    except Exception:
        return 1


SEALED_LEVEL = int(os.environ.get("ZENOS_SEALED_LEVEL", "0") or 0)
for _lib in ("/usr/lib/zenos", "/usr/local/lib/zenos"):   # the ZENOS library: installed, else development layout
    if os.path.isdir(_lib) and _lib not in sys.path:
        sys.path.append(_lib)
import zdecide                                            # where content may go (proved: formal/ZenosFormal/Flow.lean)


def folder_level(p):
    p = p or ""
    return 5 if "Black · L5" in p else 4 if "Red · L4" in p else 2 if "Green · L2-L3" in p else 1


def sealed_block(path):
    """a file opened from a sealed (.zen) original may only be copied into a folder of the same level or higher"""
    if SEALED_LEVEL and not zdecide.flow(SEALED_LEVEL, "folder", folder_level(path)):
        return "This file is L%d. Save the copy into an L%d (or higher) folder on the desktop." % (SEALED_LEVEL, SEALED_LEVEL)
    if SEALED_LEVEL and ("/dev/shm/" in path):
        return "Choose a folder for the copy."
    return None


def finfo(p):
    try:
        st = os.stat(p)
        size, mtime = st.st_size, int(st.st_mtime)
    except Exception:
        size, mtime = 0, 0
    return {"path": p, "url": GLib.filename_to_uri(p, None), "name": os.path.basename(p), "size": size,
            "dir": os.path.dirname(p), "mtime": mtime}


# What the page may name as a file. The page is the app's own HTML, but it shows files from anywhere, so a path it
# asks for is held to the places a person keeps files: the home folder (not its hidden folders, where keys, settings
# and ZENOS's own data live), removable drives, and the RAM folder a sealed file is opened into. The file the app was
# started with is always allowed.
ROOTS = [os.path.realpath(x) for x in (HOME, "/media", "/mnt", "/run/media/" + os.environ.get("USER", ""),
                                        "/dev/shm/zenos-%d" % os.getuid())]


def safe_path(p):
    if not isinstance(p, str) or not p or "\0" in p:
        raise PermissionError("bad path")
    r = os.path.realpath(p)
    if start_file and r == os.path.realpath(start_file):
        return r
    for root in ROOTS:
        if r == root or r.startswith(root + os.sep):
            rel = os.path.relpath(r, root)
            if rel == "." or not any(part.startswith(".") for part in rel.split(os.sep)):
                return r
    raise PermissionError("This app does not open files from there.")


PATH_ARGS = {"read": ("path",), "list": ("dir",), "thumb": ("path",), "img_preview": ("src",), "img_segment": ("src",),
             "export_image": ("src", "dir"), "move_file": ("path", "dest"), "pick_dir": ("path", "dir"),
             "studio_peaks": ("path",), "open": ("dir",), "save": ("dir",), "cloud_url": (), "cloud_ls": ()}


class App(Gtk.Window):
    def __init__(self):
        super().__init__(title=title)
        self.set_default_size(w, h)
        self.set_decorated(False)
        try:
            self.set_wmclass(os.path.splitext(os.path.basename(html))[0], title)
        except Exception:
            pass
        if os.path.exists(icon):
            try:
                self.set_icon_from_file(icon)
            except Exception:
                pass
        ucm = WebKit2.UserContentManager()
        ucm.register_script_message_handler("zenos")
        ucm.connect("script-message-received::zenos", self.on_msg)
        SEALED = self.sealed = int(os.environ.get("ZENOS_SEALED_LEVEL", "0") or 0)
        init = {"level": read_level(), "file": finfo(start_file) if start_file else None, "home": HOME, "sealed": SEALED}
        ucm.add_script(WebKit2.UserScript.new(
            "window.__zinit=%s;(function(){var n=0,p={};window.__zr=function(i,r){var f=p[i];delete p[i];if(f)f(r);};"
            "window.zenos={init:window.__zinit,call:function(c,a){return new Promise(function(res){var i=++n;p[i]=res;"
            "window.webkit.messageHandlers.zenos.postMessage(JSON.stringify({id:i,cmd:c,args:a||{}}));});}};})();" % json.dumps(init),
            WebKit2.UserContentInjectedFrames.TOP_FRAME, WebKit2.UserScriptInjectionTime.START, None, None))
        if SEALED >= 3:     # nothing is copied out of an L3+ sealed picture, video or PDF (same rule as the office apps)
            ucm.add_script(WebKit2.UserScript.new(
                "for (const t of ['copy','cut','dragstart']) document.addEventListener(t, e => { e.preventDefault(); e.stopImmediatePropagation(); }, true);"
                "if (navigator.clipboard) { const no = () => Promise.reject(new DOMException('Copying out of this sealed file is not allowed.', 'NotAllowedError'));"
                " try { Object.defineProperty(navigator.clipboard, 'writeText', {value: no}); Object.defineProperty(navigator.clipboard, 'write', {value: no}); } catch (e) {} }",
                WebKit2.UserContentInjectedFrames.ALL_FRAMES, WebKit2.UserScriptInjectionTime.START, None, None))
        self.view = WebKit2.WebView.new_with_user_content_manager(ucm)
        if SEALED >= 3:     # and no right-click "Copy Image" / "Save Image As"
            self.view.connect("context-menu", lambda *a: True)
            # and selected text (a PDF's text layer) never stays in the X11 PRIMARY selection (middle-click paste)
            def on_primary(clip, ev):
                if ev.owner is not None and ev.owner.get_window_type() != Gdk.WindowType.FOREIGN and clip.wait_for_text():
                    clip.set_text("", 0)
            Gtk.Clipboard.get(Gdk.SELECTION_PRIMARY).connect("owner-change", on_primary)
        self.view.set_background_color(Gdk.RGBA(0.08, 0.08, 0.09, 1))
        s = self.view.get_settings()
        s.set_allow_file_access_from_file_urls(True)
        s.set_allow_universal_access_from_file_urls(True)
        s.set_enable_fullscreen(True)
        s.set_media_playback_requires_user_gesture(False)
        s.set_enable_developer_extras(False)
        s.set_enable_write_console_messages_to_stdout(True)
        s.set_javascript_can_access_clipboard(SEALED < 3)
        self.view.connect("decide-policy", self.on_decide)
        if SEALED:          # printing: level banner on every page; above the policy ceiling (default L3) refused
            self.view.connect("print", self._on_print)
            import getpass, time as _t
            mark = "L%d · %s · printed by %s · %s" % (SEALED, os.path.basename(start_file), getpass.getuser(), _t.strftime("%Y-%m-%d %H:%M"))
            ucm.add_style_sheet(WebKit2.UserStyleSheet.new(
                "@media print { body::after { content: %s; position: fixed; left: 0; right: 0; top: 0; padding: 4px 8px;"
                " font: 600 9pt sans-serif; color: #b00020; background: #fff; border-bottom: 1px solid #b00020; z-index: 2147483647; } }"
                % json.dumps(mark), WebKit2.UserContentInjectedFrames.ALL_FRAMES, WebKit2.UserStyleLevel.USER, None, None))
        self.view.connect("enter-fullscreen", lambda *a: (self.fullscreen(), False)[1])
        self.view.connect("leave-fullscreen", lambda *a: (self.unfullscreen(), False)[1])
        # WebKit hides dropped file paths from pages; hand them over from here (the page still gets its own drop event)
        self.view.connect("drag-data-received", self._on_drop)
        self.add(self.view)
        self.connect("size-allocate", self._on_alloc)
        self.view.load_uri(GLib.filename_to_uri(os.path.abspath(html), None))

    # links inside the app never navigate the app window away
    def _on_print(self, view, op):
        ceiling = 3
        try:
            for line in open("/etc/zenos/policy.conf"):
                k, _, v = line.partition("=")
                if k.strip() == "print_max_level":
                    ceiling = int(v.strip())
        except (OSError, ValueError):
            pass
        allowed = zdecide.flow(self.sealed, "printer", print_max=ceiling)
        try:
            import zenos
            zenos.audit("print" if allowed else "print-refused", file=os.path.basename(start_file), level=self.sealed)
        except Exception:
            pass
        if allowed:
            return False
        d = Gtk.MessageDialog(transient_for=self, modal=True, message_type=Gtk.MessageType.INFO, buttons=Gtk.ButtonsType.OK,
                              text="This file is L%d. Files above L%d cannot be printed from this PC." % (self.sealed, ceiling))
        d.run()
        d.destroy()
        return True

    def on_decide(self, web, decision, dtype):
        if dtype == WebKit2.PolicyDecisionType.NAVIGATION_ACTION:
            uri = decision.get_navigation_action().get_request().get_uri() or ""
            if not uri.startswith("file:") and not uri.startswith("about:"):
                decision.ignore()
                return True
        return False

    def _on_drop(self, w, ctx, x, y, data, info, t):
        try:
            uris = data.get_uris() or []
        except Exception:
            uris = []
        files = []
        for u in uris:
            if u.startswith("file://"):
                p = GLib.filename_from_uri(u)[0]
                if os.path.isfile(p):
                    files.append(finfo(p))
        if files:
            self.view.run_javascript("window.__zdrop&&window.__zdrop(%s)" % json.dumps(files), None, None, None)

    def reply(self, i, result):
        self.view.run_javascript("window.__zr(%d,%s)" % (i, json.dumps(result)), None, None, None)

    def on_msg(self, ucm, js):
        # only the app's own page speaks to this window: not another page the view was taken to
        own = GLib.filename_to_uri(os.path.abspath(html), None)
        if (self.view.get_uri() or "").split("#", 1)[0].split("?", 1)[0] != own:
            return
        try:
            m = json.loads(js.get_js_value().to_string())
        except Exception:
            return
        i, cmd, a = m.get("id", 0), m.get("cmd"), m.get("args", {})
        if not isinstance(cmd, str) or not hasattr(self, "cmd_" + cmd) or not isinstance(a, dict):
            return self.reply(i, {"error": "unknown command"})
        try:
            for k in PATH_ARGS.get(cmd, ()):
                if a.get(k):
                    a[k] = safe_path(a[k])
        except PermissionError as e:
            return self.reply(i, {"error": str(e)})
        if cmd and (cmd.startswith("cloud_") or cmd.startswith("img_") or cmd.startswith("studio_") or cmd == "thumb"):
            # network calls run off the UI thread; the answer is posted back when ready
            def work():
                try:
                    r = getattr(self, "cmd_" + cmd)(a)
                except Exception as e:
                    r = {"error": str(e)}
                GLib.idle_add(lambda: (self.reply(i, r), False)[1])
            threading.Thread(target=work, daemon=True).start()
            return
        try:
            r = getattr(self, "cmd_" + cmd)(a)
        except Exception as e:
            r = {"error": str(e)}
        self.reply(i, r)

    # ---- window ----
    def cmd_close(self, a): GLib.idle_add(self.close); return True
    def cmd_min(self, a): self.iconify(); return True
    def cmd_max(self, a):
        self.unmaximize() if self.is_maximized() else self.maximize(); return True
    def cmd_drag(self, a):
        try:
            seat = Gdk.Display.get_default().get_default_seat()
            pos = seat.get_pointer().get_position()
            self.begin_move_drag(1, pos[1], pos[2], Gtk.get_current_event_time())
        except Exception:
            pass
        return True
    def cmd_title(self, a): self.set_title(a.get("title", title)); return True
    def cmd_level(self, a): return read_level()

    # ---- files ----
    def _filters(self, dlg, filters):
        for f in filters or []:
            ff = Gtk.FileFilter(); ff.set_name(f.get("name", "Files"))
            for pat in f.get("patterns", []):
                ff.add_pattern(pat); ff.add_pattern(pat.upper())
            dlg.add_filter(ff)

    @staticmethod
    def _pfilters(filters):
        return [(f.get("name", "Files"), list(f.get("patterns", []))) for f in (filters or [])]

    def cmd_open(self, a):
        paths = zenos_picker.open_files(self, a.get("title", "Open"), a.get("dir") or HOME,
                                        self._pfilters(a.get("filters")), bool(a.get("multiple")))
        return [finfo(p) for p in paths]

    def cmd_read(self, a):
        with open(a["path"], "rb") as f:
            return base64.b64encode(f.read()).decode()

    def cmd_save(self, a):
        d = a.get("dir") or os.path.join(HOME, "Documents")
        os.makedirs(d, exist_ok=True)
        # the level rule is checked inside the picker, so the person can choose another folder right there
        path = zenos_picker.save_file(self, a.get("title", "Save"), a.get("name", "Untitled"), d,
                                      self._pfilters(a.get("filters")), check=sealed_block)
        if not path:
            return None
        blk = sealed_block(path)
        if blk:
            return {"error": blk}
        with open(path, "wb") as f:
            f.write(base64.b64decode(a["data"]))
        return finfo(path)

    def cmd_list(self, a):
        d, exts = a.get("dir"), tuple(x.lower() for x in a.get("exts", []))
        try:
            names = sorted(os.listdir(d), key=str.lower)
        except Exception:
            return []
        return [finfo(os.path.join(d, n)) for n in names if n.lower().endswith(exts) and os.path.isfile(os.path.join(d, n))]

    def cmd_subset_font(self, a):
        # keep only the glyphs a document uses, so exported PDFs stay small (fontTools)
        import io
        from fontTools import subset
        opts = subset.Options(); opts.name_IDs = ["*"]; opts.notdef_outline = True; opts.glyph_names = False; opts.layout_features = []   # no ligatures: each character keeps its own glyph and width
        f = subset.load_font(a["path"], opts)
        sub = subset.Subsetter(opts); sub.populate(text=a.get("text", "") + " "); sub.subset(f)
        buf = io.BytesIO(); f.save(buf)
        return base64.b64encode(buf.getvalue()).decode()

    # ---- cloud storage (S3-compatible / WebDAV) ----
    def cmd_cloud_accounts(self, a): return zenos_cloud.accounts()
    def cmd_cloud_add(self, a): return zenos_cloud.add(a)
    def cmd_cloud_remove(self, a): return zenos_cloud.remove(a["id"])

    def _cloud_ok(self, acc):
        if read_level() > acc.get("maxLevel", 1):
            raise ValueError("This storage is cleared up to L%d. You are working at L%d." % (acc.get("maxLevel", 1), read_level()))

    def cmd_cloud_ls(self, a):
        acc = zenos_cloud.get(a["id"]); self._cloud_ok(acc)
        return zenos_cloud.ls(acc, a.get("path", ""))

    def cmd_cloud_url(self, a):
        acc = zenos_cloud.get(a["id"]); self._cloud_ok(acc)
        return zenos_cloud.media_url(acc["id"], a["path"])

    def cmd_thumb(self, a):
        # a still from 10% into a local video, taken with GStreamer (WebKit cannot read pixels back from its video sink)
        gi.require_version("Gst", "1.0")
        from gi.repository import Gst
        Gst.init(None)
        uri = GLib.filename_to_uri(a["path"], None).replace('"', "%22")
        pl = Gst.parse_launch('uridecodebin uri="%s" ! videoconvert ! videoscale ! video/x-raw,width=160,height=90,pixel-aspect-ratio=1/1 ! jpegenc ! appsink name=s sync=false' % uri)
        sink = pl.get_by_name("s")
        try:
            pl.set_state(Gst.State.PAUSED)
            if pl.get_state(5 * Gst.SECOND)[0] == Gst.StateChangeReturn.FAILURE:
                return None
            ok, dur = pl.query_duration(Gst.Format.TIME)
            if ok and dur > 0:
                pl.seek_simple(Gst.Format.TIME, Gst.SeekFlags.FLUSH | Gst.SeekFlags.KEY_UNIT, min(int(dur * 0.1), 30 * Gst.SECOND))
                pl.get_state(5 * Gst.SECOND)
            sample = sink.emit("try-pull-preroll", 3 * Gst.SECOND)
            if not sample:
                return None
            buf = sample.get_buffer(); m_ok, info = buf.map(Gst.MapFlags.READ); data = bytes(info.data); buf.unmap(info)
            return {"thumb": "data:image/jpeg;base64," + base64.b64encode(data).decode(), "dur": (dur / Gst.SECOND) if ok and dur > 0 else 0}
        finally:
            pl.set_state(Gst.State.NULL)

    # ---- playlists (named folders of videos, in play order) ----
    PL = os.path.join(HOME, ".config/zenos/playlists.json")

    def cmd_pl_load(self, a):
        try:
            with open(self.PL) as f:
                return json.load(f)
        except Exception:
            return []

    def cmd_pl_save(self, a):
        os.makedirs(os.path.dirname(self.PL), exist_ok=True)
        tmp = self.PL + ".tmp"
        with open(tmp, "w") as f:
            json.dump(a.get("data", []), f, ensure_ascii=False, indent=1)
        os.replace(tmp, self.PL)
        return True

    # ---- picture editing (OpenCV, classic image processing; no AI) ----
    def _ie(self):
        import zenos_imgedit
        return zenos_imgedit

    def cmd_img_preview(self, a):
        return self._ie().preview(a["src"], a.get("spec", {}), int(a.get("max", 1400)))

    def cmd_img_segment(self, a):
        return self._ie().segment(a["src"], a.get("rot", 0), a["rect"], a.get("fg"), a.get("bg"), a.get("prev"))

    def cmd_export_image(self, a):
        d = a.get("dir") or os.path.join(HOME, "Pictures")
        os.makedirs(d, exist_ok=True)
        src = a.get("src")
        def check(p):
            if p == src:
                return "Choose a new name: the original is never overwritten."
            return sealed_block(p)
        path = zenos_picker.save_file(self, "Save a copy", a.get("name", "edited.jpg"), d,
                                      [("JPEG picture", ["*.jpg", "*.jpeg"]), ("PNG picture", ["*.png"])], check=check)
        if not path:
            return None
        blk = sealed_block(path)
        if blk:
            return {"error": blk}
        if path == a.get("src"):
            return {"error": "Choose a new name: the original is never overwritten."}
        ie = self._ie()
        img = ie.render(a["src"], a.get("spec", {}), 0, True)
        fmt = "png" if path.lower().endswith(".png") else "jpeg"
        with open(path, "wb") as f:
            f.write(ie.encode(img, fmt, 94))
        return finfo(path)

    # ---- sorting: picks / rejects and moving between folders ----
    FLAGS = os.path.join(HOME, ".config/zenos/image-flags.json")

    def cmd_flags_load(self, a):
        try:
            with open(self.FLAGS) as f:
                return json.load(f)
        except Exception:
            return {}

    def cmd_flags_save(self, a):
        os.makedirs(os.path.dirname(self.FLAGS), exist_ok=True)
        with open(self.FLAGS + ".tmp", "w") as f:
            json.dump(a.get("data", {}), f)
        os.replace(self.FLAGS + ".tmp", self.FLAGS)
        return True

    @staticmethod
    def _lvl(p):
        p = p or ""
        return 5 if "Black · L5" in p else 4 if "Red · L4" in p else 2 if "Green · L2-L3" in p else 1

    def cmd_level_folders(self, a):
        d = os.path.join(HOME, "Desktop")
        out = []
        for n in sorted(os.listdir(d)) if os.path.isdir(d) else []:
            p = os.path.join(d, n)
            if os.path.isdir(p) and " · L" in n:
                out.append({"name": n, "path": p, "level": self._lvl(p)})
        return sorted(out, key=lambda x: x["level"])

    def cmd_pick_dir(self, a):
        src = a.get("path")
        def check(dest):
            if src and self._lvl(dest) < self._lvl(src):
                return "This picture is L%d. It cannot move to an L%d folder." % (self._lvl(src), self._lvl(dest))
            return None
        return zenos_picker.choose_folder(self, a.get("title", "Move to folder"), a.get("dir") or HOME, check=check, ok_label="Move here")

    def cmd_move_file(self, a):
        src, dest = a["path"], a["dest"]
        if SEALED_LEVEL:
            return {"error": "This picture is open from a sealed file; it stays where it is."}
        if not os.path.isfile(src) or not os.path.isdir(dest):
            return {"error": "The file or the folder is not there any more."}
        ls, ld = self._lvl(src), self._lvl(dest)
        if ld < ls:   # a picture never moves to a folder with a lower level: that would declassify it
            return {"error": "This picture is L%d. It cannot move to an L%d folder." % (ls, ld)}
        base, ext = os.path.splitext(os.path.basename(src))
        target = os.path.join(dest, base + ext); i = 1
        while os.path.exists(target):
            target = os.path.join(dest, "%s (%d)%s" % (base, i, ext)); i += 1
        shutil.move(src, target)
        r = finfo(target); r["level"] = ld
        return r

    # ---- Library and Studio (music, pictures, a picture on the audio, AI motion the person registered) ----
    def _st(self):
        import zenos_studio
        return zenos_studio

    def _studio_on(self):
        if SEALED_LEVEL:
            raise PermissionError("The Studio is not available for a picture opened from a sealed file.")

    def cmd_studio_library(self, a):
        self._studio_on(); return self._st().library()

    def cmd_studio_meta_load(self, a): return self._st().meta_load()
    def cmd_studio_meta_save(self, a): return self._st().meta_save(a.get("data") or {})

    def cmd_studio_peaks(self, a):
        self._studio_on(); return self._st().peaks(a["path"], int(a.get("n", 600)))

    def _main_save(self, fn):
        r = {}
        def run():
            try:
                r["v"] = fn()
            except Exception as e:
                r["v"] = {"error": str(e)}
            ev.set()
            return False
        ev = threading.Event()
        GLib.idle_add(run)
        ev.wait()
        return r["v"]

    def cmd_studio_import(self, a):
        self._studio_on()
        st = self._st()
        kind = a.get("kind", "audio")
        exts = st.AUDIO if kind == "audio" else st.IMAGES
        dest = os.path.join(HOME, "Music" if kind == "audio" else "Pictures")
        paths = self._main_save(lambda: zenos_picker.open_files(self, "Add to the library", HOME,
                                [("Music" if kind == "audio" else "Pictures", ["*" + e for e in exts])], True))
        if isinstance(paths, dict):
            return paths
        os.makedirs(dest, exist_ok=True)
        out = []
        for p in paths or []:
            if folder_level(p) > 1 or p.lower().endswith(".zen"):
                continue
            if os.path.dirname(os.path.abspath(p)).startswith(os.path.join(HOME, "Desktop")) or os.path.dirname(p) == dest:
                out.append(finfo(p)); continue          # already in an L1 place: listed where it is
            t = st._free_name(os.path.join(dest, os.path.basename(p)))
            shutil.copy2(p, t)
            out.append(finfo(t))
        return out

    def cmd_studio_export_audio(self, a):
        self._studio_on()
        st = self._st()
        src = a["src"]
        base = os.path.splitext(os.path.basename(src))[0]
        d = os.path.dirname(src) if folder_level(src) == 1 else os.path.join(HOME, "Music")
        def check(p):
            if os.path.abspath(p) == os.path.abspath(src):
                return "Choose a new name: the original is never overwritten."
            return None
        path = self._main_save(lambda: zenos_picker.save_file(self, "Save trimmed audio", base + " (cut).m4a", d,
                               [("AAC audio", ["*.m4a"]), ("MP3 audio", ["*.mp3"]), ("WAV audio", ["*.wav"]), ("FLAC audio", ["*.flac"])], check=check))
        if not path or isinstance(path, dict):
            return path
        return st.export_audio(src, a["start"], a["end"], a.get("fin", 0), a.get("fout", 0), path)

    def cmd_studio_export_video(self, a):
        self._studio_on()
        st = self._st()
        base = os.path.splitext(os.path.basename(a["audio"]))[0]
        os.makedirs(st.OUT, exist_ok=True)
        path = self._main_save(lambda: zenos_picker.save_file(self, "Export video", base + ".mp4", st.OUT,
                               [("MP4 video", ["*.mp4"])], check=lambda p: None))
        if not path or isinstance(path, dict):
            return path
        if not path.lower().endswith(".mp4"):
            path += ".mp4"
        return st.export_video(a["audio"], a.get("image"), a.get("clip"), a["start"], a["end"], a.get("fin", 0), a.get("fout", 0), path)

    def cmd_studio_ai(self, a):
        self._studio_on()
        return self._st().ai_video(a["image"], a.get("prompt", ""), a.get("seconds", 5), a.get("endpoint", ""), a.get("key", ""), a.get("model", ""))

    def cmd_exists(self, a):
        return finfo(a["path"]) if os.path.isfile(a["path"]) else None

    def _on_alloc(self, widget, alloc):
        try:
            if self.is_maximized() or (self.get_window() and self.get_window().get_state() & Gdk.WindowState.FULLSCREEN):
                self.shape_combine_region(None)
            else:
                self._round(alloc.width, alloc.height, 13)
        except Exception:
            pass

    def _round(self, w_, h_, r):
        import cairo
        if w_ <= 2 * r or h_ <= 2 * r:
            return
        reg = cairo.Region(cairo.RectangleInt(0, r, w_, h_ - 2 * r))
        reg.union(cairo.RectangleInt(r, 0, w_ - 2 * r, h_))
        for i in range(r):
            dy = r - i - 0.5
            dx = r - int(round((r * r - dy * dy) ** 0.5))
            reg.union(cairo.RectangleInt(dx, i, w_ - 2 * dx, 1))
            reg.union(cairo.RectangleInt(dx, h_ - 1 - i, w_ - 2 * dx, 1))
        self.shape_combine_region(reg)


def main():
    win = App()
    win.connect("destroy", Gtk.main_quit)
    win.show_all()
    try:
        sc = Gdk.Screen.get_default()
        win.move(max(0, (sc.get_width() - w) // 2), max(40, (sc.get_height() - h) // 2 - 10))
    except Exception:
        pass
    Gtk.main()


if __name__ == "__main__":
    main()
