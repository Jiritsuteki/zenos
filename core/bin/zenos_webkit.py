#!/usr/bin/env python3
# ZENOS Browser - WebKitGTK shell (non-Google). Two layers: an HTML toolbar and the content WebView.
import os, sys, json, time, gi
from urllib.parse import urlparse
for _lib in ("/usr/lib/zenos", "/usr/local/lib/zenos"):   # the ZENOS library: installed, else development layout
    if os.path.isdir(_lib) and _lib not in sys.path:
        sys.path.append(_lib)
import zdistrust
import zenos_bookmarks as BM
import zenos_picker
import zenos_signin
gi.require_version("Gtk", "3.0")
gi.require_version("WebKit2", "4.1")
gi.require_version("Gdk", "3.0")
from gi.repository import Gtk, WebKit2, Gdk, GLib

HOME = os.path.expanduser("~")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # program files
DOWNLOADS = os.path.join(HOME, "Downloads")
TOOLBAR = os.path.join(ROOT, "shell/toolbar.html")
ICON = os.path.join(ROOT, "icons/zenos-browser.svg")
PANEL = os.path.join(ROOT, "shell/bmpanel.html")
MANAGER = os.path.join(ROOT, "shell/bookmarks.html")
PREFS = os.path.join(HOME, ".config/zenos/browser.json")
BAR_H, BMBAR_H = 76, 28
PAD = 26          # transparent margin around popovers for their shadow
os.makedirs(DOWNLOADS, exist_ok=True)


def read_level():
    try:
        with open(os.path.join(HOME, ".config/zenos/level")) as f:
            return max(1, min(5, int(f.read().strip())))
    except Exception:
        return 1


LEVELS = {
    1: ("L1 · Public", "#0A84FF"),
    2: ("L2 · Internal", "#30D158"),
    3: ("L3 · Confidential", "#30D158"),
    4: ("L4 · Restricted", "#FF453A"),
    5: ("L5 · Secret", "#C7C7CC"),
}

START_PAGE = """<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<style>
:root{color-scheme:dark}
*{box-sizing:border-box;margin:0;padding:0;font-family:'Inter',-apple-system,'Noto Sans JP',sans-serif}
body{min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;color:#fff;
background:linear-gradient(180deg,#1a1a1e,#121216);}
h1{font-size:30px;letter-spacing:1px;margin-top:20px;font-weight:600}
.sub{color:#98989D;margin-top:6px;font-size:15px}
.searchbox{margin-top:28px;width:560px;max-width:86vw;display:flex;align-items:center;gap:12px;background:linear-gradient(180deg,#141417,#1b1b20);border:1px solid rgba(0,0,0,.5);box-shadow:inset 0 1.5px 3px rgba(0,0,0,.5);border-radius:14px;padding:0 20px}
.searchbox svg{opacity:.5;flex:0 0 auto}
.searchbox input{flex:1;background:transparent;border:none;outline:none;color:#fff;font-size:16px;padding:15px 0}
.searchbox input::placeholder{color:#636366}
.foot{position:fixed;bottom:18px;color:#48484A;font-size:12px}
</style></head><body>
<svg width="84" height="84" viewBox="0 0 124 124" fill="none" style="filter:drop-shadow(0 10px 30px rgba(155,59,239,.5))"><defs><linearGradient id="zg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#6E5BFF"/><stop offset="0.38" stop-color="#9B3BEF"/><stop offset="0.7" stop-color="#D83AB0"/><stop offset="1" stop-color="#FF6A8B"/></linearGradient></defs><path d="M86 24 a46 46 0 1 0 20 30" stroke="url(#zg)" stroke-width="8" stroke-linecap="round" fill="none"/><path d="M46 48 H80 L46 78 H82" stroke="url(#zg)" stroke-width="8" stroke-linecap="round" stroke-linejoin="round" fill="none"/></svg>
<h1>ZENOS</h1>
<div class=sub>Secure Workspace</div>
<form class=searchbox method=get action="https://html.duckduckgo.com/html/"><svg width="20" height="20" viewBox="0 0 24 24" fill="none"><circle cx="11" cy="11" r="6" stroke="#fff" stroke-width="1.8"/><path d="M20 20l-4-4" stroke="#fff" stroke-width="1.8" stroke-linecap="round"/></svg><input name=q placeholder="Search or enter address"></form>
<div class=foot>ZENOS Browser · __LVL__ · WebKitGTK 2.54 (non-Google)</div>
</body></html>"""

BLOCKED_PAGE = """<!doctype html><html><head><meta charset=utf-8><style>
*{margin:0;font-family:'Inter',-apple-system,'Noto Sans JP',sans-serif}
body{min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;background:#121216;color:#fff;text-align:center}
.b{width:72px;height:72px;border-radius:20px;background:linear-gradient(180deg,#FF6B61,#D1332A);display:flex;align-items:center;justify-content:center;font-size:36px;box-shadow:0 12px 40px rgba(255,69,58,.4)}
h2{margin-top:20px;font-size:22px}.p{color:#98989D;margin-top:8px;font-size:14px;max-width:460px}
.u{color:#636366;margin-top:14px;font-size:12px;word-break:break-all}
</style></head><body><div class=b>&#9888;</div>
<h2>Blocked at __LVL__</h2>
<div class=p>At this clearance level, external sites are disabled. Only local and in-house resources are reachable.</div>
<div class=u>__URL__</div></body></html>"""


class Zenos(Gtk.Window):
    def __init__(self):
        super().__init__(title="ZENOS Browser")
        self.set_default_size(1120, 720)
        try:
            self.set_wmclass("zenos-browser", "ZENOS Browser")
        except Exception:
            pass
        if os.path.exists(ICON):
            try:
                self.set_icon_from_file(ICON)
            except Exception:
                pass
        self.set_decorated(False)
        # an alpha-capable window, so popovers drawn by a web view can have soft shadows and round corners
        try:
            vis = self.get_screen().get_rgba_visual()
            if vis is not None:
                self.set_visual(vis)
        except Exception:
            pass
        self.level = read_level()
        self.lvl_text, self.lvl_color = LEVELS.get(self.level, LEVELS[1])

        # content web view (de-Google context)
        try:
            dm = WebKit2.WebsiteDataManager(
                base_data_directory=os.path.join(HOME, ".local/share/zenos/webdata"),
                base_cache_directory=os.path.join(HOME, ".cache/zenos/web"))
            ctx = WebKit2.WebContext.new_with_website_data_manager(dm)
        except Exception:
            dm = None
            ctx = WebKit2.WebContext.get_default()
        # keep sign-ins and site settings across restarts (WebKit keeps cookies in memory only
        # unless told where to store them); third-party cookies stay blocked and tracking prevention is on
        try:
            cm = (dm or ctx.get_website_data_manager()).get_cookie_manager()
            os.makedirs(os.path.join(HOME, ".local/share/zenos/webdata"), exist_ok=True)
            cm.set_persistent_storage(os.path.join(HOME, ".local/share/zenos/webdata/cookies.sqlite"),
                                      WebKit2.CookiePersistentStorage.SQLITE)
            cm.set_accept_policy(WebKit2.CookieAcceptPolicy.NO_THIRD_PARTY)
            (dm or ctx.get_website_data_manager()).set_itp_enabled(True)
        except Exception as e:
            print("cookie storage:", e)
        ctx.set_cache_model(WebKit2.CacheModel.WEB_BROWSER)
        ctx.connect("download-started", self.on_download)
        self.ctx = ctx
        self.stack = Gtk.Stack()
        self.tabs = []
        self.cur = None

        # toolbar web view (exact Figma chrome) with JS bridge
        ucm = WebKit2.UserContentManager()
        ucm.register_script_message_handler("zenos")
        ucm.connect("script-message-received::zenos", self.on_bar_msg)
        self.bar = WebKit2.WebView.new_with_user_content_manager(ucm)
        self.bar.set_size_request(-1, BAR_H)
        self.bar.set_background_color(Gdk.RGBA(0.18, 0.18, 0.2, 1))
        self.bar.load_uri("file://" + TOOLBAR)
        self.bar.connect("load-changed", self._bar_loaded)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        box.pack_start(self.bar, False, False, 0)
        self.signin = zenos_signin.SignIn(self)          # sign-in with the phone (zenos_credd)
        box.pack_start(self.signin.widget, False, False, 0)
        self.overlay = Gtk.Overlay()
        self.overlay.add(self.stack)
        pucm = WebKit2.UserContentManager()
        pucm.register_script_message_handler("zpanel")
        pucm.connect("script-message-received::zpanel", self.on_panel_msg)
        self.panel = WebKit2.WebView.new_with_user_content_manager(pucm)
        self.panel.set_background_color(Gdk.RGBA(0, 0, 0, 0))
        try:   # software-drawn, so its transparent corners and shadow blend over the page below
            self.panel.get_settings().set_hardware_acceleration_policy(WebKit2.HardwareAccelerationPolicy.NEVER)
        except Exception as e:
            print("panel accel:", e)
        self.panel.set_halign(Gtk.Align.START)
        self.panel.set_valign(Gtk.Align.START)
        self.panel.set_no_show_all(True)
        self.bar.connect("button-press-event", self._outside_click)
        self.panel.load_uri("file://" + PANEL)
        self.overlay.add_overlay(self.panel)
        self._panel_anchor = None
        self.prefs = self._load_prefs()
        box.pack_start(self.overlay, True, True, 0)
        self.add(box)
        self.connect("size-allocate", self._on_alloc)
        self.connect("key-press-event", self.on_key)
        self.new_tab()

    # ---------- tabs ----------
    def make_view(self, related=None):
        # a related view (new tab from a link) inherits the context and the sign-in script from the view that opened it
        v = WebKit2.WebView.new_with_related_view(related) if related else \
            WebKit2.WebView(web_context=self.ctx, user_content_manager=self.signin.ucm)
        v.set_background_color(Gdk.RGBA(0.1, 0.1, 0.12, 1))
        st = v.get_settings()
        st.set_user_agent("Mozilla/5.0 (X11; ZENOS x86_64) AppleWebKit/605.1.15 "
                          "(KHTML, like Gecko) ZENOS/1.0 Safari/605.1.15")
        st.set_enable_developer_extras(False)
        v.connect("decide-policy", self.on_decide)
        v.connect("notify::uri", self.on_uri)
        v.connect("notify::title", self.on_title)
        v.connect("create", self.on_create)
        v.connect("button-press-event", self._outside_click)
        v.connect("run-file-chooser", self.on_file_chooser)
        v.connect("enter-fullscreen", self.on_enter_fs)
        v.connect("leave-fullscreen", self.on_leave_fs)
        v.connect("load-changed", self.on_load_tls)
        self.signin.view_created(v)
        return v

    # refuse sites whose certificate chain contains a compromised CA key (system/lib/distrust.json),
    # even when a still-trusted root cross-signed that key
    def on_load_tls(self, v, ev):
        if ev != WebKit2.LoadEvent.COMMITTED:
            return
        try:
            ok, cert, _ = v.get_tls_info()
            bad = zdistrust.blocked_gio(cert) if ok and cert is not None else None
        except Exception:
            bad = None
        if bad:
            uri = v.get_uri() or ""
            v.stop_loading()
            host = GLib.markup_escape_text(urlparse(uri).hostname or uri)
            v.load_alternate_html(
                "<html><body style='font:15px sans-serif;background:#1a1a1f;color:#eee;padding:60px'>"
                f"<h2>Connection refused</h2><p>{host} uses a certificate from a compromised authority:</p>"
                f"<p><b>{GLib.markup_escape_text(bad)}</b></p><p>ZENOS will not open this site.</p></body></html>",
                uri, None)

    # video / page fullscreen: hide our chrome and take the whole screen, like other browsers
    def on_enter_fs(self, v):
        self.bar.hide()
        self.shape_combine_region(None)
        self._fs = True
        self.fullscreen()
        return False

    def on_leave_fs(self, v):
        self._fs = False
        self.unfullscreen()
        self.bar.show()
        GLib.idle_add(lambda: (self._on_alloc(self, self.get_allocation()), False)[1])
        return False

    def new_tab(self, uri=None, related=None):
        v = self.make_view(related)
        v.show()
        self.stack.add(v)
        self.tabs.append(v)
        self.switch_to(v)
        if related is None:
            if uri:
                self.navigate(uri)
            else:
                self.load_start(v)
        self.push_tabs()
        return v

    def on_create(self, view, action):
        # link with target=_blank / window.open -> a new tab next to it
        return self.new_tab(related=view)

    def switch_to(self, v):
        self.signin.on_switch(v)
        if getattr(self, "panel", None) is not None and self.panel.get_visible():
            self.hide_panel(commit=True)
        self.cur = v
        self.content = v
        self.stack.set_visible_child(v)
        self.on_uri(v)
        self.on_title(v)
        self.push_tabs()

    def close_tab(self, i):
        if not (0 <= i < len(self.tabs)):
            return
        v = self.tabs.pop(i)
        was_cur = v is self.cur
        self.stack.remove(v)
        v.destroy()
        if not self.tabs:
            self.new_tab()
            return
        if was_cur:
            self.switch_to(self.tabs[min(i, len(self.tabs) - 1)])
        self.push_tabs()

    def tab_label(self, v):
        t = v.get_title() or ""
        u = v.get_uri() or ""
        if not t:
            t = "" if u.startswith("zenos://") else (urlparse(u).hostname or u)
        return t or "New Tab"

    def push_tabs(self):
        data = [{"t": self.tab_label(v), "a": v is self.cur} for v in self.tabs]
        try:
            self.bar.run_javascript("window.zenosTabs&&window.zenosTabs(%s)" % json.dumps(data), None, None, None)
        except Exception:
            pass

    def _bar_loaded(self, w, ev):
        if ev == WebKit2.LoadEvent.FINISHED:
            self.push_tabs()
            self.on_uri(self.cur)
            self.refresh_bm()

    def focus_addr(self):
        try:
            self.bar.grab_focus()
            self.bar.run_javascript("window.zenosFocusAddr&&window.zenosFocusAddr()", None, None, None)
        except Exception:
            pass

    def on_key(self, w, ev):
        # Ctrl on PC keyboards; Command (Super/Meta) when used from a Mac
        ctrl = ev.state & (Gdk.ModifierType.CONTROL_MASK | Gdk.ModifierType.SUPER_MASK | Gdk.ModifierType.META_MASK)
        if not ctrl:
            return False
        k = Gdk.keyval_name(ev.keyval) or ""
        shift = ev.state & Gdk.ModifierType.SHIFT_MASK
        if shift and k in ("b", "B"):
            self.toggle_bar(); return True
        if shift and k in ("o", "O"):
            self.open_manager(); return True
        if k in ("d", "D") and not shift:
            # same as clicking the star, so the popover opens right under it
            self._js(self.bar, "document.getElementById('star').click()"); return True
        if k in ("t", "T"):
            self.new_tab(); self.focus_addr(); return True
        if k in ("w", "W"):
            self.close_tab(self.tabs.index(self.cur)); return True
        if k in ("l", "L"):
            self.focus_addr(); return True
        if k in ("Tab", "ISO_Left_Tab") and len(self.tabs) > 1:
            i = self.tabs.index(self.cur)
            step = -1 if (ev.state & Gdk.ModifierType.SHIFT_MASK) else 1
            self.switch_to(self.tabs[(i + step) % len(self.tabs)]); return True
        return False

    def on_bar_msg(self, ucm, js_result):
        try:
            val = js_result.get_js_value().to_string()
            msg = json.loads(val)
        except Exception:
            return
        cmd = msg.get("cmd")
        if cmd == "back":
            self.content.go_back()
        elif cmd == "forward":
            self.content.go_forward()
        elif cmd == "reload":
            self.content.reload()
        elif cmd == "home":
            self.load_start()
        elif cmd == "newtab":
            self.new_tab(); self.focus_addr()
        elif cmd == "tab":
            i = int(msg.get("i", -1))
            if 0 <= i < len(self.tabs):
                self.switch_to(self.tabs[i])
        elif cmd == "closetab":
            self.close_tab(int(msg.get("i", -1)))
        elif cmd == "navigate":
            self.navigate(msg.get("url", ""))
        elif cmd == "close":
            self.close()
        elif cmd == "min":
            self.iconify()
        elif cmd == "max":
            self._toggle_max()
        elif cmd == "drag":
            self._begin_drag()
        elif cmd == "star":
            self.bm_star(msg.get("x"))
        elif cmd == "bmopen":
            try:
                n, _ = BM.find(BM.load(), msg.get("id", ""))
                self.open_url(n.get("url", ""), bool(msg.get("nt")))
            except Exception:
                pass
        elif cmd == "bmfolder":
            self.bm_folder(msg.get("id", ""), msg.get("x", 0))
        elif cmd == "menu":
            self.show_menu(msg.get("x", 0))

    # ================= bookmarks =================
    def _load_prefs(self):
        try:
            with open(PREFS) as f:
                return json.load(f)
        except Exception:
            return {"showBar": True}

    def _save_prefs(self):
        try:
            os.makedirs(os.path.dirname(PREFS), exist_ok=True)
            with open(PREFS, "w") as f:
                json.dump(self.prefs, f)
        except Exception:
            pass

    def _js(self, view, code):
        try:
            view.run_javascript(code, None, None, None)
        except Exception:
            pass

    def _push_star(self):
        u = (self.cur.get_uri() or "") if self.cur else ""
        able = u.startswith(("http://", "https://"))
        on = bool(able and BM.find_url(BM.load(), u))
        self._js(self.bar, "window.zenosStar&&window.zenosStar(%s,%s)" % (json.dumps(on), json.dumps(able)))

    def refresh_bm(self, skip=None):
        d = BM.load()
        show = bool(self.prefs.get("showBar", True))
        items = [{"id": c["id"], "type": c["type"], "title": c["title"], "url": c.get("url", "")} for c in d["bar"]["children"]]
        self._js(self.bar, "window.zenosBar&&window.zenosBar(%s,%s)" % (json.dumps(items), json.dumps(show)))
        self.bar.set_size_request(-1, BAR_H + (BMBAR_H if show else 0))
        self._push_star()
        for v in self.tabs:
            if getattr(v, "zenos_manager", False) and v is not skip:
                self._js(v, "window.zbmChanged&&window.zbmChanged()")

    def toggle_bar(self):
        self.prefs["showBar"] = not self.prefs.get("showBar", True)
        self._save_prefs()
        self.refresh_bm()

    def open_url(self, url, new_tab=False):
        if not url:
            return
        if new_tab or getattr(self.cur, "zenos_manager", False):
            self.new_tab(url)
        else:
            self.navigate(url)

    # ---- popover panel (add / edit bookmark, folder menu, more menu) ----
    def show_panel(self, state, anchor_x, align):
        self._pgen = getattr(self, "_pgen", 0) + 1
        state["gen"] = self._pgen
        self._panel_anchor = (anchor_x, align)
        self._panel_state = state
        self._js(self.panel, "window.zpShow&&window.zpShow(%s)" % json.dumps(state))

    def _place_panel(self, w, h):
        if not self._panel_anchor:
            return
        x, align = self._panel_anchor
        x = int(x or 0)
        left = x - w if align == "right" else x - PAD
        left = max(0, min(left, self.get_allocated_width() - w))
        self.panel.set_size_request(w, h)
        self.panel.set_margin_start(left)
        self.panel.set_margin_top(0)
        self.panel.show()
        self.panel.grab_focus()

    def hide_panel(self, commit=False):
        if commit and self.panel.get_visible() and getattr(self, "_panel_state", {}).get("mode") == "edit":
            self._js(self.panel, "window.zpCommit&&window.zpCommit()")
            return
        self._panel_anchor = None
        self.panel.hide()
        self._js(self.bar, "window.zenosBarOpen&&window.zenosBarOpen('')")
        if self.cur:
            self.cur.grab_focus()

    def _outside_click(self, *a):
        # clicking anywhere else closes it (an edited name/folder is kept, like other browsers)
        if self.panel.get_visible():
            self.hide_panel(commit=True)
        return False

    def bm_star(self, x=None):
        u = self.cur.get_uri() or ""
        if not u.startswith(("http://", "https://")):
            return
        d = BM.load()
        n = BM.find_url(d, u)
        is_new = n is None
        if is_new:
            n = BM.add(d, "bar", self.cur.get_title() or u, u)
            BM.save(d)
            self.refresh_bm()
        _, parent = BM.find(d, n["id"])
        if x is None:
            x = self.get_allocated_width() // 2 + 220 + 14
        self.show_panel({"mode": "edit", "isNew": is_new, "id": n["id"], "title": n["title"], "url": n.get("url"),
                         "folder": parent["id"], "folders": BM.folders(d)}, x + PAD, "right")

    def bm_folder(self, fid, x):
        try:
            n, _ = BM.find(BM.load(), fid)
        except KeyError:
            return
        self._js(self.bar, "window.zenosBarOpen&&window.zenosBarOpen(%s)" % json.dumps(fid))
        self.show_panel({"mode": "folder", "root": n}, x, "left")

    def show_menu(self, x):
        show = bool(self.prefs.get("showBar", True))
        u = self.cur.get_uri() or ""
        items = [{"label": "New tab", "key": "Ctrl+T", "act": "newtab"}, "-",
                 {"label": "Bookmark this page…", "key": "Ctrl+D", "act": "star", "dis": not u.startswith(("http://", "https://"))},
                 {"label": "Show bookmarks bar", "key": "Ctrl+Shift+B", "act": "togglebar", "check": show},
                 {"label": "Bookmark manager", "key": "Ctrl+Shift+O", "act": "manager"}]
        self.show_panel({"mode": "menu", "items": items}, x + PAD, "right")

    def on_panel_msg(self, ucm, js_result):
        try:
            msg = json.loads(js_result.get_js_value().to_string())
        except Exception:
            return
        cmd = msg.get("cmd")
        if cmd == "err":
            print("panel error:", msg.get("m"), msg.get("l"), flush=True)
        if cmd == "size":
            self._place_panel(int(msg.get("w", 300)), int(msg.get("h", 200)))
        elif cmd == "close":
            if msg.get("gen") in (None, getattr(self, "_pgen", 0)):
                self.hide_panel()
        elif cmd == "save":
            try:
                d = BM.load()
                BM.update(d, msg["id"], title=msg.get("title", ""))
                _, parent = BM.find(d, msg["id"])
                if msg.get("folder") and msg["folder"] != parent["id"]:
                    BM.move(d, msg["id"], msg["folder"])
                BM.save(d)
            except Exception as e:
                print("bookmark save:", e)
            self.refresh_bm()
        elif cmd == "remove":
            try:
                d = BM.load(); BM.remove(d, msg["id"]); BM.save(d)
            except Exception:
                pass
            self.hide_panel()
            self.refresh_bm()
        elif cmd == "manager":
            self.hide_panel()
            self.open_manager(msg.get("id"))
        elif cmd == "open":
            self.hide_panel()
            self.open_url(msg.get("url", ""), bool(msg.get("nt")))
        elif cmd == "openall":
            self.hide_panel()
            for u in msg.get("urls", [])[:30]:
                if str(u).startswith(("http://", "https://")):
                    self.new_tab(u)
        elif cmd == "act":
            a = msg.get("act")
            self.hide_panel()
            if a == "newtab":
                self.new_tab(); self.focus_addr()
            elif a == "star":
                self._js(self.bar, "document.getElementById('star').click()")
            elif a == "togglebar":
                self.toggle_bar()
            elif a == "manager":
                self.open_manager()

    # ---- bookmark manager (an internal page in a tab) ----
    def open_manager(self, sel=None):
        for v in self.tabs:
            if getattr(v, "zenos_manager", False):
                self.switch_to(v)
                if sel:
                    self._js(v, "window.zbmSelect&&window.zbmSelect(%s)" % json.dumps(sel))
                return v
        ucm = WebKit2.UserContentManager()
        ucm.register_script_message_handler("zbm")
        v = WebKit2.WebView(web_context=self.ctx, user_content_manager=ucm)
        v.zenos_manager = True
        ucm.connect("script-message-received::zbm", lambda u, r, view=v: self.on_manager_msg(view, r))
        v.set_background_color(Gdk.RGBA(0.1, 0.1, 0.12, 1))
        v.get_settings().set_enable_developer_extras(False)
        v.connect("notify::uri", self.on_uri)
        v.connect("notify::title", self.on_title)
        v.connect("decide-policy", self._manager_policy)
        v.connect("button-press-event", self._outside_click)
        v.show()
        self.stack.add(v)
        self.tabs.append(v)
        with open(MANAGER) as f:
            v.load_html(f.read(), "zenos://bookmarks/" + ("#sel=" + sel if sel else ""))
        self.switch_to(v)
        self.push_tabs()
        return v

    def _manager_policy(self, web, decision, dtype):
        # the manager tab never leaves its own page; links open as normal tabs
        if dtype in (WebKit2.PolicyDecisionType.NAVIGATION_ACTION, WebKit2.PolicyDecisionType.NEW_WINDOW_ACTION):
            try:
                uri = decision.get_navigation_action().get_request().get_uri() or ""
            except Exception:
                return False
            if not uri.startswith(("zenos://bookmarks", "about:")):
                decision.ignore()
                if uri.startswith(("http://", "https://")):
                    GLib.idle_add(lambda: (self.new_tab(uri), False)[1])
                return True
        return False

    def _file_dialog(self, save, name=None):
        flt = [("Bookmark files (.html)", ["*.html", "*.htm"])]
        if save:
            return zenos_picker.save_file(self, "Export bookmarks", name, os.path.join(HOME, "Documents"), flt)
        r = zenos_picker.open_files(self, "Import bookmarks", DOWNLOADS, flt, ok_label="Import")
        return r[0] if r else None

    def on_file_chooser(self, view, request):
        # <input type=file> on web pages: the ZENOS picker
        try:
            multi = request.get_select_multiple()
        except Exception:
            multi = False
        paths = zenos_picker.open_files(self, "Choose a file to upload", HOME, multiple=multi, ok_label="Choose")
        if paths:
            request.select_files(paths)
        else:
            request.cancel()
        return True

    def on_manager_msg(self, view, js_result):
        if not (view.get_uri() or "").startswith("zenos://bookmarks"):
            return
        try:
            msg = json.loads(js_result.get_js_value().to_string())
        except Exception:
            return
        rid, cmd, a = msg.get("id"), msg.get("cmd"), msg.get("args") or {}
        changed = False
        try:
            d = BM.load()
            if cmd == "tree":
                out = {"bar": d["bar"], "other": d["other"]}
            elif cmd == "add_folder":
                out = BM.add(d, a.get("parent") or "other", a.get("title") or "New folder", kind="folder"); changed = True
            elif cmd == "update":
                out = BM.update(d, a["id"], title=a.get("title"), url=a.get("url")); changed = True
            elif cmd == "remove":
                out = BM.remove(d, a["id"]); changed = True
            elif cmd == "restore":
                out = BM.restore(d, a["node"], a.get("parent"), a.get("index")); changed = True
            elif cmd == "move":
                out = BM.move(d, a["id"], a["parent"], a.get("index")); changed = True
            elif cmd == "open":
                u = a.get("url", "")
                if u.startswith(("http://", "https://")):
                    GLib.idle_add(lambda: (self.new_tab(u) if a.get("nt") else self._open_from_manager(view, u), False)[1])
                out = True
            elif cmd == "import":
                path = self._file_dialog(False)
                out = None
                if path:
                    with open(path, encoding="utf-8", errors="replace") as f:
                        out = BM.import_html(d, f.read()); changed = True
            elif cmd == "export":
                path = self._file_dialog(True, "bookmarks-%s.html" % time.strftime("%Y-%m-%d"))
                out = None
                if path:
                    with open(path, "w", encoding="utf-8") as f:
                        f.write(BM.export_html(d))
                    out = path.replace(HOME, "~", 1)
            else:
                raise ValueError("unknown")
            if changed:
                BM.save(d)
            self._js(view, "window.__zr(%d,true,%s)" % (rid, json.dumps(out, ensure_ascii=False)))
        except Exception as e:
            msg = str(e) if isinstance(e, (ValueError, KeyError)) else "Something went wrong."
            self._js(view, "window.__zr(%d,false,%s)" % (rid, json.dumps(msg.strip("'\""))))
        if changed:
            self.refresh_bm(skip=view)      # that page reloads its own list

    def _open_from_manager(self, view, url):
        # double-click in the manager: open in a tab next to it (the manager stays open)
        self.new_tab(url)

    def _begin_drag(self):
        try:
            seat = Gdk.Display.get_default().get_default_seat()
            pos = seat.get_pointer().get_position()
            self.begin_move_drag(1, pos[1], pos[2], Gtk.get_current_event_time())
        except Exception:
            pass

    def _toggle_max(self):
        if self.is_maximized():
            self.unmaximize()
        else:
            self.maximize()

    def _on_alloc(self, widget, alloc):
        try:
            if self.is_maximized() or getattr(self, "_fs", False):
                self.shape_combine_region(None)
            else:
                self._round_window(alloc.width, alloc.height, 13)
        except Exception:
            pass

    def _round_window(self, w, h, r):
        import cairo
        if w <= 2 * r or h <= 2 * r:
            return
        reg = cairo.Region(cairo.RectangleInt(0, r, w, h - 2 * r))
        reg.union(cairo.RectangleInt(r, 0, w - 2 * r, h))
        for i in range(r):
            dy = r - i - 0.5
            dx = r - int(round((r * r - dy * dy) ** 0.5))
            reg.union(cairo.RectangleInt(dx, i, w - 2 * dx, 1))
            reg.union(cairo.RectangleInt(dx, h - 1 - i, w - 2 * dx, 1))
        self.shape_combine_region(reg)

    def load_start(self, v=None):
        (v or self.cur).load_html(START_PAGE.replace("__LVL__", self.lvl_text), "zenos://start/")

    def navigate(self, text):
        t = (text or "").strip()
        if not t:
            return
        if t.rstrip("/") in ("zenos://bookmarks", "about:bookmarks"):
            self.open_manager(); return
        if t.startswith("http://") or t.startswith("https://"):
            url = t
        elif ("." in t) and (" " not in t):
            url = "https://" + t
        else:
            url = "https://html.duckduckgo.com/html/?q=" + GLib.uri_escape_string(t, None, True)
        self.content.load_uri(url)

    def on_uri(self, view=None, *a):
        if view is not None and view is not self.cur:
            self.push_tabs()
            return
        u = self.cur.get_uri() or ""
        disp = "zenos://bookmarks" if u.startswith("zenos://bookmarks") else ("" if u.startswith("zenos://") else u)
        try:
            self.bar.run_javascript("window.zenosSetAddr(%s)" % json.dumps(disp), None, None, None)
            self._push_star()
        except Exception:
            pass
        self.push_tabs()

    def on_title(self, view=None, *a):
        self.push_tabs()
        if view is not None and view is not self.cur:
            return
        t = self.cur.get_title() or "ZENOS Browser"
        self.set_title(t + " — ZENOS Browser")

    def is_local(self, uri):
        if uri.startswith(("zenos://", "about:", "file:", "data:", "blob:")):
            return True
        try:
            h = urlparse(uri).hostname or ""
        except Exception:
            h = ""
        return h in ("", "localhost", "127.0.0.1", "::1")

    def on_decide(self, web, decision, dtype):
        if dtype in (WebKit2.PolicyDecisionType.NAVIGATION_ACTION,
                     WebKit2.PolicyDecisionType.NEW_WINDOW_ACTION):
            try:
                uri = decision.get_navigation_action().get_request().get_uri() or ""
            except Exception:
                return False
            if self.level >= 4 and not self.is_local(uri):
                decision.ignore()
                GLib.idle_add(self.show_blocked, web, uri)
                return True
        return False

    def show_blocked(self, web, uri):
        html = BLOCKED_PAGE.replace("__LVL__", self.lvl_text).replace("__URL__", uri)
        web.load_html(html, "zenos://blocked/")
        return False

    def on_download(self, ctx, download):
        def decide(dl, name):
            # the site names the file: keep only a plain name (no folders, no hidden file, no control characters)
            name = "".join(c for c in os.path.basename(str(name or "").replace("\\", "/")) if c.isprintable())
            name = name.lstrip(".").strip()[:200] or "download"
            dest = os.path.join(DOWNLOADS, name)
            base, ext = os.path.splitext(dest)
            i = 1
            while os.path.lexists(dest):                     # a link left there is never written through
                dest = "%s (%d)%s" % (base, i, ext)
                i += 1
            dl.set_destination(GLib.filename_to_uri(dest, None))
            return True
        download.connect("decide-destination", decide)


def main():
    import sys
    win = Zenos()
    win.connect("destroy", Gtk.main_quit)
    win.show_all()
    try:
        _s = Gdk.Screen.get_default()
        win.move(max(0, (_s.get_width() - 1120) // 2),
                 max(40, (_s.get_height() - 720) // 2 - 6))
    except Exception:
        pass
    if len(sys.argv) > 1 and sys.argv[1].strip():
        win.navigate(sys.argv[1].strip())
    Gtk.main()


if __name__ == "__main__":
    main()
