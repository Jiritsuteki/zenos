#!/usr/bin/env python3
"""ZENOS app window: shows a local ZENOS web app in its own desktop window (no browser chrome).
Engine: WebKitGTK (non-Google), same as the ZENOS Browser.
usage: zenos_webapp.py URL TITLE [ICON] [WIDTHxHEIGHT]"""
import os, sys, re, subprocess
from urllib.parse import urlparse, unquote
os.environ.pop("WAYLAND_DISPLAY", None)
os.environ["GDK_BACKEND"] = "x11"
import gi
gi.require_version("Gtk", "3.0")
gi.require_version("WebKit2", "4.1")
from gi.repository import Gtk, WebKit2

url, title = sys.argv[1], sys.argv[2]
icon = sys.argv[3] if len(sys.argv) > 3 else ""
w, h = (int(x) for x in (sys.argv[4] if len(sys.argv) > 4 else "980x640").split("x"))
HOME = os.path.expanduser("~")
BROWSER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin", "zenos-browser.sh")
slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-") or "app"
base = os.path.join(HOME, ".local/share/zenos/webapp-data", slug)
os.makedirs(base, exist_ok=True)
own = urlparse(url)

dm = WebKit2.WebsiteDataManager(base_data_directory=os.path.join(base, "data"), base_cache_directory=os.path.join(base, "cache"))
ctx = WebKit2.WebContext.new_with_website_data_manager(dm)
view = WebKit2.WebView.new_with_context(ctx)
s = view.get_settings()
s.set_enable_developer_extras(False)
s.set_javascript_can_open_windows_automatically(False)

def same_app(u):
    p = urlparse(u)
    return p.scheme in ("http", "https") and p.hostname == own.hostname and p.port == own.port

def on_perm(_v, req):                       # only this local app may show notifications; everything else is refused
    if isinstance(req, WebKit2.NotificationPermissionRequest) and same_app(view.get_uri() or ""):
        req.allow()
    else:
        req.deny()
    return True

def on_policy(_v, decision, kind):          # links that leave the app open in the ZENOS Browser, never inside the app window
    if kind in (WebKit2.PolicyDecisionType.NAVIGATION_ACTION, WebKit2.PolicyDecisionType.NEW_WINDOW_ACTION):
        target = decision.get_navigation_action().get_request().get_uri()
        if not same_app(target) and not target.startswith("about:") and not target.startswith("data:") and not target.startswith("blob:"):
            decision.ignore()
            subprocess.Popen([BROWSER, target], start_new_session=True)
            return True
    return False

def on_download(_ctx, dl):                  # attachments go to ~/Downloads
    def dest(d, suggested):
        os.makedirs(os.path.join(HOME, "Downloads"), exist_ok=True)
        name = os.path.basename(unquote(suggested or "download")) or "download"
        d.set_destination("file://" + os.path.join(HOME, "Downloads", name))
        return True
    dl.connect("decide-destination", dest)

view.connect("permission-request", on_perm)
view.connect("decide-policy", on_policy)
ctx.connect("download-started", on_download)

win = Gtk.Window(title=title)
win.set_wmclass("zenos-" + slug, title)
if icon and os.path.exists(icon):
    try: win.set_icon_from_file(icon)
    except Exception: pass
try:                                        # never open taller/wider than the screen (keeps the message box visible)
    gi.require_version("Gdk", "3.0"); from gi.repository import Gdk
    mon = Gdk.Display.get_default().get_primary_monitor() or Gdk.Display.get_default().get_monitor(0)
    wa = mon.get_workarea(); w = min(w, wa.width - 40); h = min(h, wa.height - 60)
except Exception: pass
win.set_default_size(w, h)
win.add(view)
win.connect("destroy", Gtk.main_quit)
start = os.environ.pop("ZENOS_WEBAPP_START", "")      # the first page may carry a key; it is not kept in the environment
view.load_uri(start if start and same_app(start) else url)
win.show_all()
Gtk.main()
