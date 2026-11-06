#!/bin/bash
# ZENOS Docs launcher (dark, local relay server + WebKit window)
unset WAYLAND_DISPLAY
export GDK_BACKEND=x11
R="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"   # program files
APP=$R/apps/docs
LOG="${XDG_RUNTIME_DIR:-$HOME/.cache}/zdocs_srv.log"
if ! pgrep -u "$(id -u)" -f "zoffice_server.py $APP " >/dev/null 2>&1; then
  setsid python3 "$R/apps/common/zoffice_server.py" "$APP" 5175 >"$LOG" 2>&1 < /dev/null &
fi
# open the window only on this user's own server: another account could be listening on the port first
if ! python3 "$R/bin/zenos_portcheck.py" 5175 5; then
  notify-send "ZENOS Docs" "Port 5175 is used by another account on this PC. ZENOS Docs was not opened." 2>/dev/null
  exit 1
fi
exec python3 "$R/bin/zenos-webview.py" "http://127.0.0.1:5175/" "ZENOS Docs" "$@"
