#!/bin/bash
# ZENOS Browser launcher - WebKitGTK shell (non-Google, level-gated).
# Engine is maintained by the distro (WebKitGTK); we own only this shell.
unset WAYLAND_DISPLAY
export GDK_BACKEND=x11
R="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"   # program files
# started by zenos-launchd (root): the password vault serves only a browser it started (zenos_launchd.py)
python3 -I "$R/bin/zenos_launch.py" browser "$@"; rc=$?
[ "$rc" = 3 ] || exit "$rc"
exec python3 -E -s "$R/bin/zenos_webkit.py" "$@"     # development layout: no zenos-launchd, no password vault
