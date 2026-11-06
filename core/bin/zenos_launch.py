#!/usr/bin/env python3
"""Ask zenos-launchd to start the browser or ZENOS Messages for this person (see system/sbin/zenos_launchd.py).

  zenos_launch.py browser [url...]
  zenos_launch.py messenger <account> <port>
Exit 3 when zenos-launchd is not there (a development layout): the caller then starts the program itself, and the
password vault does not serve it."""
import json, os, socket, sys

SOCK = os.environ.get("ZENOS_LAUNCH_SOCK", "/run/zenos/launch.sock")
PASS = ("DISPLAY", "XAUTHORITY", "DBUS_SESSION_BUS_ADDRESS", "LANG", "LANGUAGE", "LC_ALL", "XMODIFIERS",
        "GTK_IM_MODULE", "QT_IM_MODULE", "ZENOS_RELAY", "NODE_OPTIONS")


def main(argv):
    if len(argv) < 1 or argv[0] not in ("browser", "messenger"):
        print(__doc__, file=sys.stderr)
        return 2
    if not os.path.exists(SOCK):
        return 3
    args = [os.path.abspath(a) if argv[0] == "browser" and os.path.exists(a) else a for a in argv[1:]]
    msg = {"op": "launch", "program": argv[0], "args": args, "env": {k: os.environ[k] for k in PASS if k in os.environ}}
    try:
        s = socket.socket(socket.AF_UNIX)
        s.settimeout(10)
        s.connect(SOCK)
        s.sendall(json.dumps(msg).encode() + b"\n")
        out = json.loads(s.makefile().readline() or "{}")
    except (OSError, ValueError):
        return 3
    if not out.get("ok"):
        print("ZENOS: " + str(out.get("error")), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
