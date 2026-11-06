#!/usr/bin/env python3
"""zenos_portcheck.py PORT [SECONDS]: exit 0 when the program listening on 127.0.0.1:PORT runs as this user.

The office apps open http://127.0.0.1:<port>/ in a window. Any account on the PC can listen on a free port first;
the window would then show that program's page and hand it what the person types. The kernel says which account
owns each listening socket (/proc/net/tcp, /proc/net/tcp6), so the window is opened only on this user's own server.
"""
import os, sys, time

LOOPBACK = {"0100007F", "00000000000000000000000001000000"}       # 127.0.0.1, ::1 (as the kernel writes them)
ANY = {"00000000", "00000000000000000000000000000000"}            # 0.0.0.0, :: (also reach 127.0.0.1)


def listeners(port):
    """uids of the sockets listening on this port on loopback or any address"""
    out = []
    for f in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            lines = open(f).read().splitlines()[1:]
        except OSError:
            continue
        for l in lines:
            p = l.split()
            if len(p) < 8 or p[3] != "0A":                      # 0A: listening
                continue
            addr, _, hexport = p[1].partition(":")
            if int(hexport, 16) == port and (addr in LOOPBACK or addr in ANY or addr.endswith("0100007F")):
                out.append(int(p[7]))
    return out


def ok(port, wait=5.0):
    end = time.time() + wait
    while True:
        u = listeners(port)
        if u:
            return all(x == os.getuid() for x in u)
        if time.time() >= end:
            return False
        time.sleep(0.1)


if __name__ == "__main__":
    port = int(sys.argv[1])
    if not ok(port, float(sys.argv[2]) if len(sys.argv) > 2 else 5.0):
        sys.stderr.write("ZENOS: port %d is held by another account (or nothing answers). Not opening it.\n" % port)
        sys.exit(1)
