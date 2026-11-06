"""End-to-end check of zenos-aiguard in a private network namespace (run by test_aiguard.py as
`unshare -rn python3 tests/netns_aiguard.py`): real iptables rules, real TCP connections, the real zenos-decide.
Nothing outside the namespace is touched."""
import json, os, socket, subprocess, sys, tempfile, threading, time

D = tempfile.mkdtemp()
os.environ.update(ZENOS_AI_REGISTRY=D + "/ai.json", ZENOS_AI_LEARNED=D + "/learned.json", ZENOS_EXPOSED=D + "/exposed.json",
                  ZENOS_AIGUARD_SOCK=D + "/g.sock", ZENOS_AIGUARD_LOG=D + "/g.log", ZENOS_AIGUARD_LEDGER=D + "/l.jsonl")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../system/sbin"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../system/lib"))
subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
# the unlisted service: a name (only names are learned) for a public-looking address (a learned entry never blocks
# this machine or a private network), both only inside this namespace
subprocess.run(["ip", "addr", "add", "100.64.0.5/32", "dev", "lo"], check=True)
_gai = socket.getaddrinfo
socket.getaddrinfo = lambda h, *a, **k: _gai("100.64.0.5" if h == "new-ai.test" else h, *a, **k)
import zenos_aiguard as G

EXT, GOV, MIN, NEW = ("127.0.0.2", 8101), ("127.0.0.3", 8102), ("127.0.0.4", 8103), ("100.64.0.5", 8104)
for a in (EXT, GOV, MIN, NEW):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(a); s.listen(64)
    threading.Thread(target=lambda s=s: [c.close() for c, _ in iter(s.accept, None)], daemon=True).start()
json.dump({"services": [{"url": "http://%s:%d/v1" % EXT, "kind": "external-ai"},
                        {"url": "http://%s:%d/v1" % GOV, "kind": "gov-ai"},
                        {"url": "http://%s:%d/v1" % MIN, "kind": "ministry-ai"}]}, open(D + "/ai.json", "w"))


def reach(a):
    s = socket.socket(); s.settimeout(2)
    try:
        s.connect(a); return True
    except OSError:
        return False
    finally:
        s.close()


def expose(n):
    json.dump({"level": n}, open(D + "/exposed.json", "w"))


g = G.Guard()
out = {}
for lvl in range(0, 6):
    expose(lvl)
    ok, seen = g.sync()
    out[lvl] = [ok, seen, reach(EXT), reach(GOV), reach(MIN)]
# a service the administrator did not list is learned as external-ai and blocked from then on
expose(3)
out["check_new"] = g.check("http://new-ai.test:%d/v1" % NEW[1])
out["new_reach"] = reach(NEW)
out["check_gov"] = g.check("http://%s:%d/v1" % GOV)
# someone removes the hook: the next sync puts it back
subprocess.run(["iptables", "-D", "OUTPUT", "-j", "ZENOS_AI"])
out["unhooked_reach"] = reach(EXT)
g.sync()
out["rehooked_reach"] = reach(EXT)
# an unreadable exposure record counts as the highest level
open(D + "/exposed.json", "w").write("{broken")
g.sync()
out["broken"] = [reach(EXT), reach(GOV), reach(MIN)]
# reset: back to everything reachable
os.unlink(D + "/exposed.json")
g.sync()
out["after_reset"] = [reach(EXT), reach(GOV), reach(MIN), reach(NEW)]
print(json.dumps(out))
