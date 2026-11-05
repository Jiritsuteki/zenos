"""The proven ZENOS decisions, called from the root services.

Whether a sealed file may be opened, whether an officer's answer is recorded, whether a stop is released and how many
officers a release needs are decided by `zenos-decide`, a program built from the Lean sources in formal/ whose
properties are machine-checked (docs/FORMAL_VERIFICATION.md). This module only gathers the facts the decision needs
and runs it. Anything that goes wrong (program missing, timeout, unreadable answer) is a refusal.

The facts are checked here, outside the proof: signatures (Ed25519 with the enrolled officers' keys), digests, the
clearance file, the roster, the stop state, the clock; for sign-in with the phone, the passkey checks (zwebauthn).
"""
import json, math, os, subprocess, time

_HERE = os.path.dirname(os.path.abspath(__file__))
PROGRAM = os.environ.get("ZENOS_DECIDE") or next(
    (p for p in (os.path.join(_HERE, "zenos-decide"),                                       # installed: /usr/lib/zenos
                 os.path.join(_HERE, "..", "..", "formal", ".lake", "build", "bin", "zenos-decide"))  # repository
     if os.path.isfile(p) and os.access(p, os.X_OK)), None)


class Refused(Exception):
    pass


def ask(req):
    """run one decision; raises Refused when no trustworthy answer comes back"""
    if not PROGRAM:
        raise Refused("zenos-decide is not installed")
    try:
        r = subprocess.run([PROGRAM], input=json.dumps(req, ensure_ascii=True).encode(), capture_output=True,
                           timeout=10, env={})
        out = json.loads(r.stdout or b"{}")
    except (OSError, subprocess.SubprocessError, ValueError) as e:
        raise Refused("zenos-decide failed: %s" % e)
    if r.returncode != 0 or "error" in out:
        raise Refused("zenos-decide refused the request: %s" % out.get("error"))
    return out


def now():
    return math.ceil(time.time())          # whole seconds, rounded so that an expiry is never stretched


def open_file(user, clearance, level, file_hash, halted, roster, grant=None):
    """(allowed, by, reason). grant: dict with requester, holder, file_hash, level, kind, expires, digest_ok, approvals"""
    if grant is not None:
        grant = dict(grant, expires=int(math.floor(float(grant["expires"]))))
    try:
        a = ask({"op": "open", "user": user, "clearance": int(clearance), "level": int(level), "file_hash": file_hash,
                 "now": now(), "halted": bool(halted), "roster": list(roster), "grant": grant})
        return bool(a["allow"]), a.get("by"), a.get("reason")
    except (Refused, KeyError, TypeError, ValueError) as e:
        return False, None, str(e)


def approve(request, roster, who, act, sig_ok, code_ok):
    """'added' | 'declined' | 'refused:<reason>'"""
    try:
        a = ask({"op": "approve", "request": _request(request), "roster": list(roster), "who": who, "act": act,
                 "sig_ok": bool(sig_ok), "code_ok": bool(code_ok)})
        return a["result"] if a["result"] != "refused" else "refused:" + str(a.get("reason"))
    except (Refused, KeyError, TypeError, ValueError) as e:
        return "refused:" + str(e)


def release(halted, request, roster):
    """(release?, counted approvers)"""
    try:
        a = ask({"op": "release", "halted": bool(halted), "request": _request(request), "roster": list(roster)})
        return bool(a["release"]), list(a["approvers"])
    except (Refused, KeyError, TypeError, ValueError):
        return False, []


def release_required(roster, requester, level):
    try:
        return int(ask({"op": "release-required", "roster": list(roster), "requester": requester,
                        "level": int(level)})["required"])
    except (Refused, KeyError, TypeError, ValueError):
        return 1000                        # cannot be met: the PC stays stopped until the decision program is back


def required(level):
    return int(ask({"op": "required", "level": int(level)})["required"])


def flow(src, sink, level=0, print_max=3):
    """may content of level `src` go to `sink` ("folder", "window" with a level; "clipboard", "printer",
    "external-ai", "gov-ai", "ministry-ai")? Refused if the decision cannot be had."""
    try:
        return bool(ask({"op": "flow", "src": max(0, int(src)), "sink": sink, "level": max(0, int(level)),
                         "print_max": max(0, int(print_max))})["allow"])
    except (Refused, KeyError, TypeError, ValueError):
        return False


def chain(start, records):
    """records: [{"prev", "hash", "hash_ok"}] oldest first -> (ok, index of the first broken record, reason, head)"""
    try:
        a = ask({"op": "chain", "start": str(start),
                 "records": [{"prev": str(r.get("prev")), "hash": str(r.get("hash")), "hash_ok": bool(r.get("hash_ok"))}
                             for r in records]})
        return bool(a["ok"]), a.get("index"), a.get("reason"), a.get("head")
    except (Refused, KeyError, TypeError, ValueError) as e:
        return False, 0, "no decision: %s" % e, None


def send(sealed, sig_ok, size, huge_max, plan_ok):
    """(allowed, reason) for the pre-send check"""
    try:
        a = ask({"op": "send", "sealed": bool(sealed), "sig_ok": bool(sig_ok), "size": int(size),
                 "huge_max": int(huge_max), "plan_ok": bool(plan_ok)})
        return bool(a["allow"]), a.get("reason")
    except (Refused, KeyError, TypeError, ValueError) as e:
        return False, "no decision: %s" % e


class EgressStream:
    """the network sentinel's counter: one long-running `zenos-decide egress` that keeps the windows. send() answers
    whether the destination is cut now. If the program cannot answer, the destination is cut (fail closed)."""

    def __init__(self, window_ms, threshold):
        self.args = [PROGRAM or "/nonexistent/zenos-decide", "egress", str(int(window_ms)), str(int(threshold))]
        self.p = None

    def _start(self):
        self.p = subprocess.Popen(self.args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1,
                                  env={})

    def send(self, key, dst, allowed, t_ms, size):
        line = "%s\t%s\t%d\t%d\t%d\n" % (str(key).replace("\t", " ").replace("\n", " "),
                                           str(dst).replace("\t", " ").replace("\n", " "), 1 if allowed else 0,
                                           int(t_ms), max(0, int(size)))
        for _ in range(2):
            try:
                if self.p is None or self.p.poll() is not None:
                    self._start()
                self.p.stdin.write(line)
                self.p.stdin.flush()
                ans = self.p.stdout.readline().strip()
                if ans in ("cut", "ok"):
                    return ans == "cut"
            except (OSError, ValueError):
                pass
            self.p = None
        return True

    def close(self):
        if self.p is not None:
            try:
                self.p.stdin.close()
                self.p.wait(timeout=5)
            except Exception:
                pass


def cred(ttl_ms, used, devices, request, answer, now_ms):
    """(release?, reason) for a password request answered on the phone. devices: [{"device", "user"}];
    request: id, user, origin, entry_origin, tls_ok, code, created (ms); answer: device, sig_ok, challenge_ok,
    origin_ok, user_verified, counter_ok, code (the facts checked by zwebauthn)"""
    try:
        a = ask({"op": "cred", "ttl": int(ttl_ms), "now": int(now_ms), "used": [str(u) for u in used],
                 "devices": [{"device": str(d["device"]), "user": str(d["user"])} for d in devices],
                 "request": {"id": str(request["id"]), "user": str(request["user"]), "origin": str(request["origin"]),
                             "entry_origin": str(request["entry_origin"]), "tls_ok": request["tls_ok"] is True,
                             "code": max(0, int(request["code"])), "created": max(0, int(request["created"]))},
                 "answer": {"device": str(answer["device"]), "code": max(0, int(answer["code"])),
                            **{k: answer[k] is True for k in ("sig_ok", "challenge_ok", "origin_ok", "user_verified",
                                                               "counter_ok")}}})
        return bool(a["allow"]), a.get("reason")
    except (Refused, KeyError, TypeError, ValueError) as e:
        return False, "no decision: %s" % e


def ask_ok(window_ms, max_prompts, now_ms, log):
    """may one more prompt go to the phone? log: times (ms) of the prompts already sent"""
    try:
        return bool(ask({"op": "ask", "window": int(window_ms), "max": int(max_prompts), "now": int(now_ms),
                         "log": [max(0, int(t)) for t in log]})["allow"])
    except (Refused, KeyError, TypeError, ValueError):
        return False


def _request(r):
    """the part of a release request the decision reads; each approval carries sig_ok, checked by the caller"""
    return {"id": str(r["id"]), "requester": str(r["requester"]), "level": int(r["level"]),
            "required": int(r["required"]), "status": str(r["status"]),
            "approvals": [{"approver": str(a["approver"]), "sig_ok": bool(a.get("sig_ok"))} for a in r["approvals"]]}


def key_release(enrolled, sig_ok, fresh, now_s, last_seen, silence, services_ok, pc_halted, recent, rate_max,
                machine_recent, machine_rate_max, assigned, presence_from, presence, user, clearance, level,
                file_hash, roster, grant=None):
    """(allowed, by, reason) for the key service. presence: None or the passkey facts (registered, sig_ok,
    challenge_ok, origin_ok, user_verified, counter_ok); grant as for open_file"""
    if grant is not None:
        grant = dict(grant, expires=int(math.floor(float(grant["expires"]))))
    if presence is not None:
        presence = {k: presence.get(k) is True for k in ("registered", "sig_ok", "challenge_ok", "origin_ok",
                                                          "user_verified", "counter_ok")}
    try:
        a = ask({"op": "key", "enrolled": bool(enrolled), "sig_ok": bool(sig_ok), "fresh": bool(fresh),
                 "now": int(now_s), "last_seen": max(0, int(last_seen)), "silence": max(0, int(silence)),
                 "services_ok": bool(services_ok), "pc_halted": bool(pc_halted), "recent": max(0, int(recent)),
                 "rate_max": max(0, int(rate_max)), "machine_recent": max(0, int(machine_recent)),
                 "machine_rate_max": max(0, int(machine_rate_max)), "assigned": bool(assigned),
                 "presence_from": max(0, int(presence_from)), "presence": presence,
                 "open": {"user": user, "clearance": int(clearance), "level": int(level), "file_hash": file_hash,
                          "now": int(now_s), "halted": False, "roster": list(roster), "grant": grant}})
        return bool(a["allow"]), a.get("by"), a.get("reason")
    except (Refused, KeyError, TypeError, ValueError) as e:
        return False, None, str(e)


def install(f):
    """(allowed, reason) for one package file; f: the facts from zsupply.facts"""
    try:
        a = ask({"op": "install", "nodes": [str(n) for n in f["nodes"]],
                 "votes": [{"node": str(v["node"]), "sig_ok": v["sig_ok"] is True, "record": str(v["record"])}
                           for v in f["votes"]],
                 "record": str(f["record"]), "hash_ok": f["hash_ok"] is True, "signers": [str(s) for s in f["signers"]],
                 "officers": [str(o) for o in f["officers"]], "required": max(0, int(f["required"])),
                 "revoked": f["revoked"] is not False, "ring_open": max(0, int(f["ring_open"])),
                 "now": max(0, int(f["now"]))})
        return bool(a["allow"]), a.get("reason")
    except (Refused, KeyError, TypeError, ValueError) as e:
        return False, "no decision: %s" % e


def _install_fields(f):
    return {"nodes": [str(n) for n in f["nodes"]],
            "votes": [{"node": str(v["node"]), "sig_ok": v["sig_ok"] is True, "record": str(v["record"])} for v in f["votes"]],
            "record": str(f["record"]), "hash_ok": f["hash_ok"] is True, "signers": [str(s) for s in f["signers"]],
            "officers": [str(o) for o in f["officers"]], "required": max(0, int(f["required"])),
            "revoked": f["revoked"] is not False, "ring_open": max(0, int(f["ring_open"])), "now": max(0, int(f["now"]))}


def model(f):
    """(allowed, reason) for loading an AI model kept on the PC; f: the facts from zmodel.facts"""
    try:
        a = ask({"op": "model", **_install_fields(f), "kind_ok": f["kind_ok"] is True, "files_ok": f["files_ok"] is True,
                 "level": max(0, int(f["level"])), "max_level": max(0, int(f["max_level"]))})
        return bool(a["allow"]), a.get("reason")
    except (Refused, KeyError, TypeError, ValueError) as e:
        return False, "no decision: %s" % e


def model_api(f):
    """(allowed, reason) for calling an AI model through an API at its pinned identity"""
    try:
        a = ask({"op": "model_api", **_install_fields(f), "kind_ok": f["kind_ok"] is True,
                 "same_model": f["same_model"] is True, "denied": f["denied"] is not False,
                 "level": max(0, int(f["level"])), "max_level": max(0, int(f["max_level"]))})
        return bool(a["allow"]), a.get("reason")
    except (Refused, KeyError, TypeError, ValueError) as e:
        return False, "no decision: %s" % e


def sysegress(system, listed, loopback, enforce):
    """cut this destination? (the network sentinel's rule for system accounts); no decision cuts in enforce mode"""
    try:
        return bool(ask({"op": "sysegress", "system": bool(system), "listed": bool(listed), "loopback": bool(loopback),
                         "enforce": bool(enforce)})["cut"])
    except (Refused, KeyError, TypeError, ValueError):
        return bool(enforce and system and not listed and not loopback)
