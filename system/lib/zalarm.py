#!/usr/bin/env python3
"""ZENOS alerting (PoC).

severity "red": a full-screen flashing siren that rings until a person ACKNOWLEDGEs it (zenos_siren), PLUS a
fan-out to every pre-registered senior's device (dispatch). Red is meant to be impossible to ignore and to
reach the chain of command, not just the one machine.
severity "low": on-screen notice only.
"""
import json, os, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import zconf
Z = zconf.data()
STATE = os.path.join(Z, "redalert.json")
PID = os.path.join(Z, "redalert.pid")
RECIPIENTS = os.path.join(Z, "alert-recipients.json")
INBOX = os.path.join(Z, "alerts-outbox")          # per-recipient fan-out (reaches their device via the grid)
LEDGER = os.path.join(Z, "ledger.jsonl")
SIREN = os.path.join(zconf.SBIN, "zenos_siren.py")


def _alive(pid):
    try:
        os.kill(pid, 0); return True
    except Exception:
        return False


def _ensure_siren(text):
    os.makedirs(Z, exist_ok=True)
    with open(STATE, "w") as f:
        json.dump({"text": text, "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z")}, f)
    zconf.give_to_user(STATE)
    try:
        if os.path.exists(PID) and _alive(int(open(PID).read().strip())):
            return                                   # already ringing; message refreshed via STATE
    except Exception:
        pass
    env = zconf.pulse_env()
    env.setdefault("DISPLAY", ":0" if not os.path.exists("/tmp/.X11-unix/X1") else ":1")
    if os.geteuid() == 0:     # a root service rings the siren on the desktop user's screen
        cmd = ["runuser", "-u", zconf.user(), "--", "env", "DISPLAY=" + env["DISPLAY"],
               "PULSE_SERVER=" + env.get("PULSE_SERVER", ""), "HOME=" + zconf.home(), "python3", "-I", SIREN]
    else:
        cmd = ["python3", "-I", SIREN]
    try:
        subprocess.Popen(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def _recipients():
    try:
        return json.load(open(RECIPIENTS))
    except Exception:
        return []


def _msg_key():
    """The messenger's local key (it answers only callers that show it). The file sits in the desk user's folder, so it
    is opened without following a link and used only if that user owns it: a planted link to a root file gives nothing."""
    import stat
    try:
        fd = os.open(os.path.join(Z, "msg", "store", "zenos", "local.key"), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return ""
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != _desk_uid() or st.st_size > 128:
            return ""
        k = os.read(fd, 128).decode("ascii", "replace").strip()
        return k if k and all(c.isalnum() or c in "-_" for c in k) else ""
    finally:
        os.close(fd)


def _desk_uid():
    import pwd
    try:
        return pwd.getpwnam(zconf.user()).pw_uid
    except Exception:
        return os.getuid()


def dispatch(title, text, reasons):
    """Fan the alert out to every pre-registered senior's device (PoC: per-recipient outbox + ledger)."""
    sent = []
    recs = _recipients()
    for r in recs:
        try:
            d = os.path.join(INBOX, r["id"]); os.makedirs(d, exist_ok=True)
            fn = os.path.join(d, time.strftime("%Y%m%d-%H%M%S") + ".json")
            json.dump({"to": r, "title": title, "text": text, "reasons": reasons,
                       "severity": "red", "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z")},
                      open(fn, "w"), ensure_ascii=False)
            sent.append(r["id"])
        except Exception:
            pass
    key = _msg_key()
    try:
        import urllib.request as _u
        req = _u.Request("http://127.0.0.1:8096/api/channel-send",
                         data=__import__("json").dumps({"ch": "alerts", "text": "RED ALERT: " + text, "level": 4}).encode(),
                         headers={"Content-Type": "application/json", "X-Zenos-Local": key})
        _u.urlopen(req, timeout=4)              # post into #alerts -> fans out to seniors' PWAs
    except Exception:
        pass
    try:                                        # Web Push to the owner's linked phone(s), even when the app is closed
        import urllib.request as _u
        req = _u.Request("http://127.0.0.1:8096/api/push/alert",
                         data=__import__("json").dumps({"title": "ZENOS RED ALERT: " + str(title)[:60], "body": str(text)[:300]}).encode(),
                         headers={"Content-Type": "application/json", "X-Zenos-Local": key})
        r = __import__("json").loads(_u.urlopen(req, timeout=8).read() or b"{}")
        if r.get("sent"):
            sent.append("owner-phone-push")
    except Exception:
        pass
    try:
        import zledger
        dev = __import__("hashlib").sha256(b"node-A").hexdigest()[:16]
        zledger.append(LEDGER, "red-dispatch", "alarm", dev, recipients=sent, reasons=reasons, text=text)
        zconf.give_to_user(LEDGER)
        zconf.give_to_user(LEDGER + ".lock")
    except Exception:
        pass
    return sent


def _notify(title, text, urgent):
    for disp in (os.environ.get("DISPLAY"), ":1", ":0"):
        if not disp:
            continue
        try:
            subprocess.run(["notify-send"] + (["-u", "critical"] if urgent else ["-u", "normal"]) +
                           [title, text], env={**os.environ, "DISPLAY": disp}, timeout=5,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            break
        except Exception:
            continue


def ack():
    for f in (STATE, PID):
        try:
            os.remove(f)
        except Exception:
            pass


def raise_alert(severity, title, text, reasons=None):
    reasons = reasons or []
    _notify(title, text, urgent=(severity == "red"))
    if severity == "red":
        _ensure_siren(text)
        dispatch(title, text, reasons)
    return severity


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "ack":
        ack(); print("acknowledged")
    else:
        raise_alert("red", "ZENOS RED ALERT", sys.argv[1] if len(sys.argv) > 1 else "test", [])
