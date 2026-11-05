#!/usr/bin/env python3
"""ZENOS approval window (PoC). Opens on the approver's phone or PC browser.
Shows who / which level / why. Never shows the file content.
PoC: the signature is made with the officer's key held by this service.
Production: the officer touches their FIDO2 key (NFC) and the phone only relays the signature."""
import hmac, html, json, os, secrets, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import zenos

LV = {1: "#E5E7EB", 2: "#38BDF8", 3: "#22C55E", 4: "#EF4444", 5: "#A1A1AA"}
CSS = """
*{box-sizing:border-box}body{margin:0;min-height:100vh;font-family:Inter,'Noto Sans CJK JP',system-ui,sans-serif;color:#fff;
background:radial-gradient(900px 600px at 10% -10%,rgba(59,130,246,.55),transparent 70%),radial-gradient(900px 700px at 100% 100%,rgba(139,92,246,.45),transparent 70%),#0B1430}
main{max-width:520px;margin:0 auto;padding:28px 16px 60px}
h1{font-size:20px;margin:0 0 4px}.sub{color:#A5B4D4;font-size:13px;margin:0 0 22px}
.card{background:rgba(20,27,46,.72);border:1px solid rgba(255,255,255,.14);border-radius:16px;padding:18px;margin-bottom:16px;
box-shadow:0 18px 44px rgba(0,0,0,.45);backdrop-filter:blur(24px)}
.tag{display:inline-block;font-size:11px;font-weight:600;padding:3px 8px;border-radius:5px;margin-bottom:10px}
.who{font-size:16px;font-weight:600;margin:0 0 8px}.meta{font-size:13px;color:#CBD5E1;line-height:1.6;margin:0 0 12px}
.prog{font-size:12px;color:#94A3B8;margin:0 0 12px}
label{display:block;font-size:12px;color:#94A3B8;margin:10px 0 6px}
select,input{width:100%;font:inherit;font-size:15px;color:#fff;background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.18);border-radius:10px;padding:10px 12px}
input.code{font-size:22px;font-weight:700;letter-spacing:.3em;text-align:center}
.row{display:flex;gap:10px;margin-top:14px}button{flex:1;font:inherit;font-size:14px;font-weight:600;border:0;border-radius:10px;padding:12px;cursor:pointer}
.ok{background:linear-gradient(#3B82F6,#1D4ED8);color:#fff;box-shadow:inset 0 1px 0 rgba(255,255,255,.35)}.no{background:rgba(255,255,255,.1);color:#E5E7EB}
.note{font-size:11px;color:#94A3B8;margin:12px 0 0}.msg{border-radius:12px;padding:12px 14px;margin-bottom:16px;font-size:14px}
.good{background:rgba(34,197,94,.16);border:1px solid rgba(34,197,94,.4)}.bad{background:rgba(239,68,68,.16);border:1px solid rgba(239,68,68,.4)}
.done{opacity:.7}.empty{color:#94A3B8;font-size:14px}
"""


def load_requests():
    zenos.REQ.mkdir(parents=True, exist_ok=True)
    rs = []
    for d in [zenos.REQ] + ([zenos.RELEASE_REQ] if zenos.RELEASE_REQ else []):
        for p in d.glob("*.json"):
            try:
                rs.append(json.loads(p.read_text()))
            except Exception:
                pass
    return sorted(rs, key=lambda r: r["created"], reverse=True)


def num(x, lo=0, hi=10 ** 6):
    """a number shown in the page: always an integer in range, never text from the request file"""
    try:
        return max(lo, min(hi, int(x)))
    except (TypeError, ValueError):
        return lo


def card(r):
    e = html.escape
    r = dict(r, level=num(r.get("level"), 1, 5), required=num(r.get("required"), 1, 9))
    c = LV[r["level"]]
    who = ", ".join(str(zenos.ROSTER.get(a.get("approver"), a.get("approver"))).split(" · ")[0] for a in r["approvals"]) or "none yet"
    kind = r.get("kind", "access")
    sent = e(str(r["created"])[:16].replace("T", " "))
    if kind == "release":
        sc = r["scope"]
        tag, c = f"Emergency release · L{r['level']}", "#F97316"
        who_line = f"ZENOS stopped {e(str(r['requester']))}'s PC"
        meta = (f"Anomaly: {e(str(r['reason']))}<br>Files: {e(', '.join(map(str, sc.get('files', [])[:5])))}<br>"
                f"Approving unlocks the PC. The stopped operation is cancelled and quarantined files stay in quarantine.<br>Stopped: {sent}")
        done_txt = "Approved · stop released"
    elif kind == "plan":
        sc = r["scope"]
        tag, c = f"Pre-filed operation · L{r['level']}", "#38BDF8"
        who_line = f"{e(str(r['requester']))} files an operation in advance"
        meta = (f"Operation: {e(str(zenos.PLAN_RULES.get(sc.get('rule'), sc.get('rule'))))} · up to {num(sc.get('max_files'))} file(s) · "
                f"{num(sc.get('minutes'))} min<br>Reason: {e(str(r['reason']))}<br>Sent: {sent}")
        done_txt = "Approved · ZENOS will not stop this operation"
    else:
        tag = f"Approval request · L{r['level']}"
        who_line = f"{e(str(r['requester']))} requests access"
        meta = (f"File: {e(str(r['name']))} (L{r['level']} · {e(str(r['label']))})<br>Reason: {e(str(r['reason']))}<br>Sent: {sent}")
        done_txt = "Approved · access granted"
    head = (f'<span class="tag" style="background:{c}33;color:{c}">{tag}</span>'
            f'<p class="who">{who_line}</p><p class="meta">{meta}</p>'
            f'<p class="prog">Approvals: {len(r["approvals"])} of {r["required"]} · {e(who)}</p>')
    if r["status"] != "pending":
        state = done_txt if r["status"] == "approved" else f"Declined by {e(zenos.ROSTER.get(r.get('declined_by', ''), ''))}"
        return f'<div class="card done">{head}<p class="prog">{state}</p></div>'
    opts = "".join(f'<option value="{k}">{e(v)}</option>' for k, v in zenos.ROSTER.items()
                   if not any(a["approver"] == k for a in r["approvals"]))
    return (f'<div class="card">{head}<form method="post">'
            f'<input type="hidden" name="id" value="{e(str(r["id"]))}">'
            f'<label>Signing as (in production: the officer\'s own key)</label><select name="approver">{opts}</select>'
            f'<label>Match code shown on the requester\'s screen</label>'
            f'<input class="code" name="code" inputmode="numeric" maxlength="4" placeholder="····" autocomplete="off">'
            f'<div class="row"><button class="ok" name="action" value="approve">Approve with key</button>'
            f'<button class="no" name="action" value="decline">Decline</button></div>'
            f'<p class="note">This decision is recorded in the audit log. The file content is never shown here.</p>'
            f'</form></div>')


def page(msg=None, good=True):
    rs = load_requests()
    pend = [r for r in rs if r["status"] == "pending"]
    done = [r for r in rs if r["status"] != "pending"][:5]
    m = f'<div class="msg {"good" if good else "bad"}">{html.escape(msg)}</div>' if msg else ""
    body = "".join(card(r) for r in pend) or '<p class="empty">No pending requests.</p>'
    hist = "".join(card(r) for r in done)
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1"><title>ZENOS Approvals</title>'
            f'<style>{CSS}</style><script>setInterval(function(){{var a=document.activeElement;'
            f'if(!a||(a.tagName!=="INPUT"&&a.tagName!=="SELECT"))location.href="/"}},8000)</script></head><body><main>'
            f'<h1>ZENOS Approvals</h1><p class="sub">Who, which level, and why. Never the content.</p>{m}{body}'
            f'{"<h1 style=margin-top:28px;font-size:15px>Recent</h1>" + hist if hist else ""}</main></body></html>')


# The page signs as an officer, so it answers only who shows its key: written at start to a file only this account
# can read (approval-url), turned into a cookie by the first visit. Another account on the PC, or a web page in a
# browser (another site's Origin, or a host name other than this one), gets nothing.
KEY = secrets.token_urlsafe(32)
PORT = int(os.environ.get("ZENOS_APPROVAL_PORT", "8090"))


class H(BaseHTTPRequestHandler):
    def send(self, text, code=200, extra=()):
        b = text.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b)

    def allowed(self):
        host = self.headers.get("Host", "")
        own = {f"{h}:{PORT}" for h in ("127.0.0.1", "localhost", "[::1]", os.environ.get("ZENOS_APPROVAL_HOST", "127.0.0.1"))}
        origin = self.headers.get("Origin")
        if host not in own or (origin and origin.split("://", 1)[-1] not in own):
            return False
        ck = dict(x.strip().split("=", 1) for x in self.headers.get("Cookie", "").split(";") if "=" in x)
        return hmac.compare_digest(ck.get("zak", ""), KEY)

    def do_GET(self):
        q = parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
        if hmac.compare_digest(q.get("k", [""])[0], KEY) and self.headers.get("Host", "").endswith(f":{PORT}"):
            return self.send("", 302, [("Set-Cookie", f"zak={KEY}; Path=/; HttpOnly; SameSite=Strict"), ("Location", "/")])
        if not self.allowed():
            return self.send("Open the approval page from the link in approval-url on this PC.", 403)
        self.send(page())

    def do_POST(self):
        if not self.allowed():
            return self.send("Open the approval page from the link in approval-url on this PC.", 403)
        n = min(int(self.headers.get("Content-Length", 0) or 0), 65536)
        f = {k: v[0] for k, v in parse_qs(self.rfile.read(n).decode()).items()}
        rid = os.path.basename(f.get("id", ""))
        if not zenos.request_path(rid).exists():
            return self.send(page("Unknown request.", False))
        if f.get("action") == "decline":
            ok, msg = zenos.decline(rid, f.get("approver", ""))
        else:
            ok, msg = zenos.approve(rid, f.get("approver", ""), f.get("code", ""))
        self.send(page(msg, ok))

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    for k in zenos.ROSTER:
        zenos.approver_key(k)
    # Default: this machine only. Opening it to a network (e.g. a phone on the LAN)
    # must be an explicit decision: ZENOS_APPROVAL_BIND=0.0.0.0. The OS firewall
    # (zenos-firewall) still drops inbound connections unless that is also changed.
    bind = os.environ.get("ZENOS_APPROVAL_BIND", "127.0.0.1")
    cert, key = os.environ.get("ZENOS_APPROVAL_CERT"), os.environ.get("ZENOS_APPROVAL_KEY")
    if bind not in ("127.0.0.1", "::1", "localhost") and not (cert and key):
        # an approval page reachable from a network is an administration screen: never in plain HTTP
        raise SystemExit("ZENOS_APPROVAL_BIND other than this machine needs TLS (ZENOS_APPROVAL_CERT, ZENOS_APPROVAL_KEY)")
    srv = ThreadingHTTPServer((bind, PORT), H)
    zenos.Z.mkdir(parents=True, exist_ok=True)
    url = zenos.Z / "approval-url"
    fd = os.open(url, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    os.fchmod(fd, 0o600)
    os.write(fd, f"{'https' if cert and key else 'http'}://127.0.0.1:{PORT}/?k={KEY}\n".encode())
    os.close(fd)
    if cert and key:
        import ssl
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cert, key)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    srv.serve_forever()
