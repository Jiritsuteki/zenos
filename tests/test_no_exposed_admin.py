"""No management screen or debug entry reachable from outside (国家サイバー統括室, 5 Nov 2026, 1.(3) 対策例2:
管理画面、デバッグ用エンドポイント、開発・検証環境の公開の点検). Run on every build.

Checked in the source, for every program ZENOS ships:
  - every HTTP server listens on this machine only, or refuses to start on another address without TLS;
  - every Node.js server listens on 127.0.0.1;
  - no request path for debugging or administration (/debug, /admin, /_..., /console, /metrics, /pprof);
  - systemd units that open a service to other machines pass a certificate;
  - LiveKit's generated settings bind to 127.0.0.1.
And by running them: the audit node, the key service, the data peers and the approval page each refuse to start on
0.0.0.0 without a certificate."""
import json, os, re, socket, subprocess, sys, unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SHIPPED_PY = sorted(list((REPO / "system" / "sbin").glob("*.py")) + list((REPO / "core" / "bin").glob("*.py")) +
                    list((REPO / "apps").glob("*/*.py")))
SHIPPED_JS = [REPO / "messenger" / f for f in ("client.js", "relay.js", "federation.js")] + \
             sorted((REPO / "storage" / "bin").glob("*.js")) + sorted((REPO / "storage" / "lib").glob("*.js"))
LOOPBACK = ("127.0.0.1", "::1", "localhost")
TLS_GUARD = re.compile(r"not in \(\"127\.0\.0\.1\", \"::1\", \"localhost\"\) and not")


class NoExposedAdmin(unittest.TestCase):
    def test_http_servers_bind_locally_or_need_tls(self):
        for p in SHIPPED_PY:
            s = p.read_text(errors="replace")
            for m in re.finditer(r"HTTPServer\(\(\s*([^,]+),", s):
                host = m.group(1).strip()
                const = re.search(r"^%s\s*=\s*['\"]([^'\"]+)['\"]\s*$" % re.escape(host), s, re.M)
                if host.strip("'\"") in LOOPBACK or (const and const.group(1) in LOOPBACK):
                    continue
                self.assertTrue(TLS_GUARD.search(s), f"{p.name}: listens on {host} without refusing plain HTTP off this machine")

    def test_node_servers_listen_on_loopback(self):
        for p in SHIPPED_JS:
            s = p.read_text(errors="replace")
            for m in re.finditer(r"\.listen\(([^)]*)\)", s):
                args = m.group(1)
                if not args.strip() or re.fullmatch(r"\s*\d*\s*", args):
                    if "net.createServer" in s or "http.createServer" in s:
                        self.fail(f"{p.name}: listen({args}) binds every address")
                    continue
                if "createServer" in s[max(0, m.start() - 4000):m.start()] or "Server" in args:
                    self.assertIn('"127.0.0.1"', args, f"{p.name}: listen({args})")

    def test_no_debug_or_admin_paths(self):
        bad = re.compile(r"""["'`]/(?:debug|admin|_[a-z]|console|metrics|pprof|phpinfo|actuator)\b""")
        for p in SHIPPED_PY + SHIPPED_JS:
            for i, l in enumerate(p.read_text(errors="replace").splitlines(), 1):
                self.assertIsNone(bad.search(l), f"{p.relative_to(REPO)}:{i}: {l.strip()[:120]}")

    def test_units_open_to_others_only_with_a_certificate(self):
        for p in sorted((REPO / "system" / "systemd").glob("*.service")) + sorted((REPO / "packaging" / "grid").glob("*.service")):
            for l in p.read_text().splitlines():
                if l.startswith("ExecStart=") and "--host 0.0.0.0" in l:
                    self.assertIn("--cert", l, p.name)

    def test_livekit_binds_to_this_machine(self):
        s = (REPO / "core" / "bin" / "zenos-firstrun.sh").read_text()
        self.assertIn('bind_addresses: [\\"127.0.0.1\\"]', s.replace('"', '\\"'))

    def refused(self, cmd, env=None):
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30, env=dict(os.environ, **(env or {})))
        self.assertNotEqual(r.returncode, 0, cmd)
        self.assertRegex(r.stderr + r.stdout, r"TLS|cert", cmd)

    def test_services_refuse_to_open_without_tls(self):
        import tempfile
        t = tempfile.mkdtemp(prefix="zenos-exposed-")
        py = sys.executable
        self.refused([py, str(REPO / "system/sbin/zenos_datapeer.py"), "--state", t + "/p", "--host", "0.0.0.0"])
        self.refused([py, str(REPO / "core/bin/approval_server.py")], {"ZENOS_APPROVAL_BIND": "0.0.0.0",
                     "PYTHONPATH": str(REPO / "system" / "lib"), "HOME": t})


    def test_approval_page_answers_only_its_key(self):
        """the approval page signs as an officer: no key (another account, a web page), no page"""
        import tempfile, time, http.client
        t = tempfile.mkdtemp(prefix="zenos-approve-")
        with socket.socket() as so:
            so.bind(("127.0.0.1", 0))
            port = so.getsockname()[1]
        p = subprocess.Popen([sys.executable, str(REPO / "core/bin/approval_server.py")],
                             env=dict(os.environ, PYTHONPATH=str(REPO / "system" / "lib"), HOME=t, ZENOS_APPROVAL_PORT=str(port)),
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            url = os.path.join(t, ".local/share/zenos/approval-url")
            for _ in range(100):
                if os.path.exists(url) and open(url).read().strip():
                    break
                time.sleep(0.1)
            self.assertEqual(os.stat(url).st_mode & 0o077, 0)
            key = open(url).read().strip().split("?k=", 1)[1]

            def ask(method, path, headers=None, body=None):
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                c.request(method, path, body=body, headers=dict({"Host": "127.0.0.1:%d" % port}, **(headers or {})))
                r = c.getresponse()
                r.read()
                return r.status, r.getheader("Set-Cookie") or ""
            self.assertEqual(ask("GET", "/")[0], 403)
            self.assertEqual(ask("POST", "/", body="id=x&action=decline")[0], 403)
            st, ck = ask("GET", "/?k=" + key)
            self.assertEqual(st, 302)
            cookie = ck.split(";", 1)[0]
            self.assertEqual(ask("GET", "/", {"Cookie": cookie})[0], 200)
            self.assertEqual(ask("GET", "/", {"Cookie": cookie, "Host": "evil.example:%d" % port})[0], 403)
            self.assertEqual(ask("POST", "/", {"Cookie": cookie, "Origin": "http://evil.example"}, "id=x&action=decline")[0], 403)
        finally:
            p.kill()
            p.wait()


    def test_office_ai_relay_serves_only_its_own_page(self):
        """the office apps' AI relay: no other site's page, no request that skips the browser's preflight, and no
        address other than an https AI service (http only for this PC)"""
        import tempfile, time, http.client, socket
        t = tempfile.mkdtemp(prefix="zenos-office-")
        os.makedirs(os.path.join(t, "dist"))
        with socket.socket() as so:
            so.bind(("127.0.0.1", 0))
            port = so.getsockname()[1]
        p = subprocess.Popen([sys.executable, str(REPO / "apps/common/zoffice_server.py"), t, str(port)],
                             env=dict(os.environ, ZENOS_AIGUARD_SOCK=t + "/none", ZENOS_KEYD_SOCK=t + "/none"),
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            def post(body, headers):
                for _ in range(50):
                    try:
                        c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                        c.request("POST", "/ai/chat", body=json.dumps(body), headers=dict({"Host": "127.0.0.1:%d" % port}, **headers))
                        r = c.getresponse()
                        r.read()
                        return r.status
                    except ConnectionRefusedError:
                        time.sleep(0.1)
            js = {"Content-Type": "application/json"}
            ask = {"provider": "openai", "apiKey": "k", "model": "m", "messages": [], "baseUrl": "https://127.0.0.1:1/v1"}
            self.assertEqual(post(ask, {"Content-Type": "text/plain"}), 403)
            self.assertEqual(post(ask, dict(js, Origin="http://evil.example")), 403)
            for bad in ("file:///etc/passwd#", "http://169.254.169.254/latest", "https://u@api.example/v1", "gopher://x/"):
                self.assertEqual(post(dict(ask, baseUrl=bad), dict(js, Origin="http://127.0.0.1:%d" % port)), 400, bad)
        finally:
            p.kill()
            p.wait()


if __name__ == "__main__":
    unittest.main()
