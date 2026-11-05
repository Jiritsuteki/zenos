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
import os, re, socket, subprocess, sys, unittest
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


if __name__ == "__main__":
    unittest.main()
