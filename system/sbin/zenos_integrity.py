#!/usr/bin/env python3
"""ZENOS integrity check (root, hourly): what is on the PC against what was released, and the ways a genuine program
can be made to load something else.

NetamLoader (Kaspersky, 29 Oct 2026) ran a genuine, signed program and fed it one crafted configuration file and one
data file from the update folder. A signature on the program does not see that. This check looks at:
  - the files of every package whose release record the PC accepted (zenos_pkgcheck.py keeps it), byte for byte
    against the record, configuration files included; and every other package against dpkg's own sums;
  - the paths that make a genuine program load something else: /etc/ld.so.preload, LD_PRELOAD and friends in
    environment files and systemd settings, Python .pth and sitecustomize files, systemd drop-ins, apt hooks,
    ld.so.conf.d entries, NODE_OPTIONS — any of these that no installed package owns is reported;
  - the AI models kept on the PC (/var/lib/zenos/models, zmodel.py): every file against the model's release record,
    and the record's officers' signatures. A file added, changed or missing is an alert.
Findings go into the PC's ledger (the audit nodes alert the officers on "integrity-alert") and
/var/lib/zenos/integrity.json (for the System Monitor).

  zenos_integrity.py [--no-dpkg|--dpkg]   check once, print the findings (dpkg's full check: daily by default)
"""
import glob, hashlib, json, os, re, subprocess, sys, time
from pathlib import Path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "lib", "zenos"))
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "lib"))
try:
    import zledger                                              # noqa: E402
except Exception:
    zledger = None

ROOT = Path(os.environ.get("ZENOS_INTEGRITY_ROOT", "/"))
MANIFESTS = Path(os.environ.get("ZENOS_MANIFESTS", "/var/lib/zenos/manifests"))
STATE = Path(os.environ.get("ZENOS_INTEGRITY_STATE", "/var/lib/zenos/integrity.json"))
LEDGER = os.environ.get("ZENOS_INTEGRITY_LEDGER", "/var/log/zenos/access-ledger.jsonl")
DPKG_INFO = os.environ.get("ZENOS_DPKG_INFO", "/var/lib/dpkg/info")
LOADER_VARS = ("LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "NODE_OPTIONS", "NODE_PATH", "PYTHONPATH",
               "PYTHONSTARTUP", "PYTHONHOME", "PERL5OPT", "PERL5LIB", "RUBYOPT", "BASH_ENV", "ENV")
VAR_RE = re.compile(r"(?<![A-Za-z0-9_])(" + "|".join(LOADER_VARS) + r")\s*=")
APT_HOOK_RE = re.compile(r"(Pre-Invoke|Post-Invoke|Pre-Install-Pkgs|Post-Invoke-Success|Update::Pre-Invoke|"
                         r"Update::Post-Invoke|APT::Update::Post-Invoke-Success)", re.I)


def p(path):
    return ROOT / str(path).lstrip("/")


def owned_files():
    """every path an installed package owns (dpkg's lists)"""
    out = set()
    for lst in glob.glob(os.path.join(str(p(DPKG_INFO)), "*.list")):
        try:
            with open(lst, encoding="utf-8", errors="replace") as f:
                out.update(l.rstrip("\n") for l in f if l.strip())
        except OSError:
            pass
    return out


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def installed_versions():
    """{(name, arch): version} for installed packages (dpkg's status)"""
    out = {}
    try:
        text = p("/var/lib/dpkg/status").read_text(errors="replace")
    except OSError:
        return out
    for block in text.split("\n\n"):
        f = dict(l.split(": ", 1) for l in block.splitlines() if ": " in l and not l.startswith(" "))
        if "install ok installed" in f.get("Status", ""):
            out[(f.get("Package"), f.get("Architecture"))] = f.get("Version")
    return out


def diverted():
    out = set()
    try:
        lines = p("/var/lib/dpkg/diversions").read_text(errors="replace").splitlines()
        out.update(lines[0::3])
    except OSError:
        pass
    return out


def check_manifests(owned):
    """installed files against the release records this PC accepted (only for the version now installed)"""
    found = []
    inst, div = installed_versions(), diverted()
    for mf in sorted(MANIFESTS.glob("*.json")) if MANIFESTS.is_dir() else []:
        try:
            m = json.loads(mf.read_text())["manifest"]
        except (OSError, ValueError, KeyError):
            found.append({"level": "alert", "kind": "manifest-unreadable", "path": str(mf)})
            continue
        if inst and inst.get((m.get("name"), m.get("arch"))) != m.get("version"):
            continue                   # removed, or another version installed: that record no longer applies
        conf = set(m.get("conffiles") or [])
        for path, want in (m.get("files") or {}).items():
            if path in div or (owned and path not in owned):
                continue               # diverted, or left out by dpkg's path-exclude
            f = p(path)
            try:
                got = sha256(f)
            except FileNotFoundError:
                found.append({"level": "review" if path in conf else "alert", "kind": "missing", "package": m["name"],
                              "path": path})
                continue
            except OSError:
                continue
            if got != want:
                found.append({"level": "review" if path in conf else "alert",
                              "kind": "changed-conffile" if path in conf else "changed", "package": m["name"],
                              "path": path})
    return found


def check_dpkg():
    """every package against dpkg's own sums (weaker than the ledger: the sums live on the PC)"""
    if ROOT != Path("/"):
        return []
    found = []
    r = subprocess.run(["dpkg", "--verify"], capture_output=True, text=True, timeout=1800)
    for line in r.stdout.splitlines():
        m = re.match(r"^(\S{9})\s+(c?)\s*(/.*)$", line)
        if m and m.group(1)[2] == "5":
            found.append({"level": "review" if m.group(2) == "c" else "alert",
                          "kind": "changed-conffile" if m.group(2) == "c" else "changed", "path": m.group(3),
                          "by": "dpkg"})
    return found


def _files(patterns):
    for pat in patterns:
        for f in glob.glob(str(p(pat)), recursive=True):
            if os.path.isfile(f):
                yield f


def rel(f):
    return "/" + os.path.relpath(f, str(ROOT)) if ROOT != Path("/") else f


def check_loaders(owned):
    found = []
    pre = p("/etc/ld.so.preload")
    if pre.exists() and pre.read_text(errors="replace").strip():
        found.append({"level": "alert", "kind": "ld.so.preload", "path": "/etc/ld.so.preload",
                      "detail": pre.read_text(errors="replace").strip()[:200]})
    env_files = ["/etc/environment", "/etc/environment.d/*", "/etc/profile", "/etc/profile.d/*", "/etc/bash.bashrc",
                 "/etc/security/pam_env.conf", "/etc/systemd/system.conf", "/etc/systemd/system.conf.d/*",
                 "/etc/systemd/user.conf", "/etc/systemd/user.conf.d/*", "/etc/systemd/system/**/*.conf",
                 "/etc/systemd/system/*.service", "/run/systemd/system/**/*.conf", "/etc/sudoers", "/etc/sudoers.d/*"]
    for f in _files(env_files):
        try:
            text = Path(f).read_text(errors="replace")
        except OSError:
            continue
        for ln in text.splitlines():
            s = ln.strip()
            if s.startswith("#"):
                continue
            m = VAR_RE.search(s)
            if m and (rel(f) not in owned or m.group(1) in ("LD_PRELOAD", "LD_AUDIT")):
                found.append({"level": "alert", "kind": "loader-variable", "path": rel(f), "detail": s[:200]})
    for f in _files(["/etc/systemd/system/*.d/*.conf", "/run/systemd/system/*.d/*.conf", "/etc/systemd/system/*.service"]):
        if os.path.islink(f):
            continue                   # enabling or masking a unit makes links, not new settings
        if rel(f) not in owned and not re.search(r"\.wants/|\.requires/", f):
            found.append({"level": "review", "kind": "systemd-local", "path": rel(f)})
    for f in _files(["/etc/apt/apt.conf.d/*"]):
        if rel(f) in owned:
            continue
        try:
            if APT_HOOK_RE.search(Path(f).read_text(errors="replace")):
                found.append({"level": "alert", "kind": "apt-hook", "path": rel(f)})
        except OSError:
            pass
    for f in _files(["/etc/ld.so.conf.d/*"]):
        if os.path.islink(f) and os.readlink(f).startswith("/etc/alternatives/"):
            continue                   # update-alternatives (fakeroot and others)
        if rel(f) not in owned:
            found.append({"level": "alert", "kind": "ld.so.conf.d", "path": rel(f)})
    # Python reads .pth files only at the top of its site directories, and sitecustomize / usercustomize from there
    site = ["/usr/lib/python3*/dist-packages", "/usr/lib/python3*/site-packages", "/usr/lib/python3/dist-packages",
            "/usr/local/lib/python3*/dist-packages", "/usr/local/lib/python3*/site-packages", "/usr/lib/python3.*"]
    for f in _files([d + "/" + n for d in site for n in ("*.pth", "sitecustomize.py", "usercustomize.py")]):
        if rel(f) not in owned:
            local = rel(f).startswith("/usr/local/")     # pip's own installs live there: worth a look, not an alarm
            found.append({"level": "review" if local else "alert", "kind": "python-startup", "path": rel(f)})
    for f in _files(["/etc/npmrc", "/usr/etc/npmrc", "/usr/lib/node_modules/npm/npmrc"]):
        if rel(f) not in owned:
            found.append({"level": "review", "kind": "npmrc", "path": rel(f)})
    return found


def check_models():
    """every AI model folder against its release record (no network needed: the record carries the officers'
    signatures, checked with the keys enrolled on this PC)"""
    try:
        import zmodel
    except Exception:
        return []
    out = []
    for folder in zmodel.models():
        if folder.name.startswith("."):
            continue
        for f in zmodel.offline_check(folder):
            out.append({"level": "alert", "kind": f["kind"], "path": f["path"], "detail": f["detail"]})
    return out


def run(with_dpkg=None):
    """with_dpkg None: dpkg's full check once a day (it reads every installed file), the rest every run"""
    owned = owned_files()
    try:
        last = json.loads(STATE.read_text()).get("dpkg_t", 0)
    except (OSError, ValueError):
        last = 0
    if with_dpkg is None:
        with_dpkg = time.time() - last > 86400
    found = check_manifests(owned) + check_loaders(owned) + check_models() + (check_dpkg() if with_dpkg else [])
    alerts = [f for f in found if f["level"] == "alert"]
    st = {"t": int(time.time()), "alerts": len(alerts), "review": len(found) - len(alerts), "findings": found[:500],
          "dpkg_t": int(time.time()) if with_dpkg else last}
    try:
        STATE.parent.mkdir(parents=True, exist_ok=True)
        tmp = STATE.with_name(STATE.name + ".tmp")
        tmp.write_text(json.dumps(st, ensure_ascii=False))
        os.replace(tmp, STATE)
    except OSError:
        pass
    if zledger is not None:
        try:
            zledger.append(LEDGER, "integrity-alert" if alerts else "integrity-ok", "root", "integrity",
                           alerts=len(alerts), review=st["review"],
                           first=[{k: f.get(k) for k in ("kind", "path", "package")} for f in alerts[:10]])
        except Exception:
            pass
    return st


def main():
    st = run(False if "--no-dpkg" in sys.argv else True if "--dpkg" in sys.argv else None)
    for f in st["findings"]:
        print(f"{f['level']:6} {f['kind']:18} {f.get('path')}  {f.get('detail', '')}")
    print(f"{st['alerts']} alert(s), {st['review']} to review")
    return 1 if st["alerts"] else 0


if __name__ == "__main__":
    sys.exit(main())
