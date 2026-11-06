#!/usr/bin/env python3
"""ZENOS: apt's check before installing (DPkg::Pre-Install-Pkgs). apt passes the package files on stdin; each
one goes in only if the release ledger says so (zsupply.py, decided by formal/ZenosFormal/Supply.lean). Every
check, allowed or not, is written to the PC's ledger, which the audit shipping sends to the audit nodes: which PC
installed what, and when. Exit status non-zero stops apt before anything is installed.

/etc/zenos/supply.json "mode": "enforce" (refuse), "warn" (record and let in), "off" (record only).
  zenos_pkgcheck.py FILE.deb...    check files by hand (prints the facts and the decision)
"""
import json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "lib", "zenos"))
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "lib"))
import zdecide, zsupply                                         # noqa: E402
try:
    import zledger                                              # noqa: E402
except Exception:
    zledger = None

LEDGER = os.environ.get("ZENOS_PKGCHECK_LEDGER", "/var/log/zenos/access-ledger.jsonl")


def record(event, **kw):
    if zledger is None:
        return
    try:
        zledger.append(LEDGER, event, "root", "pkgcheck", **kw)
    except Exception:
        pass


MANIFESTS = os.environ.get("ZENOS_MANIFESTS", "/var/lib/zenos/manifests")


def keep(f, name):
    """the accepted release record, for the hourly integrity check (zenos_integrity.py)"""
    rec = f.get("_record")
    if not rec:
        return
    try:
        os.makedirs(MANIFESTS, exist_ok=True)
        tmp = os.path.join(MANIFESTS, f".{name}.json.tmp")
        with open(tmp, "w") as fh:
            json.dump(rec, fh)
        arch = (rec.get("manifest") or {}).get("arch", "all")
        os.replace(tmp, os.path.join(MANIFESTS, f"{name}_{arch}.json"))
    except OSError:
        pass


CACHE = os.environ.get("ZENOS_PKGCHECK_CACHE", "/var/lib/zenos/pkgcheck-allowed.json")
CACHE_TTL = 6 * 3600


def remember(sha):
    """allowed files, by SHA-256, for the dpkg wrapper (zenos-dpkg), which checks the copy dpkg will really read"""
    try:
        with open(CACHE) as f:
            c = json.load(f)
    except (OSError, ValueError):
        c = {}
    now = __import__("time").time()
    c = {k: v for k, v in c.items() if now - v < CACHE_TTL}
    c[sha] = now
    tmp = CACHE + ".tmp"
    try:
        os.makedirs(os.path.dirname(CACHE), exist_ok=True)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(c, f)
        os.replace(tmp, CACHE)
    except OSError:
        pass


def allowed_recently(sha):
    try:
        with open(CACHE) as f:
            t = json.load(f).get(sha)
    except (OSError, ValueError):
        return False
    return t is not None and __import__("time").time() - t < CACHE_TTL


def check(debs, c=None, get=zsupply.fetch, out=sys.stderr):
    c = c or zsupply.conf()
    mode = c.get("mode", "off")
    keys = zsupply.officers()
    nodes = zsupply.audit_nodes()
    refused = []
    for deb in debs:
        try:
            name, version, _ = zsupply.deb_fields(deb)
            sha = zsupply.sha256_file(deb)
        except Exception as e:
            name, version, sha = os.path.basename(deb), "?", "?"
            if mode != "enforce":
                record("pkg-unchecked", file=os.path.basename(deb), reason=str(e)[:80])
                continue
            refused.append((deb, "unreadable"))
            record("pkg-refused", file=os.path.basename(deb), reason="unreadable", mode=mode)
            continue
        if mode == "off":
            record("pkg-unchecked", name=name, version=version, sha256=sha)
            continue
        if c.get("broken"):
            ok, why = False, "the supply configuration cannot be read"
        else:
            try:
                ok, why, f = zsupply.decide(deb, nodes, keys, c.get("required", 2), c.get("ring", 1), get=get)
            except Exception as e:                         # a failure of the check itself: refused when enforcing,
                ok, why, f = False, f"check failed: {type(e).__name__}", {}    # recorded otherwise, never a crash
        if ok:
            keep(f, name)
            remember(sha)
        record("pkg-allowed" if ok else ("pkg-refused" if mode == "enforce" else "pkg-would-refuse"),
               name=name, version=version, sha256=sha, reason=why, mode=mode)
        if not ok:
            print(f"ZENOS: {name} {version} is not in the release ledger as required ({why}).", file=out)
            if mode == "enforce":
                refused.append((deb, why))
    if refused:
        print(f"ZENOS: {len(refused)} package(s) refused; nothing was installed.", file=out)
        return 1
    return 0


def main():
    args = sys.argv[1:]
    if args:
        c = zsupply.conf()
        for deb in args:
            ok, why, f = zsupply.decide(deb, zsupply.audit_nodes(), zsupply.officers(), c.get("required", 2), c.get("ring", 1))
            f.pop("_record", None)
            print(json.dumps({**f, "decision": [ok, why]}, indent=1))
        return 0
    # apt's Pre-Install-Pkgs, version 1: one package file per line (a line may also be "**CONFIGURE**" or "**REMOVE**")
    debs = [l.strip() for l in sys.stdin if l.strip().endswith(".deb")]
    return check(debs)


if __name__ == "__main__":
    sys.exit(main())
