#!/usr/bin/env python3
"""ZENOS: vulnerability information from outside, matched against this PC's parts (root; zenos-vulnwatch.timer).

  zenos_vulnwatch.py run                 fetch the enabled sources (/etc/zenos/vuln.json), match, decide, record
  zenos_vulnwatch.py show                the last result: affected parts first (KEV, then score, then reach)
  zenos_vulnwatch.py mitigations         mitigations offered for affected parts, and their signatures
  zenos_vulnwatch.py apply ID            apply a mitigation, only if zenos-decide "vuln" allows it: the part is
                                         affected and enough release officers signed the mitigation

What it writes:
  /run/zenos/vuln.json             counts and the affected parts, for the System Monitor (world-readable, no secrets)
  /var/lib/zenos/vuln-state.json   the same, kept across restarts; the audit shipping sends the counts with the
                                   PC's signed status
  the ledger                       "vuln-affected" when a part becomes affected, "vuln-fixed" and
                                   "vuln-mitigated" when that changes, "mitigation-applied", "vuln-source-error"

A mitigation (switching a kernel setting off, keeping a module from loading) is a record in
/etc/zenos/mitigations/ that release officers sign as they sign a release (zenos_release.py sign). It is never
applied on the word of a source, of an AI, or of a single person: `apply` refuses it unless the decision allows.
"""
import json, os, sys, time
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "lib", "zenos"))
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "lib"))
import zvuln, zsupply                                             # noqa: E402
try:
    import zledger                                                # noqa: E402
except Exception:
    zledger = None

RUN = Path(os.environ.get("ZENOS_VULN_RUN", "/run/zenos/vuln.json"))
STATE = Path(os.environ.get("ZENOS_VULN_STATE", "/var/lib/zenos/vuln-state.json"))
MITIGATIONS = Path(os.environ.get("ZENOS_MITIGATIONS", "/etc/zenos/mitigations"))
APPLIED = Path(os.environ.get("ZENOS_MITIGATIONS_APPLIED", "/var/lib/zenos/mitigations-applied.json"))
LEDGER = os.environ.get("ZENOS_VULN_LEDGER", "/var/log/zenos/access-ledger.jsonl")
SYSCTL_DIR = Path(os.environ.get("ZENOS_SYSCTL_DIR", "/etc/sysctl.d"))
MODPROBE_DIR = Path(os.environ.get("ZENOS_MODPROBE_DIR", "/etc/modprobe.d"))
KIND = "zenos-mitigation"


def record(event, **kw):
    if zledger is not None:
        try:
            zledger.append(LEDGER, event, "root", "zenos-vulnwatch", **kw)
        except Exception:
            pass


def _write(p, obj, mode=0o644):
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=1))
    os.chmod(tmp, mode)
    os.replace(tmp, p)


# ---------------------------------------------------------------- mitigations
def mitigation_records(d=None):
    out = {}
    d = Path(d or MITIGATIONS)
    for p in sorted(d.glob("*.json")) if d.is_dir() else []:
        try:
            rec = json.loads(p.read_text())
            m = rec["manifest"]
            if m.get("kind") == KIND and zvuln.NAME.match(str(m.get("id", ""))):
                out[m["id"]] = rec
        except (OSError, ValueError, KeyError, TypeError):
            continue
    return out


def applied():
    try:
        return json.loads(APPLIED.read_text())
    except (OSError, ValueError):
        return {}


def mitigated_cves():
    out = {}
    recs = mitigation_records()
    for mid in applied():
        for c in ((recs.get(mid) or {}).get("manifest") or {}).get("cves", []):
            out[c] = mid
    return out


def offered_signatures(keys=None):
    """{cve: the most valid officers' signatures any mitigation offered for it carries}"""
    keys = zsupply.officers() if keys is None else keys
    out = {}
    for rec in mitigation_records().values():
        n = len(zsupply.valid_signers(rec, keys))
        for c in rec["manifest"].get("cves", []):
            out[c] = max(out.get(c, 0), n)
    return out


def _action_ok(a):
    import re
    if not isinstance(a, dict):
        return False
    if a.get("kind") == "sysctl":
        s = a.get("settings")
        return isinstance(s, dict) and s and all(re.fullmatch(r"[a-z0-9_.]{1,80}", k) and re.fullmatch(r"[0-9 ]{1,20}", str(v))
                                                 for k, v in s.items())
    if a.get("kind") == "module-off":
        m = a.get("modules")
        return isinstance(m, list) and m and all(re.fullmatch(r"[a-z0-9_-]{1,60}", x) for x in m)
    return False


def apply(mid, findings, keys=None, required=None, decide=None, run=True):
    """apply one signed mitigation; returns what was written. Raises zvuln.Refused-like ValueError on refusal."""
    import subprocess, zdecide
    decide = decide or zdecide.ask
    rec = mitigation_records().get(mid)
    if not rec:
        raise ValueError(f"no mitigation {mid}")
    m = rec["manifest"]
    if not _action_ok(m.get("action")):
        raise ValueError("the mitigation's action is not one ZENOS applies (sysctl or module-off)")
    keys = zsupply.officers() if keys is None else keys
    required = int(zsupply.conf().get("required", 2) if required is None else required)
    sigs = len(zsupply.valid_signers(rec, keys))
    hit = [f for f in findings if f["cve"] in m.get("cves", []) and f["status"] == "affected"]
    allowed = False
    for f in hit:
        r = decide({"op": "vuln", "listed": True, "fixed_installed": False, "mitigated": False, "kev": f["kev"],
                    "score": f["score"], "remote": f["remote"], "signatures": sigs, "required": required})
        allowed = allowed or bool(r.get("may_mitigate"))
    if not allowed:
        record("mitigation-refused", id=mid, signatures=sigs, required=required, affected=len(hit))
        raise ValueError(f"refused: {sigs} of {required} signatures, {len(hit)} affected part(s)")
    a = m["action"]
    if a["kind"] == "sysctl":
        p = SYSCTL_DIR / f"70-zenos-mitigation-{mid}.conf"
        text = f"# ZENOS mitigation {mid} for {', '.join(m['cves'])} (signed by {sigs} release officers)\n" + \
               "".join(f"{k} = {v}\n" for k, v in sorted(a["settings"].items()))
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        if run:
            subprocess.run(["sysctl", "-p", str(p)], capture_output=True, timeout=30)
    else:
        p = MODPROBE_DIR / f"zenos-mitigation-{mid}.conf"
        text = f"# ZENOS mitigation {mid} for {', '.join(m['cves'])} (signed by {sigs} release officers)\n" + \
               "".join(f"install {x} /bin/false\n" for x in a["modules"])
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        if run:
            for x in a["modules"]:
                subprocess.run(["modprobe", "-r", x], capture_output=True, timeout=30)
    ap = applied()
    ap[mid] = {"t": int(time.time()), "file": str(p), "signatures": sigs}
    _write(APPLIED, ap, 0o600)
    record("mitigation-applied", id=mid, cves=m["cves"], signatures=sigs, file=str(p))
    return p


# ---------------------------------------------------------------- one run
def gather(c=None, get=zvuln.fetch):
    """fetch and parse the enabled sources; a source that fails is reported and skipped"""
    c = c or zvuln.conf()
    kev, debian, scores, extra, errors = {}, {}, {}, {}, {}
    for name, parse in (("kev", zvuln.parse_kev), ("debian", zvuln.parse_debian), ("jvn", zvuln.parse_jvn),
                        ("zerowire", zvuln.parse_feed)):
        if not c["on"].get(name):
            continue
        try:
            got = parse(get(c["urls"][name]))
        except Exception as e:
            errors[name] = type(e).__name__
            continue
        if name == "kev":
            kev = got
        elif name == "debian":
            debian = got
        elif name == "jvn":
            for k, v in got.items():
                scores.setdefault(k, {}).update(v)
        else:
            extra.update(got)
    if c["on"].get("spdx"):
        try:
            for f in json.loads(get(c["urls"]["spdx"])):
                u = f.get("download_url") or ""
                if f.get("name", "").endswith(".json") and u.startswith("https://raw.githubusercontent.com/NCSC-NL/"):
                    for k, v in zvuln.parse_spdx(get(u)).items():
                        extra.setdefault(k, {}).update(v)
        except Exception as e:
            errors["spdx"] = type(e).__name__
    return kev, debian, scores, extra, errors


def scores_for(cves, c, get=zvuln.fetch, have=None, limit=40):
    """NVD scores for the vulnerabilities that matter here (affected parts), a few per run (NVD's rate limit)"""
    out = dict(have or {})
    if not c["on"].get("nvd"):
        return out
    for cve in [x for x in cves if x not in out][:limit]:
        try:
            out.update(zvuln.parse_nvd(get(c["urls"]["nvd"].format(cve=cve))))
        except Exception:
            break
        time.sleep(6.5)
    return out


def run(c=None, get=zvuln.fetch, inv=None, decide=None, keys=None, sleep_nvd=True):
    c = c or zvuln.conf()
    kev, debian, scores, extra, errors = gather(c, get)
    for name, err in errors.items():
        record("vuln-source-error", source=name, error=err)
    inv = zvuln.installed() if inv is None else inv
    try:
        old = json.loads(STATE.read_text())
    except (OSError, ValueError):
        old = {}
    scores = dict(old.get("scores") or {}, **scores)
    first = zvuln.match(debian, kev, scores, inv, mitigated_cves(), offered_signatures(keys), decide=decide)
    want = sorted({f["cve"] for f in first if f["status"] in ("affected", "mitigated")})
    if sleep_nvd:
        scores = scores_for(want, c, get, scores)
    findings = zvuln.match(debian, kev, scores, inv, mitigated_cves(), offered_signatures(keys), decide=decide)
    hot = [f for f in findings if f["status"] in ("affected", "mitigated")]
    before = {(f["cve"], f["package"]): f["status"] for f in old.get("findings") or []}
    for f in hot:
        if before.get((f["cve"], f["package"])) != f["status"]:
            record("vuln-" + f["status"], cve=f["cve"], package=f["package"], kev=f["kev"], score=f["score"],
                   priority=f["priority"])
    now_keys = {(f["cve"], f["package"]) for f in hot}
    for (cve, pkg), st in before.items():
        if (cve, pkg) not in now_keys and st in ("affected", "mitigated"):
            record("vuln-fixed", cve=cve, package=pkg)
    s = zvuln.summary(findings)
    s["not_affected"] = sum(1 for cves in debian.values() for d in cves.values() if d["status"] == "not-affected")
    state = {"t": int(time.time()), "sources": {k: v for k, v in c["on"].items() if v}, "errors": errors,
             "summary": s, "findings": hot[:500], "scores": {k: scores[k] for k in want if k in scores},
             "also_listed": sorted(k for k in extra if k in {f["cve"] for f in hot})}
    _write(STATE, state, 0o644)
    _write(RUN, {k: state[k] for k in ("t", "sources", "errors", "summary")} | {"top": hot[:20]}, 0o644)
    return state


def main():
    a = sys.argv[1:]
    if not a:
        sys.exit(__doc__)
    if a[0] == "run":
        s = run()
        print(json.dumps(s["summary"]))
        return 0
    if a[0] == "show":
        try:
            s = json.loads(STATE.read_text())
        except (OSError, ValueError):
            print("no result yet: zenos_vulnwatch.py run")
            return 1
        print(json.dumps(s["summary"]))
        for f in s["findings"][:50]:
            print(f"{f['status']:10} {'KEV ' if f['kev'] else '    '}{f['score'] / 10:4.1f} {'net ' if f['remote'] else '    '}"
                  f"{f['cve']:18} {f['package']} {f['installed']} -> {f['fixed'] or 'no fix yet'}")
        return 0
    if a[0] == "mitigations":
        keys = zsupply.officers()
        for mid, rec in mitigation_records().items():
            print(f"{mid:30} {len(zsupply.valid_signers(rec, keys))} signature(s) {'applied' if mid in applied() else ''}"
                  f" {', '.join(rec['manifest'].get('cves', []))}")
        return 0
    if a[0] == "apply" and len(a) == 2:
        try:
            s = json.loads(STATE.read_text())
            print("applied:", apply(a[1], s.get("findings") or []))
            return 0
        except (OSError, ValueError) as e:
            print(str(e), file=sys.stderr)
            return 1
    sys.exit(__doc__)


if __name__ == "__main__":
    sys.exit(main())
